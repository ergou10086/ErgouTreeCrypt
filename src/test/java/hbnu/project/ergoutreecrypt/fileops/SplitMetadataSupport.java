package hbnu.project.ergoutreecrypt.fileops;

import hbnu.project.ergoutreecrypt.encoding.RsCodecs;
import hbnu.project.ergoutreecrypt.volume.*;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.*;
import java.util.*;
import java.util.zip.CRC32;

/** 仅验证内嵌分卷元数据迁移，供桌面 JVM 和真实 Android ART 共用。 */
public final class SplitMetadataSupport {
    /** 禁止实例化。 */ private SplitMetadataSupport() { }

    /**
     * @param root 工作目录
     * @return 边界用例数
     * @throws Exception 新格式边界或兼容性失败。
     */
    public static int boundaries(Path root) throws Exception {
        Files.createDirectories(root);int cases=0;
        List<long[]> pairs=new ArrayList<>();
        for(int size:List.of(0,1,1023,1024,1025,2048,2049))for(long chunk:List.of(1024L,Long.MAX_VALUE))pairs.add(new long[]{size,chunk});
        for(int size=0;size<=6;size++)pairs.add(new long[]{size,1});
        for(long[] pair:pairs) {
            int size=(int)pair[0];long chunk=pair[1];
            Path folder=Files.createDirectories(root.resolve("edge-"+cases));
            byte[] data=new byte[size];new Random(size).nextBytes(data);
            Path base=Files.write(folder.resolve("data.pcv"),data);Splitter.split(base,chunk);Files.delete(base);
            var info=Splitter.inspect(base);info.requireComplete();
            require(info.totalKnown()&&info.expectedCount()==Math.max(1,1+(size-1L)/chunk),"Wrong embedded count");
            require(!Files.exists(Splitter.manifestPath(base)),"Sidecar generated");
            for(int i=0;i<info.chunks().size();i++) {
                SplitMetadata metadata=SplitMetadata.read(info.chunks().get(i));
                require(metadata!=null&&metadata.index()==i,"Wrong embedded index");
                require(Files.size(info.chunks().get(i))==metadata.payloadSize()+64,"Wrong physical size");
            }
            Path restored=folder.resolve("restored");Splitter.recombine(restored,base.toString());
            require(Arrays.equals(data,Files.readAllBytes(restored)),"Footer leaked into merged bytes");cases++;
        }
        Path base=Files.write(root.resolve("repeat.ergou"),new byte[2050]);Splitter.split(base,1024);
        SplitMetadata old=SplitMetadata.read(Path.of(base+".0"));
        writeUtf8(Splitter.manifestPath(base),"stale manifest");
        Files.write(base,new byte[10]);Splitter.split(base,1024);
        require(!Files.exists(Splitter.manifestPath(base))&&!Files.exists(Path.of(base+".2")),"Resplit left old artifacts");
        require(!old.group().equals(SplitMetadata.read(Path.of(base+".0")).group()),"Split batch identifier reused");cases++;
        Path left=Files.write(root.resolve("left.ergou"),new byte[2050]),right=Files.write(root.resolve("right.ergou"),new byte[2050]);
        Splitter.split(left,1024);Splitter.split(right,1024);
        Files.copy(Path.of(right+".1"),Path.of(left+".1"),StandardCopyOption.REPLACE_EXISTING);
        require(Splitter.inspect(left).damaged().equals(List.of(1)),"Identical payloads from different batches accepted");cases++;
        System.out.println("METADATA BOUNDARIES PASS "+cases);return cases;
    }

    /**
     * * 每一生成端的同一组分卷，在每一读取端分别测试认证和解密拒绝，以及 RS 载荷修复。
     * @param corpus 本轮语料
     * @param work 工作目录
     * @return 异常及修复用例数
     * @throws Exception 不正确地接受损坏或破坏输出。
     */
    public static int mutations(Path corpus,Path work) throws Exception {
        Properties inventory=new Properties();try(var in=Files.newInputStream(corpus.resolve("manifest.properties"))){inventory.load(in);}
        Path plainBase=findCaseBase(corpus,inventory,"embedded-sample");
        var original=Splitter.inspect(plainBase);original.requireComplete();
        Map<Integer,byte[]> bytes=new TreeMap<>();
        for(int i=0;i<original.expectedCount();i++)bytes.put(i,Files.readAllBytes(Path.of(plainBase+"."+i)));
        List<String> scenarios=List.of("missing-first","missing-middle","missing-last","only-first","only-last","all-gone",
                "mixed-batch","swapped-indices","raw-in-new","short","long","checksum","start-magic","end-magic",
                "unsupported-version","invalid-count","extra","stale-sidecar","ciphertext");
        for(String scenario:scenarios) {
            Path folder=Files.createDirectories(work.resolve(scenario).resolve("中文 空格/深层"));
            Path base=folder.resolve("移动后.pcv");
            for(var entry:bytes.entrySet())Files.write(Path.of(base+"."+entry.getKey()),entry.getValue());
            int last=original.expectedCount()-1;
            switch(scenario) {
                case "missing-first" -> Files.delete(Path.of(base+".0"));
                case "missing-middle" -> Files.delete(Path.of(base+".1"));
                case "missing-last" -> Files.delete(Path.of(base+"."+last));
                case "only-first", "only-last", "all-gone" -> {
                    int keep=scenario.equals("only-first")?0:scenario.equals("only-last")?last:-1;
                    for(int i:bytes.keySet())if(i!=keep)Files.delete(Path.of(base+"."+i));
                }
                case "mixed-batch" -> {
                    byte[] b=bytes.get(1).clone();SplitMetadata m=SplitMetadata.decode(Arrays.copyOfRange(b,b.length-64,b.length));
                    byte[] tail=new SplitMetadata(m.index(),m.count(),m.total(),m.chunkSize(),UUID.randomUUID()).encode();
                    System.arraycopy(tail,0,b,b.length-64,64);Files.write(Path.of(base+".1"),b);
                }
                case "swapped-indices" -> {
                    Files.write(Path.of(base+".0"),bytes.get(1));Files.write(Path.of(base+".1"),bytes.get(0));
                }
                case "raw-in-new" -> Files.write(Path.of(base+".1"),Arrays.copyOf(bytes.get(1),bytes.get(1).length-64));
                case "short", "long" -> Files.write(Path.of(base+".1"),Arrays.copyOf(bytes.get(1),bytes.get(1).length+(scenario.equals("short")?-1:1)));
                case "checksum", "start-magic", "end-magic", "unsupported-version", "invalid-count", "ciphertext" -> {
                    byte[] b=bytes.get(1).clone();int start=b.length-64;
                    if(scenario.equals("ciphertext"))b[50]^=1;
                    else if(scenario.equals("unsupported-version")) {ByteBuffer.wrap(b).putInt(start+48,99);rewriteCrc(b);}
                    else if(scenario.equals("invalid-count")) {ByteBuffer.wrap(b).putInt(start+12,Integer.MAX_VALUE);rewriteCrc(b);}
                    else b[start+(scenario.equals("start-magic")?0:scenario.equals("end-magic")?56:20)]^=1;
                    Files.write(Path.of(base+".1"),b);
                }
                case "extra" -> Files.write(Path.of(base+"."+original.expectedCount()),bytes.get(1));
                case "stale-sidecar" -> writeUtf8(Splitter.manifestPath(base),"format=EGTC-SPLIT-1\ncount=1\nbytes=1\nchunkSize=1\n");
                default -> throw new IOException("Unknown metadata mutation");
            }
            if(scenario.startsWith("missing-")||scenario.startsWith("only-")) {
                var info=Splitter.inspect(base);
                require(info.totalKnown()&&info.expectedCount()==original.expectedCount(),"Remaining chunk lost known total: "+scenario);
                for(int i:bytes.keySet())require(info.missing().contains(i)==!Files.exists(Path.of(base+"."+i)),"Missing indices incorrect: "+scenario);
                require(Splitter.describeInput(folder.getParent()).contains("移动后.pcv"),"Nested folder preview lost split group");
            }
            Path selected=Path.of(base+"."+(scenario.equals("missing-first")||scenario.equals("only-last")?last:0));
            assertRejected(selected,folder.resolve("preserve"),List.of());
            try(var files=Files.walk(folder)){require(files.noneMatch(p->p.toString().endsWith(".incomplete")),"Temporary artifact leaked");}
            System.out.println("METADATA REJECT verify+decrypt "+inventory.getProperty("runtime")+" "+scenario);
        }
        Path rsBase=findCaseBase(corpus,inventory,"embedded-all-options");
        Path rsFolder=Files.createDirectories(work.resolve("rs-payload")),copy=rsFolder.resolve("rs.ergou");
        var rsInfo=Splitter.inspect(rsBase);rsInfo.requireComplete();
        for(int i=0;i<rsInfo.expectedCount();i++)Files.copy(Path.of(rsBase+"."+i),Path.of(copy+"."+i),StandardCopyOption.REPLACE_EXISTING);
        byte[] damaged=Files.readAllBytes(Path.of(copy+".1"));damaged[50]^=1;Files.write(Path.of(copy+".1"),damaged);
        Splitter.inspect(copy).requireComplete();
        List<String> keys=List.of(corpus.resolve("key1").toString(),corpus.resolve("key2").toString());
        VerifyRequest v=verifyRequest(Path.of(copy+".1"),keys);require(Verifier.verify(v),"RS payload repair failed verification");
        DecryptRequest d=decryptRequest(Path.of(copy+".1"),rsFolder.resolve("restored"),keys);Decryptor.decrypt(d);
        require(Arrays.equals(Files.readAllBytes(corpus.resolve("sample.bin")),Files.readAllBytes(Path.of(d.getOutputFile()))),"RS payload repair changed plaintext");
        require(SplitInteropSupport.sha256(corpus.resolve("sample.bin")).equals(SplitInteropSupport.sha256(Path.of(d.getOutputFile()))),"RS hash mismatch");
        System.out.println("METADATA RS PAYLOAD PASS verify+decrypt "+inventory.getProperty("runtime"));
        return scenarios.size()+1;
    }

    /**
     * @param corpus 传统伪装清单语料
     * @param work 工作目录
     * @return 用例数
     * @throws Exception 缺首中末或全部卷时未正确拒绝。
     */
    public static int legacyMissing(Path corpus,Path work) throws Exception {
        Properties inventory=new Properties();try(var in=Files.newInputStream(corpus.resolve("manifest.properties"))){inventory.load(in);}
        Path original=findCaseBase(corpus,inventory,"legacy-deniability");var info=Splitter.inspect(original);info.requireComplete();
        require(info.expectedCount()>=3,"Fallback fixture needs three volumes");
        int count=0;
        for(List<Integer> missing:List.of(List.of(0),List.of(1),List.of(info.expectedCount()-1),
                java.util.stream.IntStream.range(0,info.expectedCount()).boxed().toList())) {
            Path folder=Files.createDirectories(work.resolve("missing-"+count));Path base=folder.resolve("legacy.pcv");
            for(int i=0;i<info.expectedCount();i++)Files.copy(Path.of(original+"."+i),Path.of(base+"."+i),StandardCopyOption.REPLACE_EXISTING);
            Files.copy(Splitter.manifestPath(original),Splitter.manifestPath(base),StandardCopyOption.REPLACE_EXISTING);
            for(int i:missing)Files.delete(Path.of(base+"."+i));
            var broken=Splitter.inspect(base);require(broken.totalKnown()&&broken.expectedCount()==info.expectedCount()&&broken.missing().equals(missing),"Fallback missing indices incorrect");
            assertRejected(Splitter.manifestPath(base),folder.resolve("keep"),List.of(corpus.resolve("key1").toString(),corpus.resolve("key2").toString()));
            System.out.println("LEGACY FALLBACK REJECT verify+decrypt "+inventory.getProperty("runtime")+" "+missing);count++;
        }
        return count;
    }

    /**
     * @param bytes 完整分卷
     * @throws IOException 不正确的尾部。
     */
    private static void rewriteCrc(byte[] bytes) throws IOException {
        if(bytes.length<64)throw new IOException("No footer");CRC32 crc=new CRC32();crc.update(bytes,bytes.length-64,52);
        ByteBuffer.wrap(bytes).putInt(bytes.length-12,(int)crc.getValue());
    }

    /**
     * @param corpus 语料
     * @param inventory 用例记录
     * @param id 用例名
     * @return 分卷基础路径
     * @throws IOException 未找到用例。
     */
    private static Path findCaseBase(Path corpus,Properties inventory,String id) throws IOException {
        for(int i=0;i<Integer.parseInt(inventory.getProperty("count"));i++)if(id.equals(inventory.getProperty("case."+i+".id"))) {
            Path artifact=corpus.resolve(inventory.getProperty("case."+i+".artifact"));
            try(var files=Files.walk(artifact)) {
                Path chunk=files.filter(Files::isRegularFile).filter(p->Splitter.isSplitChunkPath(p.toString())).findFirst().orElseThrow();
                return Path.of(Splitter.splitChunkBase(chunk.toString()));
            }
        }
        throw new IOException("No case: "+id);
    }

    /**
     * @param selected 输入碎片
     * @param output 既有输出
     * @param keys 密钥文件
     * @throws Exception 认证或解密误接受、输出被破坏。
     */
    private static void assertRejected(Path selected,Path output,List<String> keys) throws Exception {
        boolean rejected=false;try{rejected=!Verifier.verify(verifyRequest(selected,keys));}catch(Exception expected){rejected=true;}
        require(rejected,"Verifier accepted invalid split group: "+selected);
        writeUtf8(output,"keep");rejected=false;
        try{Decryptor.decrypt(decryptRequest(selected,output,keys));}catch(Exception expected){rejected=true;}
        require(rejected,"Decryptor accepted invalid split group: "+selected);
        require(Arrays.equals(Files.readAllBytes(output),"keep".getBytes(java.nio.charset.StandardCharsets.UTF_8)),"Existing output changed after rejection");
    }

    /**
     * @param selected 输入
     * @param keys 密钥文件
     * @return 只读校验请求。
     */
    private static VerifyRequest verifyRequest(Path selected,List<String> keys) {
        VerifyRequest v=new VerifyRequest();v.setInputFile(selected.toString());v.setPassword(SplitInteropSupport.PASSWORD);v.setKeyfiles(keys);v.setRsCodecs(new RsCodecs());return v;
    }

    /**
     * @param selected 输入
     * @param output 输出
     * @param keys 密钥文件
     * @return 解密请求。
     */
    private static DecryptRequest decryptRequest(Path selected,Path output,List<String> keys) {
        DecryptRequest d=new DecryptRequest();d.setInputFile(selected.toString());d.setOutputFile(output.toString());d.setPassword(SplitInteropSupport.PASSWORD);d.setKeyfiles(keys);d.setRsCodecs(new RsCodecs());return d;
    }

    /**
     * @param path 输出路径
     * @param text UTF-8 文本
     * @throws IOException 写入失败。
     */
    private static void writeUtf8(Path path,String text) throws IOException {
        Files.write(path,text.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    /**
     * @param condition 断言
     * @param message 错误详情
     * @throws IOException 断言失败。
     */
    private static void require(boolean condition,String message) throws IOException {if(!condition)throw new IOException(message);}
}
