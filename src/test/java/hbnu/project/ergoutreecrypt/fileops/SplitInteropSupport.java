package hbnu.project.ergoutreecrypt.fileops;

import hbnu.project.ergoutreecrypt.encoding.RsCodecs;
import hbnu.project.ergoutreecrypt.crypto.BruteForceGuard;
import hbnu.project.ergoutreecrypt.settings.SettingsManager;
import hbnu.project.ergoutreecrypt.volume.*;
import java.io.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

/** 在桌面 JVM 和 Android ART 间交换同一批真实分卷产物，校验和解密分别验证。 */
public final class SplitInteropSupport {
    public static final String PASSWORD="split-密码🔑";
    public static final String ARCHIVE_PASSWORD="archive-密码🔐";
    /** 禁止实例化。 */ private SplitInteropSupport() { }

    /**
     * 生成分卷语料：16 种密码学选项组合、无密码、空文件、可压缩数据和六种前后归档。
     * @param output 语料目录
     * @param source 真实源文件
     * @param mobile 是否在 Android 运行
     * @param slow 是否加入 1 GiB KDF 的可否认分支
     * @return 总测试用例数
     * @throws Exception 生成失败
     */
    public static int generate(Path output,Path source,boolean mobile,boolean slow) throws Exception {
        Files.createDirectories(output);
        Path real=output.resolve("source.bin"); if(!real.equals(source))Files.copy(source,real,StandardCopyOption.REPLACE_EXISTING);
        Path sample=output.resolve("sample.bin");
        try(InputStream in=Files.newInputStream(real)){Files.write(sample,in.readNBytes(3*1024*1024+129));}
        Files.write(output.resolve("empty.bin"),new byte[0]);
        byte[] compressible=new byte[3*1024*1024+127];Arrays.fill(compressible,(byte)65);Files.write(output.resolve("重复 空格.bin"),compressible);
        Files.write(output.resolve("key1"),"first keyfile".getBytes(java.nio.charset.StandardCharsets.UTF_8));Files.write(output.resolve("key2"),"第二个密钥文件🔑".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        Properties manifest=new Properties(); manifest.setProperty("runtime",mobile?"Android ART":"Desktop JVM");
        int index=0;
        boolean custom=SettingsManager.isArchiveCustomEncryption(),fallback=SettingsManager.isArchivePasswordFallback();
        SettingsManager.setArchiveCustomEncryption(true);SettingsManager.setArchivePasswordFallback(false);
        try {
            for(int mask=0;mask<16;mask++) {
                String input=Set.of(0,3,12,15).contains(mask)?"source.bin":"sample.bin";
                index=produce(output,manifest,index,"options-"+mask,input,mask,"",null,false,mobile,false,false);
            }
            index=produce(output,manifest,index,"public","sample.bin",7,"",null,false,mobile,true,false);
            index=produce(output,manifest,index,"keyfile-only","sample.bin",15,"",null,false,mobile,true,false);
            index=produce(output,manifest,index,"empty","empty.bin",7,"",null,false,mobile,false,false);
            index=produce(output,manifest,index,"compressible","重复 空格.bin",15,"",null,false,mobile,false,false);
            for(String fmt:List.of("ZIP","GZ","TAR.GZ","7Z","LZ4","TAR.LZ4")) {
                for(boolean password:List.of(false,true)) {
                    index=produce(output,manifest,index,"post-"+fmt+"-"+password,"sample.bin",15,"post",fmt,password,mobile,false,false);
                }
                index=produce(output,manifest,index,"pre-"+fmt,"sample.bin",15,"pre",fmt,true,mobile,false,false);
            }
            if(slow) {
                index=produce(output,manifest,index,"legacy-deniability","sample.bin",15,"",null,false,mobile,false,true);
                index=produce(output,manifest,index,"dual-deniability","sample.bin",7,"post","ZIP",true,mobile,false,true);
            }
        } finally {SettingsManager.setArchiveCustomEncryption(custom);SettingsManager.setArchivePasswordFallback(fallback);}
        manifest.setProperty("count",Integer.toString(index));
        try(OutputStream out=Files.newOutputStream(output.resolve("manifest.properties"))){manifest.store(out,"Split cross-runtime regression corpus");}
        return index;
    }

    /**
     * 创建一个用例，并记录全部分卷与清单的 SHA-256。
     * @param root 语料根 @param manifest 用例清单 @param index 编号 @param id 名称 @param input 输入名
     * @param mask 偏执、RS、Zstd、密钥文件四个开关 @param workflow 归档顺序 @param fmt 格式
     * @param archivePassword 归档密码开关 @param mobile 运行端 @param publicPassword 是否无密码
     * @param deniable 是否可否认 @return 下一个编号 @throws Exception 生成失败
     */
    private static int produce(Path root,Properties manifest,int index,String id,String input,int mask,
            String workflow,String fmt,boolean archivePassword,boolean mobile,boolean publicPassword,boolean deniable) throws Exception {
        Path caseDir=Files.createDirectories(root.resolve("case-"+index));
        EncryptRequest req=new EncryptRequest();req.setInputFile(root.resolve(input).toString());req.setOutputFile(caseDir.resolve(input+".ergou").toString());
        req.setPassword(publicPassword?"":PASSWORD);req.setRsCodecs(new RsCodecs());req.setArgon2MemoryKib(mobile?4096:8192);req.setArgon2Passes(1);req.setArgon2Threads(2);
        req.setParanoid((mask&1)!=0);req.setReedSolomon((mask&2)!=0);req.setCompress((mask&4)!=0);
        if((mask&8)!=0){req.setKeyfiles(List.of(root.resolve("key1").toString(),root.resolve("key2").toString()));req.setKeyfileOrdered(true);}
        req.setComments("分卷互操作 🔑 Unicode / "+id);req.setSplit(true);req.setChunkSize(input.equals("source.bin")?7:1);
        String archivePw=archivePassword?ARCHIVE_PASSWORD:null;
        if(workflow.equals("post")){req.setArchiveFormat(fmt);req.setArchivePassword(archivePw);}
        if(workflow.equals("pre")){req.setPreArchiveFormat(fmt);req.setPreArchivePassword(archivePw);}
        boolean dual=deniable&&id.startsWith("dual");
        if(dual){req.setDualDeniability(true);req.setDecoyFilePath(root.resolve("empty.bin").toString());req.setFakePassword("decoy");}
        else req.setDeniability(deniable);
        Encryptor.encrypt(req);
        Path produced=Path.of(req.getOutputFile());Path artifact=Files.exists(produced)?produced:produced.getParent();
        String prefix="case."+index+".";
        manifest.setProperty(prefix+"id",id);manifest.setProperty(prefix+"input",input);
        manifest.setProperty(prefix+"sha256",sha256(root.resolve(input)));manifest.setProperty(prefix+"mask",Integer.toString(mask));
        manifest.setProperty(prefix+"workflow",workflow);manifest.setProperty(prefix+"format",fmt==null?"":fmt);
        manifest.setProperty(prefix+"archivePassword",Boolean.toString(archivePassword));manifest.setProperty(prefix+"public",Boolean.toString(publicPassword));
        manifest.setProperty(prefix+"artifact",root.relativize(artifact).toString().replace('\\','/'));
        List<Path> files;
        if(Files.isDirectory(artifact)){try(var walk=Files.walk(artifact)){files=walk.filter(Files::isRegularFile).sorted().toList();}}
        else files=List.of(artifact);
        manifest.setProperty(prefix+"files",Integer.toString(files.size()));
        for(int i=0;i<files.size();i++){manifest.setProperty(prefix+"file."+i,root.relativize(files.get(i)).toString().replace('\\','/'));manifest.setProperty(prefix+"file."+i+".sha256",sha256(files.get(i)));}
        return index+1;
    }

    /**
     * 对所有产物先做只读认证校验，再解密并逐字节核对原文。
     * @param corpus 已生成语料 @param output 工作目录 @return 完成用例数 @throws Exception 任一用例失败
     */
    public static int verifyAll(Path corpus,Path output) throws Exception {
        Properties manifest=new Properties();try(InputStream in=Files.newInputStream(corpus.resolve("manifest.properties"))){manifest.load(in);}
        int count=Integer.parseInt(manifest.getProperty("count"));
        for(int i=0;i<count;i++) {
            String p="case."+i+".";Path work=output.resolve("case-"+i);
            if(Files.exists(work))deleteWork(work);Files.createDirectories(work);
            for(int f=0;f<Integer.parseInt(manifest.getProperty(p+"files"));f++) {
                require(sha256(corpus.resolve(manifest.getProperty(p+"file."+f))).equals(manifest.getProperty(p+"file."+f+".sha256")),"Artifact changed: "+manifest.getProperty(p+"id"));
            }
            Path artifact=corpus.resolve(manifest.getProperty(p+"artifact"));
            String pw=Boolean.parseBoolean(manifest.getProperty(p+"public"))?"":PASSWORD;
            String archivePw=Boolean.parseBoolean(manifest.getProperty(p+"archivePassword"))?ARCHIVE_PASSWORD:null;
            String workflow=manifest.getProperty(p+"workflow");Path volumeDir=artifact;
            if(workflow.equals("post")){volumeDir=work.resolve("volumes");ArchiveExtractor.extractPreserving(artifact,volumeDir,archivePw);}
            Path base;
            try(var walk=Files.walk(volumeDir)) {
                Path sidecar=walk.filter(Files::isRegularFile).filter(f->Splitter.isManifestPath(f.toString())).findFirst().orElseThrow(()->new IOException("Missing split manifest"));
                base=Path.of(sidecar.toString().substring(0,sidecar.toString().length()-".volumes".length()));
            }
            var inspection=Splitter.inspect(base);inspection.requireComplete();require(inspection.totalKnown(),"Unknown total");
            List<String> keys=(Integer.parseInt(manifest.getProperty(p+"mask"))&8)==0?List.of():List.of(corpus.resolve("key1").toString(),corpus.resolve("key2").toString());
            VerifyRequest v=new VerifyRequest();v.setInputFile(Splitter.manifestPath(base).toString());v.setPassword(pw);v.setKeyfiles(keys);v.setRsCodecs(new RsCodecs());v.setRecombine(true);
            require(Verifier.verify(v),"Verifier rejected "+manifest.getProperty(p+"id"));
            Path restored=work.resolve("restored.bin"+(workflow.equals("pre")?ArchivePacker.extOf(ArchivePacker.parseFormat(manifest.getProperty(p+"format"))):""));
            DecryptRequest d=new DecryptRequest();d.setInputFile(inspection.chunks().get(inspection.chunks().size()-1).toString());d.setOutputFile(restored.toString());d.setPassword(pw);d.setKeyfiles(keys);d.setRsCodecs(new RsCodecs());d.setRecombine(true);
            BruteForceGuard guard=BruteForceGuard.getInstance();
            guard.recordSuccess(d.getInputFile());guard.recordFailure(d.getInputFile());
            try {
                require(guard.getFailCount(d.getInputFile())==1,"Failure counter was not seeded");
                Decryptor.decrypt(d);
                require(guard.getFailCount(d.getInputFile())==0,"Successful split decrypt did not reset failures: "+manifest.getProperty(p+"id"));
            } finally {guard.recordSuccess(d.getInputFile());}
            if(workflow.equals("pre")) {
                List<Path> extracted=ArchiveExtractor.extractPreserving(restored,work.resolve("plain"),archivePw);
                require(extracted.size()==1,"Unexpected pre-archive entries");restored=extracted.getFirst();
            }
            Path source=corpus.resolve(manifest.getProperty(p+"input"));
            require(sameBytes(source,restored),"Byte mismatch: "+manifest.getProperty(p+"id"));
            require(sha256(restored).equals(manifest.getProperty(p+"sha256")),"SHA-256 mismatch");
            deleteWork(work);
            System.out.println("SPLIT PASS verify+decrypt "+manifest.getProperty("runtime")+" "+manifest.getProperty(p+"id"));
        }
        return count;
    }

    /**
     * 18 个分卷目录场景：三种深度、串并行、普通/前归档/后归档，以及同名不同子目录。
     * @param root 本次工作目录 @return 用例数 @throws Exception 往返或路径核对失败
     */
    public static int directoryRegression(Path root) throws Exception {
        Files.createDirectories(root);int count=0;
        boolean custom=SettingsManager.isArchiveCustomEncryption(),fallback=SettingsManager.isArchivePasswordFallback();
        SettingsManager.setArchiveCustomEncryption(true);SettingsManager.setArchivePasswordFallback(false);
        try {
            for(int depth:List.of(1,2,6))for(int threads:List.of(1,3))for(String workflow:List.of("plain","pre","post")) {
                Path work=Files.createDirectories(root.resolve("folder-"+count));Path source=Files.createDirectories(work.resolve("目录 空格"));
                byte[] bytes=new byte[1024*1024+129];new Random(46).nextBytes(bytes);
                Map<String,byte[]> inputs=new LinkedHashMap<>();inputs.put("a.txt",new byte[]{4,3,2,1});inputs.put("A/same.bin",bytes);
                byte[] second=bytes.clone();second[0]^=1;inputs.put("B/same.bin",second);inputs.put("A/deep/更深/empty.bin",new byte[0]);
                for(var entry:inputs.entrySet()){Path f=source.resolve(entry.getKey());Files.createDirectories(f.getParent());Files.write(f,entry.getValue());}
                Path key=Files.write(work.resolve("key"),new byte[]{8,7,6});Path enc=Files.createDirectories(work.resolve("encrypted"));
                FolderCrypt.EncryptOptions e=new FolderCrypt.EncryptOptions();e.password=PASSWORD;e.rsCodecs=new RsCodecs();e.argon2MemoryKib=4096;e.argon2Passes=1;e.argon2Threads=1;e.encryptDepth=depth;e.threadCount=threads;e.split=true;e.chunkSize=1;e.paranoid=true;e.reedSolomon=true;e.compress=true;e.keyfiles=List.of(key.toString());e.keyfileOrdered=true;
                if(workflow.equals("post")){e.archiveFormat="ZIP";e.archivePassword=ARCHIVE_PASSWORD;}
                if(workflow.equals("pre")){e.preArchiveFormat="LZ4";e.preArchivePassword=ARCHIVE_PASSWORD;}
                FolderCrypt.encryptFolder(source,enc,e);require(e.batchResult.failedCount()==0,"Folder encryption failure");
                Path artifact;try(var entries=Files.list(enc)){artifact=entries.findFirst().orElseThrow();}
                FolderCrypt.DecryptOptions d=new FolderCrypt.DecryptOptions();d.password=PASSWORD;d.rsCodecs=new RsCodecs();d.archivePassword=ARCHIVE_PASSWORD;d.keyfiles=List.of(key.toString());d.threadCount=threads;d.recursiveExtract=true;d.decryptThenExtract=true;
                Path output=Files.createDirectories(work.resolve("restored"));FolderCrypt.decryptAuto(artifact,output,d);require(d.batchResult.failedCount()==0,"Folder decryption failure");
                List<Path> restored;try(var walk=Files.walk(output)){restored=walk.filter(Files::isRegularFile).toList();}
                for(var entry:inputs.entrySet()) {
                    boolean found=false;
                    for(Path f:restored)if(f.toString().replace('\\','/').endsWith(entry.getKey())&&Arrays.equals(Files.readAllBytes(f),entry.getValue())){found=true;break;}
                    require(found,"Folder path or bytes changed: "+depth+"/"+threads+"/"+workflow+"/"+entry.getKey());
                    require(Arrays.equals(Files.readAllBytes(source.resolve(entry.getKey())),entry.getValue()),"Source modified");
                }
                deleteWork(work);count++;
                System.out.println("SPLIT FOLDER PASS "+depth+"/"+threads+"/"+workflow);
            }
        } finally {SettingsManager.setArchiveCustomEncryption(custom);SettingsManager.setArchivePasswordFallback(fallback);}
        return count;
    }

    /**
     * 双端运行的 RS 分卷修复与损坏拒绝测试，使用密钥文件检验重试派生。
     * @param root 本次工作目录 @throws Exception 回归失败
     */
    public static void corruptionRegression(Path root) throws Exception {
        Files.createDirectories(root);byte[] bytes=new byte[4096];new Random(31).nextBytes(bytes);
        Path source=Files.write(root.resolve("source.bin"),bytes),key=Files.write(root.resolve("key"),new byte[]{1,2,3});
        for(boolean rs:List.of(false,true)) {
            EncryptRequest e=new EncryptRequest();e.setInputFile(source.toString());e.setOutputFile(root.resolve("data-"+rs+".ergou").toString());e.setPassword(PASSWORD);e.setRsCodecs(new RsCodecs());e.setReedSolomon(rs);e.setKeyfiles(List.of(key.toString()));e.setArgon2MemoryKib(8192);e.setArgon2Passes(1);e.setArgon2Threads(1);Encryptor.encrypt(e);
            Path base=Path.of(e.getOutputFile());Splitter.split(base,700);Files.delete(base);Path chunk=Path.of(base+".4");byte[] changed=Files.readAllBytes(chunk);changed[50]^=1;Files.write(chunk,changed);
            VerifyRequest v=new VerifyRequest();v.setInputFile(Path.of(base+".0").toString());v.setPassword(PASSWORD);v.setKeyfiles(List.of(key.toString()));v.setRsCodecs(new RsCodecs());
            DecryptRequest d=new DecryptRequest();d.setInputFile(Path.of(base+".0").toString());d.setPassword(PASSWORD);d.setKeyfiles(List.of(key.toString()));d.setRsCodecs(new RsCodecs());d.setOutputFile(root.resolve("restored-"+rs).toString());
            if(rs){require(Verifier.verify(v),"RS verification failed");Decryptor.decrypt(d);require(sameBytes(source,Path.of(d.getOutputFile())),"RS did not restore bytes");}
            else {
                boolean rejected=false;try{Verifier.verify(v);}catch(Exception expected){rejected=true;}require(rejected,"Damaged split passed verification");
                rejected=false;try{Decryptor.decrypt(d);}catch(Exception expected){rejected=true;}require(rejected,"Damaged split decrypted");require(!Files.exists(Path.of(d.getOutputFile())),"Corrupt plaintext committed");
            }
            require(!Files.exists(Path.of(d.getOutputFile()+".incomplete")),"Incomplete output leaked");
        }
    }

    /**
     * 重写先前的两个密码 ZIP 语料，用于中断后续跑；保留其他原生生成的产物。
     * @param corpus Android 已生成语料 @throws Exception 重写失败
     */
    public static void repairPasswordZipCases(Path corpus) throws Exception {
        Properties manifest=new Properties();try(InputStream in=Files.newInputStream(corpus.resolve("manifest.properties"))){manifest.load(in);}
        int count=Integer.parseInt(manifest.getProperty("count"));
        for(int i=0;i<count;i++) {
            String p="case."+i+".";String id=manifest.getProperty(p+"id");
            if(!"post-ZIP-true".equals(id)&&!"dual-deniability".equals(id))continue;
            produce(corpus,manifest,i,id,manifest.getProperty(p+"input"),Integer.parseInt(manifest.getProperty(p+"mask")),"post","ZIP",true,true,false,id.startsWith("dual"));
        }
        try(OutputStream out=Files.newOutputStream(corpus.resolve("manifest.properties"))){manifest.store(out,"Repacked native password ZIP volumes");}
    }

    /**
     * 同一密码 ZIP 分卷输出重复覆盖，多卷缩短为单卷后不遗漏或残留旧条目。
     * @param root 工作目录 @throws Exception 任一轮归档或明文核对失败
     */
    public static void repeatedPasswordZipSplitRegression(Path root) throws Exception {
        Files.createDirectories(root);
        for(int round=0;round<2;round++) {
            byte[] bytes=new byte[round==0?1024*1024+129:100];new Random(round+13).nextBytes(bytes);
            Path source=Files.write(root.resolve("source.bin"),bytes);
            EncryptRequest e=new EncryptRequest();e.setInputFile(source.toString());e.setOutputFile(root.resolve("data.ergou").toString());e.setPassword(PASSWORD);e.setRsCodecs(new RsCodecs());e.setArgon2MemoryKib(4096);e.setArgon2Passes(1);e.setArgon2Threads(1);e.setSplit(true);e.setChunkSize(1);e.setArchiveFormat("ZIP");e.setArchivePassword(ARCHIVE_PASSWORD);Encryptor.encrypt(e);
            Path volumes=root.resolve("unpacked-"+round);ArchiveExtractor.extractPreserving(Path.of(e.getOutputFile()),volumes,ARCHIVE_PASSWORD);
            Path sidecar;try(var walk=Files.walk(volumes)){sidecar=walk.filter(f->Splitter.isManifestPath(f.toString())).findFirst().orElseThrow();}
            Path base=Path.of(sidecar.toString().substring(0,sidecar.toString().length()-".volumes".length()));
            var inspection=Splitter.inspect(base);inspection.requireComplete();require(inspection.expectedCount()==(round==0?2:1),"Old ZIP split tail retained");
            VerifyRequest v=new VerifyRequest();v.setInputFile(sidecar.toString());v.setPassword(PASSWORD);v.setRsCodecs(new RsCodecs());require(Verifier.verify(v),"Repeated ZIP split failed authentication");
            DecryptRequest d=new DecryptRequest();d.setInputFile(sidecar.toString());d.setOutputFile(root.resolve("plain-"+round).toString());d.setPassword(PASSWORD);d.setRsCodecs(new RsCodecs());Decryptor.decrypt(d);require(sameBytes(source,Path.of(d.getOutputFile())),"Repeated ZIP split lost bytes");
        }
        deleteWork(root);System.out.println("SPLIT REPEATED PASSWORD ZIP PASS");
    }

    /**
     * 验证双卷可否认的诱饵密码分支，读取现有语料，不重新加密。
     * @param corpus 含双卷用例的语料 @param root 工作目录 @throws Exception 回归失败
     */
    public static void deniabilityDecoyRegression(Path corpus,Path root) throws Exception {
        deniabilityDecoyRegression(corpus,root,false);
    }

    /** @param corpus 双卷语料 @param root 工作目录 @throws Exception RS 未修复可恢复的诱饵数据损坏。 */
    public static void deniabilityRsRecoveryRegression(Path corpus,Path root) throws Exception {
        deniabilityDecoyRegression(corpus,root,true);
    }

    /** @param corpus 语料 @param root 工作目录 @param damage 是否损坏一个 RS 载荷字节 @throws Exception 回归失败。 */
    private static void deniabilityDecoyRegression(Path corpus,Path root,boolean damage) throws Exception {
        Properties manifest=new Properties();try(InputStream in=Files.newInputStream(corpus.resolve("manifest.properties"))){manifest.load(in);}
        int count=Integer.parseInt(manifest.getProperty("count"));
        for(int i=0;i<count;i++) {
            String p="case."+i+".";if(!"dual-deniability".equals(manifest.getProperty(p+"id")))continue;
            Files.createDirectories(root);Path volumes=root.resolve("volumes");
            ArchiveExtractor.extractPreserving(corpus.resolve(manifest.getProperty(p+"artifact")),volumes,ARCHIVE_PASSWORD);
            Path sidecar;try(var walk=Files.walk(volumes)){sidecar=walk.filter(f->Splitter.isManifestPath(f.toString())).findFirst().orElseThrow();}
            if(damage) {
                String baseName=sidecar.toString().substring(0,sidecar.toString().length()-".volumes".length());
                Path first=Path.of(baseName+".0");byte[] chunk=Files.readAllBytes(first);
                int dataOffset=java.nio.ByteBuffer.wrap(chunk,5,4).order(java.nio.ByteOrder.LITTLE_ENDIAN).getInt();
                chunk[dataOffset+2]^=1;Files.write(first,chunk);Splitter.inspect(Path.of(baseName)).requireComplete();
            }
            VerifyRequest v=new VerifyRequest();v.setInputFile(sidecar.toString());v.setPassword("decoy");v.setRsCodecs(new RsCodecs());require(Verifier.verify(v),"Decoy verification failed");
            DecryptRequest d=new DecryptRequest();d.setInputFile(sidecar.toString());d.setOutputFile(root.resolve("decoy.bin").toString());d.setPassword("decoy");d.setRsCodecs(new RsCodecs());Decryptor.decrypt(d);
            require(sameBytes(corpus.resolve("empty.bin"),Path.of(d.getOutputFile())),"Decoy bytes changed");
            deleteWork(root);System.out.println("SPLIT DECOY "+(damage?"RS RECOVERY ":"")+"PASS "+manifest.getProperty("runtime"));return;
        }
        throw new IOException("Slow dual-deniability corpus required");
    }

    /**
     * 无序密钥文件和强制解密选项的分卷行为，包括缺卷不能被强制跳过。
     * @param root 工作目录 @throws Exception 回归失败
     */
    public static void advancedOptionsRegression(Path root) throws Exception {
        Files.createDirectories(root);byte[] bytes=new byte[4096];new Random(9).nextBytes(bytes);
        Path source=Files.write(root.resolve("source.bin"),bytes),a=Files.write(root.resolve("key-a"),new byte[]{1,2}),b=Files.write(root.resolve("key-b"),new byte[]{3,4});
        EncryptRequest e=new EncryptRequest();e.setInputFile(source.toString());e.setOutputFile(root.resolve("data.ergou").toString());e.setPassword(PASSWORD);e.setRsCodecs(new RsCodecs());e.setKeyfiles(List.of(a.toString(),b.toString()));e.setKeyfileOrdered(false);e.setArgon2MemoryKib(4096);e.setArgon2Passes(1);e.setArgon2Threads(1);Encryptor.encrypt(e);
        Path base=Path.of(e.getOutputFile());Splitter.split(base,700);Files.delete(base);
        VerifyRequest v=new VerifyRequest();v.setInputFile(Splitter.manifestPath(base).toString());v.setPassword(PASSWORD);v.setKeyfiles(List.of(b.toString(),a.toString()));v.setRsCodecs(new RsCodecs());require(Verifier.verify(v),"Unordered reversed keyfiles failed verification");
        DecryptRequest d=new DecryptRequest();d.setInputFile(Path.of(base+".2").toString());d.setOutputFile(root.resolve("restored.bin").toString());d.setPassword(PASSWORD);d.setKeyfiles(v.getKeyfiles());d.setRsCodecs(new RsCodecs());Decryptor.decrypt(d);require(sameBytes(source,Path.of(d.getOutputFile())),"Unordered keyfiles failed decryption");
        for(Path artifact:Splitter.artifacts(base)) {
            String before=sha256(artifact);d.setOutputFile(artifact.toString());boolean rejected=false;
            try{Decryptor.decrypt(d);}catch(IOException expected){rejected=true;}
            require(rejected&&before.equals(sha256(artifact)),"Plaintext output overwrote split input");
        }
        Path changed=Path.of(base+".4");byte[] damaged=Files.readAllBytes(changed);damaged[50]^=1;Files.write(changed,damaged);
        d.setForceDecrypt(true);d.setOutputFile(root.resolve("forced.bin").toString());Decryptor.decrypt(d);
        require(Files.size(Path.of(d.getOutputFile()))==bytes.length,"Forced output length changed");require(!sameBytes(source,Path.of(d.getOutputFile())),"Forced damaged bytes unexpectedly unchanged");
        Files.delete(Path.of(base+".0"));d.setOutputFile(root.resolve("missing.bin").toString());
        boolean rejected=false;try{Decryptor.decrypt(d);}catch(IOException expected){rejected=true;}
        require(rejected&&!Files.exists(Path.of(d.getOutputFile())),"Force accepted missing volume");
        deleteWork(root);System.out.println("SPLIT ADVANCED PASS unordered-keyfiles/force/missing");
    }

    /**
     * 源分卷只读、输出目录独立时仍可认证和解密；恢复权限后清理测试数据。
     * @param root 本次工作目录 @throws Exception 回归失败
     */
    public static void readOnlySourceRegression(Path root) throws Exception {
        Files.createDirectories(root);Path folder=Files.createDirectories(root.resolve("readonly-volumes"));
        byte[] bytes=new byte[2050];new Random(5).nextBytes(bytes);
        Path source=Files.write(root.resolve("source.bin"),bytes);
        EncryptRequest e=new EncryptRequest();e.setInputFile(source.toString());e.setOutputFile(folder.resolve("data.ergou").toString());e.setPassword(PASSWORD);e.setRsCodecs(new RsCodecs());e.setArgon2MemoryKib(4096);e.setArgon2Passes(1);e.setArgon2Threads(1);Encryptor.encrypt(e);
        Path base=Path.of(e.getOutputFile());Splitter.split(base,700);Files.delete(base);
        List<Path> artifacts=Splitter.artifacts(base);Map<Path,String> before=new HashMap<>();
        for(Path artifact:artifacts){before.put(artifact,sha256(artifact));artifact.toFile().setWritable(false,false);}
        folder.toFile().setWritable(false,false);
        boolean enforced=!Files.isWritable(folder);
        try {
            VerifyRequest v=new VerifyRequest();v.setInputFile(Path.of(base+".1").toString());v.setPassword(PASSWORD);v.setRsCodecs(new RsCodecs());require(Verifier.verify(v),"Readonly verification failed");
            DecryptRequest d=new DecryptRequest();d.setInputFile(Splitter.manifestPath(base).toString());d.setOutputFile(root.resolve("restored.bin").toString());d.setPassword(PASSWORD);d.setRsCodecs(new RsCodecs());Decryptor.decrypt(d);
            require(sameBytes(source,Path.of(d.getOutputFile())),"Readonly source plaintext mismatch");
            for(Path artifact:artifacts)require(sha256(artifact).equals(before.get(artifact)),"Readonly source changed");
            try(var entries=Files.list(folder)){require(entries.count()==artifacts.size(),"Source-folder temporary file leaked");}
            System.out.println("SPLIT READONLY PASS directory write permission enforced="+enforced);
        } finally {
            folder.toFile().setWritable(true,false);for(Path artifact:artifacts)artifact.toFile().setWritable(true,false);
            deleteWork(root);
        }
    }

    /** @param input 文件 @return SHA-256 @throws Exception 读取失败。 */
    public static String sha256(Path input) throws Exception {
        MessageDigest digest=MessageDigest.getInstance("SHA-256");
        try(InputStream in=Files.newInputStream(input)){byte[] b=new byte[1024*1024];int n;while((n=in.read(b))!=-1)digest.update(b,0,n);}
        StringBuilder hex=new StringBuilder();for(byte b:digest.digest())hex.append(String.format("%02x",b&255));return hex.toString();
    }
    /** @param first 第一文件 @param second 第二文件 @return 逐字节相同 @throws IOException 读失败。 */
    private static boolean sameBytes(Path first,Path second) throws IOException {
        if(Files.size(first)!=Files.size(second))return false;
        try(InputStream a=Files.newInputStream(first);InputStream b=Files.newInputStream(second)){
            while(true){byte[] left=a.readNBytes(1024*1024),right=b.readNBytes(1024*1024);
                if(!Arrays.equals(left,right))return false;if(left.length==0)return true;}
        }
    }
    /** @param work 本次专属工作目录 @throws IOException 删除失败。 */
    private static void deleteWork(Path work) throws IOException {
        try(var walk=Files.walk(work)){for(Path p:walk.sorted(Comparator.reverseOrder()).toList())Files.deleteIfExists(p);}
    }
    /** @param condition 断言 @param message 失败详情 @throws IOException 不满足。 */
    private static void require(boolean condition,String message) throws IOException {if(!condition)throw new IOException(message);}
}