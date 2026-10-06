package hbnu.project.ergoutreecrypt.fileops;

import hbnu.project.ergoutreecrypt.encoding.RsCodecs;
import hbnu.project.ergoutreecrypt.crypto.BruteForceGuard;
import hbnu.project.ergoutreecrypt.settings.SettingsManager;
import hbnu.project.ergoutreecrypt.settings.SplitMetadataMode;
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
     * 只生成内嵌元数据迁移涉及的用例，保留旧格式读取和新格式归档入口验证。
     * @param output 语料目录 @param source 真实源文件 @param mobile 是否 ART @param slow 是否包含可否认容器
     * @return 用例数 @throws Exception 生成失败。
     */
    public static int generateMetadata(Path output,Path source,boolean mobile,boolean slow) throws Exception {
        if(Files.exists(output))deleteWork(output);
        Files.createDirectories(output);
        Files.copy(source,output.resolve("source.bin"),StandardCopyOption.REPLACE_EXISTING);
        try(InputStream in=Files.newInputStream(source)){Files.write(output.resolve("sample.bin"),in.readNBytes(3*1024*1024+129));}
        Files.write(output.resolve("empty.bin"),new byte[0]);
        Files.write(output.resolve("key1"),"first keyfile".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        Files.write(output.resolve("key2"),"第二个密钥文件🔑".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        Properties manifest=new Properties();manifest.setProperty("runtime",mobile?"Android ART":"Desktop JVM");
        boolean custom=SettingsManager.isArchiveCustomEncryption(),fallback=SettingsManager.isArchivePasswordFallback();
        SettingsManager.setArchiveCustomEncryption(true);SettingsManager.setArchivePasswordFallback(false);
        int index=0;
        try {
            index=produce(output,manifest,index,"embedded-sample","sample.bin",0,"",null,false,mobile,false,false);
            index=produce(output,manifest,index,"embedded-real","source.bin",0,"",null,false,mobile,false,false);
            index=produce(output,manifest,index,"embedded-all-options","sample.bin",15,"",null,false,mobile,false,false);
            index=produce(output,manifest,index,"embedded-empty","empty.bin",0,"",null,false,mobile,false,false);
            index=produce(output,manifest,index,"embedded-post-zip","sample.bin",15,"post","ZIP",true,mobile,false,false);
            index=produce(output,manifest,index,"embedded-post-lz4-single","empty.bin",0,"post","LZ4",true,mobile,false,false);
            index=produce(output,manifest,index,"embedded-post-gz-single","empty.bin",0,"post","GZ",false,mobile,false,false);
            index=produce(output,manifest,index,"embedded-pre-lz4","sample.bin",15,"pre","LZ4",true,mobile,false,false);
            for(boolean sidecar:List.of(false,true)) {
                int legacy=index;
                index=produce(output,manifest,index,sidecar?"legacy-sidecar":"legacy-raw","sample.bin",0,"",null,false,mobile,false,false);
                Path base=findBase(output.resolve(manifest.getProperty("case."+legacy+".artifact")));
                var info=Splitter.inspect(base);SplitMetadata metadata=SplitMetadata.read(info.chunks().getFirst());
                for(Path chunk:info.chunks()) {
                    byte[] bytes=Files.readAllBytes(chunk);Files.write(chunk,Arrays.copyOf(bytes,bytes.length-SplitMetadata.SIZE));
                }
                if(sidecar)writeUtf8(Splitter.manifestPath(base),"format=EGTC-SPLIT-1\ncount="+metadata.count()+"\nbytes="+metadata.total()+"\nchunkSize="+metadata.chunkSize()+"\n");
                try(var walk=Files.walk(base.getParent())) {
                    List<Path> files=walk.filter(Files::isRegularFile).sorted().toList();
                    String p="case."+legacy+".";manifest.setProperty(p+"files",Integer.toString(files.size()));
                    for(int f=0;f<files.size();f++) {
                        manifest.setProperty(p+"file."+f,output.relativize(files.get(f)).toString().replace('\\','/'));
                        manifest.setProperty(p+"file."+f+".sha256",sha256(files.get(f)));
                    }
                }
            }
            if(slow) {
                index=produce(output,manifest,index,"legacy-deniability","sample.bin",15,"",null,false,mobile,false,true);
                index=produce(output,manifest,index,"dual-deniability","sample.bin",7,"post","ZIP",true,mobile,false,true);
            }
        } finally {SettingsManager.setArchiveCustomEncryption(custom);SettingsManager.setArchivePasswordFallback(fallback);}
        manifest.setProperty("count",Integer.toString(index));
        try(OutputStream out=Files.newOutputStream(output.resolve("manifest.properties"))){manifest.store(out,"Embedded split metadata migration corpus (test inventory only)");}
        return index;
    }

    /**
     * 传统伪装模式保留随机外观的清单回退，单独追加八方向，不重复已通过的内嵌矩阵。
     * @param output 语料目录 @param source 真实样本 @param mobile 是否 ART @return 用例数 @throws Exception 写入或检查失败。
     */
    public static int generateLegacyFallback(Path output,Path source,boolean mobile) throws Exception {
        if(Files.exists(output))deleteWork(output);Files.createDirectories(output);
        try(InputStream in=Files.newInputStream(source)){Files.write(output.resolve("sample.bin"),in.readNBytes(3*1024*1024+129));}
        Files.write(output.resolve("key1"),"first keyfile".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        Files.write(output.resolve("key2"),"第二个密钥文件🔑".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        Properties inventory=new Properties();inventory.setProperty("runtime",mobile?"Android ART":"Desktop JVM");
        int count=produce(output,inventory,0,"legacy-deniability","sample.bin",15,"",null,false,mobile,false,true);
        Path base=findBase(output.resolve(inventory.getProperty("case.0.artifact")));
        require(Files.isRegularFile(Splitter.manifestPath(base)),"Traditional disguise lost fallback manifest");
        for(Path chunk:Splitter.listChunks(base))require(SplitMetadata.read(chunk)==null,"Identifiable footer appended to traditional disguise");
        inventory.setProperty("count",Integer.toString(count));
        try(OutputStream out=Files.newOutputStream(output.resolve("manifest.properties"))){inventory.store(out,"Traditional disguise split fallback (test inventory only)");}
        return count;
    }

    /**
     * 格式设置的定向语料：两种方式的普通、高级选项、空文件、前后归档和双卷隐藏。
     *
     * @param output 语料目录
     * @param source 真实测试文件
     * @param mobile 是否运行于 ART
     *
     * @return 用例数
     * @throws Exception 生成或格式断言失败
     */
    public static int generateModes(Path output, Path source, boolean mobile) throws Exception {
        if (Files.exists(output)) deleteWork(output);
        Files.createDirectories(output);
        try (InputStream in = Files.newInputStream(source)) {
            Files.write(output.resolve("sample.bin"), in.readNBytes(3 * 1024 * 1024 + 129));
        }
        Files.write(output.resolve("empty.bin"), new byte[0]);
        Files.write(output.resolve("key1"), new byte[]{1, 2, 3});
        Files.write(output.resolve("key2"), new byte[]{4, 5, 6});
        Properties inventory = new Properties();
        inventory.setProperty("runtime", mobile ? "Android ART" : "Desktop JVM");
        SplitMetadataMode saved = SettingsManager.getSplitMetadataMode();
        boolean custom = SettingsManager.isArchiveCustomEncryption();
        SettingsManager.setArchiveCustomEncryption(true);
        int index = 0;
        try {
            for (SplitMetadataMode mode : SplitMetadataMode.values()) {
                SettingsManager.setSplitMetadataMode(mode);
                EncryptRequest snapshot = new EncryptRequest();
                FolderCrypt.EncryptOptions batch = new FolderCrypt.EncryptOptions();
                SettingsManager.setSplitMetadataMode(mode == SplitMetadataMode.EMBEDDED ? SplitMetadataMode.MANIFEST : SplitMetadataMode.EMBEDDED);
                require(snapshot.getSplitMetadataMode() == mode && batch.splitMetadataMode == mode, "Task format was not snapshotted");
                SettingsManager.setSplitMetadataMode(mode);
                String name = "mode-" + mode.name().toLowerCase(Locale.ROOT) + "-";
                index = produce(output, inventory, index, name + "plain", "sample.bin", 0, "", null, false, mobile, false, false);
                index = produce(output, inventory, index, name + "advanced", "sample.bin", 15, "", null, false, mobile, false, false);
                index = produce(output, inventory, index, name + "empty", "empty.bin", 0, "", null, false, mobile, true, false);
                index = produce(output, inventory, index, name + "post-zip", "sample.bin", 0, "post", "ZIP", true, mobile, false, false);
                index = produce(output, inventory, index, name + "pre-lz4", "sample.bin", 0, "pre", "LZ4", true, mobile, false, false);
                index = produce(output, inventory, index, "dual-" + name, "sample.bin", 0, "post", "ZIP", true, mobile, false, true);
                index = produceModeFolder(output, inventory, index, name + "folder");
            }
        } finally {
            SettingsManager.setSplitMetadataMode(saved);
            SettingsManager.setArchiveCustomEncryption(custom);
        }
        inventory.setProperty("count", Integer.toString(index));
        try (OutputStream out = Files.newOutputStream(output.resolve("manifest.properties"))) {
            inventory.store(out, "Split format settings regression inventory only");
        }
        return index;
    }

    /**
     * @param root 语料目录
     * @param inventory 用例记录
     * @param index 编号
     * @param id 用例名
     *
     * @return 下一个编号
     * @throws Exception 嵌套目录分卷失败 */
    private static int produceModeFolder(Path root, Properties inventory, int index, String id) throws Exception {
        Path input = Files.createDirectories(root.resolve("folder-input-" + index).resolve("层 空格"));
        Files.copy(root.resolve("sample.bin"), input.resolve("sample.bin"));
        Path artifact = Files.createDirectories(root.resolve("case-" + index));
        FolderCrypt.EncryptOptions options = new FolderCrypt.EncryptOptions();
        options.password = PASSWORD; options.rsCodecs = new RsCodecs(); options.split = true; options.chunkSize = 1;
        options.argon2MemoryKib = 4096; options.argon2Passes = 1; options.argon2Threads = 1;
        options.threadCount = 2; options.encryptDepth = 2;
        FolderCrypt.encryptFolder(input.getParent(), artifact, options);
        require(options.batchResult.failedCount() == 0, "Folder mode encryption failed");
        String p = "case." + index + ".";
        inventory.setProperty(p + "id", id); inventory.setProperty(p + "input", "sample.bin");
        inventory.setProperty(p + "sha256", sha256(root.resolve("sample.bin"))); inventory.setProperty(p + "mask", "0");
        inventory.setProperty(p + "workflow", ""); inventory.setProperty(p + "format", "");
        inventory.setProperty(p + "archivePassword", "false"); inventory.setProperty(p + "public", "false");
        inventory.setProperty(p + "artifact", root.relativize(artifact).toString().replace('\\', '/'));
        try (var walk = Files.walk(artifact)) {
            List<Path> files = walk.filter(Files::isRegularFile).sorted().toList();
            inventory.setProperty(p + "files", Integer.toString(files.size()));
            for (int i = 0; i < files.size(); i++) {
                inventory.setProperty(p + "file." + i, root.relativize(files.get(i)).toString().replace('\\', '/'));
                inventory.setProperty(p + "file." + i + ".sha256", sha256(files.get(i)));
            }
        }
        deleteWork(input.getParent());
        return index + 1;
    }

    /**
     * 验证格式与卷大小，认证与解密，并检查两种方式下的缺首卷、中卷、末卷。
     *
     * @param corpus 双格式语料
     * @param work 工作目录
     * @return 成功读取用例数
     *
     * @throws Exception 格式或明文核对失败
     */
    public static int verifyModes(Path corpus, Path work) throws Exception {
        int count = verifyAll(corpus, work.resolve("complete"));
        Properties inventory = new Properties();
        try (InputStream in = Files.newInputStream(corpus.resolve("manifest.properties"))) { inventory.load(in); }
        for (int i = 0; i < count; i++) {
            String p = "case." + i + ".";
            String id = inventory.getProperty(p + "id");
            Path artifact = corpus.resolve(inventory.getProperty(p + "artifact"));
            Path volumeDir = artifact;
            Path extracted = work.resolve("archive-" + i);
            if (inventory.getProperty(p + "workflow").equals("post")) {
                ArchiveExtractor.extractPreserving(artifact, extracted, ARCHIVE_PASSWORD);
                volumeDir = extracted;
            }
            Path base = findBase(volumeDir);
            var info = Splitter.inspect(base);
            boolean manifest = id.contains("mode-manifest-");
            require(Files.isRegularFile(Splitter.manifestPath(base)) == manifest, "Wrong format selected: " + id);
            for (Path chunk : info.chunks()) {
                require((SplitMetadata.read(chunk) == null) == manifest, "Footer policy mismatch: " + id);
                require(Files.size(chunk) <= 1024 * 1024, "Configured volume limit exceeded");
            }
            if (id.endsWith("-plain")) {
                require(info.expectedCount() >= 3, "Missing-volume test needs three volumes");
                for (int missing : List.of(0, 1, info.expectedCount() - 1)) {
                    Path folder = Files.createDirectories(work.resolve("missing-" + i + "-" + missing));
                    Path brokenBase = folder.resolve(base.getFileName());
                    for (Path file : Splitter.artifacts(base)) Files.copy(file, folder.resolve(file.getFileName()), StandardCopyOption.REPLACE_EXISTING);
                    Files.delete(Path.of(brokenBase + "." + missing));
                    var broken = Splitter.inspect(brokenBase);
                    require(broken.totalKnown() && broken.expectedCount() == info.expectedCount() && broken.missing().equals(List.of(missing)), "Incorrect missing volume hint");
                    Path selected = Path.of(brokenBase + "." + (missing == 0 ? 1 : 0));
                    VerifyRequest v = new VerifyRequest(); v.setInputFile(selected.toString()); v.setPassword(PASSWORD); v.setRsCodecs(new RsCodecs());
                    boolean rejected = false;
                    try { Verifier.verify(v); } catch (IOException expected) { rejected = true; }
                    require(rejected, "Missing volume authenticated");
                    DecryptRequest d = new DecryptRequest(); d.setInputFile(selected.toString()); d.setPassword(PASSWORD); d.setRsCodecs(new RsCodecs()); d.setOutputFile(folder.resolve("plain").toString());
                    rejected = false;
                    try { Decryptor.decrypt(d); } catch (IOException expected) { rejected = true; }
                    require(rejected && !Files.exists(Path.of(d.getOutputFile())), "Missing volume decrypted");
                    deleteWork(folder);
                }
            }
            if (Files.exists(extracted)) deleteWork(extracted);
        }
        deleteWork(work);
        return count;
    }

    /**
     * 创建一个用例，并记录全部分卷产物的 SHA-256。
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
            Path base=findBase(volumeDir);
            if(manifest.getProperty(p+"id").startsWith("embedded-")) {
                try(var walk=Files.walk(volumeDir)){require(walk.noneMatch(f->Splitter.isManifestPath(f.toString())),"New output contains sidecar");}
            }
            var inspection=Splitter.inspect(base);inspection.requireComplete();
            if(manifest.getProperty(p+"id").startsWith("embedded-")||manifest.getProperty(p+"id").endsWith("deniability")) {
                long maximum=(manifest.getProperty(p+"input").equals("source.bin")?7L:1L)*1024*1024;
                for(Path chunk:inspection.chunks())require(Files.size(chunk)<=maximum,"Volume exceeds configured maximum: "+chunk);
            }
            require(inspection.totalKnown() || manifest.getProperty(p+"id").equals("legacy-raw"),"Unknown total");
            List<String> keys=(Integer.parseInt(manifest.getProperty(p+"mask"))&8)==0?List.of():List.of(corpus.resolve("key1").toString(),corpus.resolve("key2").toString());
            VerifyRequest v=new VerifyRequest();v.setInputFile(selectInput(base).toString());v.setPassword(pw);v.setKeyfiles(keys);v.setRsCodecs(new RsCodecs());v.setRecombine(true);
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
            Path base=findBase(volumes);Path sidecar=selectInput(base);
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
            Path base=findBase(volumes);Path sidecar=selectInput(base);
            if(damage) {
                String baseName=base.toString();
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
        VerifyRequest v=new VerifyRequest();v.setInputFile(selectInput(base).toString());v.setPassword(PASSWORD);v.setKeyfiles(List.of(b.toString(),a.toString()));v.setRsCodecs(new RsCodecs());require(Verifier.verify(v),"Unordered reversed keyfiles failed verification");
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
            DecryptRequest d=new DecryptRequest();d.setInputFile(selectInput(base).toString());d.setOutputFile(root.resolve("restored.bin").toString());d.setPassword(PASSWORD);d.setRsCodecs(new RsCodecs());Decryptor.decrypt(d);
            require(sameBytes(source,Path.of(d.getOutputFile())),"Readonly source plaintext mismatch");
            for(Path artifact:artifacts)require(sha256(artifact).equals(before.get(artifact)),"Readonly source changed");
            try(var entries=Files.list(folder)){require(entries.count()==artifacts.size(),"Source-folder temporary file leaked");}
            System.out.println("SPLIT READONLY PASS directory write permission enforced="+enforced);
        } finally {
            folder.toFile().setWritable(true,false);for(Path artifact:artifacts)artifact.toFile().setWritable(true,false);
            deleteWork(root);
        }
    }

    /** @param folder 分卷目录 @return 新旧格式的基础路径 @throws IOException 未找到分卷。 */
    private static Path findBase(Path folder) throws IOException {
        try(var walk=Files.walk(folder)) {
            Path input=walk.filter(Files::isRegularFile)
                    .filter(f->Splitter.isSplitChunkPath(f.toString())||Splitter.isManifestPath(f.toString()))
                    .sorted().findFirst().orElseThrow(()->new IOException("Missing split volumes"));
            String path=input.toString();
            return Path.of(Splitter.isManifestPath(path)?path.substring(0,path.length()-".volumes".length()):Splitter.splitChunkBase(path));
        }
    }
    /** @param base 分卷基础路径 @return 可选择的旧清单或新碎片。 */
    private static Path selectInput(Path base) {
        return Files.isRegularFile(Splitter.manifestPath(base))?Splitter.manifestPath(base):Path.of(base+".0");
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
    /** @param path 输出路径 @param text UTF-8 文本 @throws IOException 写入失败。 */
    private static void writeUtf8(Path path,String text) throws IOException {
        Files.write(path,text.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    /** @param condition 断言 @param message 失败详情 @throws IOException 不满足。 */
    private static void require(boolean condition,String message) throws IOException {if(!condition)throw new IOException(message);}
}