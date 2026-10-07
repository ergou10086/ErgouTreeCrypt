package hbnu.project.ergoutreecrypt.fileops;

import hbnu.project.ergoutreecrypt.encoding.RsCodecs;
import hbnu.project.ergoutreecrypt.settings.SplitMetadataMode;
import hbnu.project.ergoutreecrypt.volume.*;
import java.io.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

/** 在桌面 JVM 与 Android ART 之间交换真实 ZIPX 产物，先认证再解密。 */
public final class ZipxInteropSupport {
    public static final String ARCHIVE_PASSWORD = "zipx-归档🔐";
    public static final String VOLUME_PASSWORD = "zipx-加密🔑";

    /** 禁止实例化。 */
    private ZipxInteropSupport() { }

    /**
     * 生成完整的真实文件编解码、卷及分卷用例，并验证生产端自身输出。
     * @param output 语料目录
     * @param source 真实 M4A 文件
     * @param mobile 生产端是否运行在 ART
     * @return 语料清单
     * @throws Exception 生产或生产端自校验失败
     */
    public static Properties generate(Path output, Path source, boolean mobile) throws Exception {
        Files.createDirectories(output);
        Path real = output.resolve("source.m4a");
        if (!real.equals(source)) Files.copy(source, real, StandardCopyOption.REPLACE_EXISTING);
        Path notes = output.resolve("notes.txt"), empty = output.resolve("empty");
        Files.write(notes, "ZIPX 双端真实文件互操作\n".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        Files.write(empty, new byte[0]);
        Properties manifest = new Properties();
        manifest.setProperty("source.sha256", sha256(real));
        manifest.setProperty("source.size", Long.toString(Files.size(real)));
        manifest.setProperty("notes.sha256", sha256(notes));
        manifest.setProperty("runtime", mobile ? "Android ART" : "Desktop JVM");
        int index = 0;
        for (ZipxMethod codec : ZipxMethod.values()) for (boolean password : List.of(false, true)) {
            index = produce(output, manifest, index, "archive-" + codec + "-" + password, "archive", codec,
                    password, false, SplitMetadataMode.EMBEDDED, mobile);
        }
        for (String workflow : List.of("pre", "post")) for (boolean password : List.of(false, true)) {
            index = produce(output, manifest, index, workflow + "-" + password, workflow, ZipxMethod.XZ,
                    password, false, SplitMetadataMode.EMBEDDED, mobile);
        }
        for (SplitMetadataMode mode : SplitMetadataMode.values()) for (String workflow : List.of("pre", "post")) {
            index = produce(output, manifest, index, "split-" + workflow + "-" + mode, workflow, ZipxMethod.XZ,
                    true, true, mode, mobile);
        }
        manifest.setProperty("count", Integer.toString(index));
        try (OutputStream out = Files.newOutputStream(output.resolve("manifest.properties"))) {
            manifest.store(out, "ZIPX real-file interop: authentication and extraction/decryption separately");
        }
        return manifest;
    }

    /**
     * 生成单个产物，立即执行独立认证与还原阶段。
     * @param root 语料根目录
     * @param manifest 用例清单
     * @param index 用例编号
     * @param id 稳定用例标识符
     * @param workflow 归档、前处理或后处理流程
     * @param codec 压缩方法
     * @param password 归档是否加密
     * @param split 卷是否分卷
     * @param mode 分卷元数据格式
     * @param mobile 生产端是否运行在 ART
     * @return 下一个用例编号
     * @throws Exception 生产或自校验失败
     */
    private static int produce(Path root, Properties manifest, int index, String id, String workflow,
                                ZipxMethod codec, boolean password, boolean split, SplitMetadataMode mode,
                                boolean mobile) throws Exception {
        Path artifact;
        String pwd = password ? ARCHIVE_PASSWORD : null;
        if (workflow.equals("archive")) {
            artifact = root.resolve(id + ".zipx");
            ZipxArchive.pack(artifact, List.of(root.resolve("source.m4a"), root.resolve("notes.txt"), root.resolve("empty")),
                    List.of("目录/[ひなみ桜花][2024-01-25].m4a", "notes.txt", "empty"), codec, pwd, null);
        } else {
            Path caseRoot = Files.createDirectories(root.resolve(id));
            EncryptRequest request = new EncryptRequest();
            request.setInputFile(root.resolve("source.m4a").toString());
            request.setOutputFile(caseRoot.resolve("data.ergou").toString());
            request.setPassword(VOLUME_PASSWORD); request.setRsCodecs(new RsCodecs());
            request.setArgon2MemoryKib(mobile ? 4096 : 8192); request.setArgon2Passes(1); request.setArgon2Threads(1);
            request.setSplit(split); request.setChunkSize(8); request.setSplitMetadataMode(mode);
            if (workflow.equals("pre")) {
                request.setPreArchiveFormat("ZIPX"); request.setPreArchivePassword(pwd);
            } else {
                request.setArchiveFormat("ZIPX"); request.setArchivePassword(pwd);
            }
            Encryptor.encrypt(request);
            artifact = split && workflow.equals("pre") ? caseRoot : Path.of(request.getOutputFile());
        }
        String prefix = "case." + index + ".";
        manifest.setProperty(prefix + "id", id);
        manifest.setProperty(prefix + "workflow", workflow);
        manifest.setProperty(prefix + "password", Boolean.toString(password));
        manifest.setProperty(prefix + "split", Boolean.toString(split));
        manifest.setProperty(prefix + "artifact", root.relativize(artifact).toString().replace('\\', '/'));
        manifest.setProperty(prefix + "artifact.sha256", treeHash(artifact));
        Path output = root.resolve("self-" + index);
        verify(root, output, manifest, index);
        deleteWork(output);
        return index + 1;
    }

    /**
     * 认证并还原单个传输产物，通过 SHA-256 和大小比较完整字节。
     * @param corpus 生产端语料目录
     * @param output 当前操作拥有的输出目录
     * @param manifest 生产端清单
     * @param index 用例编号
     * @throws Exception 任意认证或还原检查失败
     */
    public static void verify(Path corpus, Path output, Properties manifest, int index) throws Exception {
        Files.createDirectories(output);
        String prefix = "case." + index + ".";
        String id = manifest.getProperty(prefix + "id"), workflow = manifest.getProperty(prefix + "workflow");
        boolean split = Boolean.parseBoolean(manifest.getProperty(prefix + "split"));
        String pwd = Boolean.parseBoolean(manifest.getProperty(prefix + "password")) ? ARCHIVE_PASSWORD : null;
        Path artifact = corpus.resolve(manifest.getProperty(prefix + "artifact"));
        require(treeHash(artifact).equals(manifest.getProperty(prefix + "artifact.sha256")), "Transferred artifact changed: " + id);
        List<Path> restored;
        if (workflow.equals("archive")) {
            ZipxArchive.verify(artifact, pwd);
            System.out.println("ZIPX AUTHENTICATED " + id);
            restored = ArchiveExtractor.extract(artifact, output.resolve("files"), pwd);
            require(restored.size() == 3, "Missing Unicode, notes or empty entry");
            require(Files.size(output.resolve("files/empty")) == 0, "Empty file changed");
            require(sha256(output.resolve("files/notes.txt")).equals(manifest.getProperty("notes.sha256")), "Notes changed");
        } else {
            Path volume;
            if (workflow.equals("post")) {
                ZipxArchive.verify(artifact, pwd);
                Path extracted = output.resolve("volumes");
                List<Path> volumes = ArchiveExtractor.extract(artifact, extracted, pwd);
                volume = split ? splitInput(extracted) : volumes.getFirst();
            } else volume = split ? splitInput(artifact) : artifact;
            VerifyRequest verify = new VerifyRequest();
            verify.setInputFile(volume.toString()); verify.setPassword(VOLUME_PASSWORD);
            verify.setRsCodecs(new RsCodecs()); verify.setRecombine(split);
            require(Verifier.verify(verify), "Volume authentication failed: " + id);
            System.out.println("ZIPX AUTHENTICATED " + id);
            Path plain = output.resolve(workflow.equals("pre") ? "restored.zipx" : "restored.m4a");
            DecryptRequest decrypt = new DecryptRequest();
            decrypt.setInputFile(volume.toString()); decrypt.setOutputFile(plain.toString());
            decrypt.setPassword(VOLUME_PASSWORD); decrypt.setRsCodecs(new RsCodecs()); decrypt.setRecombine(split);
            Decryptor.decrypt(decrypt);
            if (workflow.equals("pre")) {
                require(ArchiveExtractor.hasEncryptedEntries(plain) == (pwd != null), "Pre-archive password ignored");
                ZipxArchive.verify(plain, pwd);
                restored = ArchiveExtractor.extract(plain, output.resolve("files"), pwd);
            } else restored = List.of(plain);
        }
        boolean found = false;
        for (Path file : restored) if (sha256(file).equals(manifest.getProperty("source.sha256"))) {
            require(Files.size(file) == Long.parseLong(manifest.getProperty("source.size")), "Source size changed");
            found = true;
        }
        require(found, "Real source file missing or changed: " + id);
        System.out.println("ZIPX RESTORED " + id + " SHA256=" + manifest.getProperty("source.sha256"));
    }

    /**
     * 验证从另一个运行时接收的所有用例。
     * @param corpus 生产端语料根目录
     * @param output 当前操作拥有的输出目录
     * @throws Exception 矩阵不完整或用例失败
     */
    public static void verifyAll(Path corpus, Path output) throws Exception {
        Properties manifest = new Properties();
        try (InputStream in = Files.newInputStream(corpus.resolve("manifest.properties"))) { manifest.load(in); }
        int count = Integer.parseInt(manifest.getProperty("count"));
        require(count == 14, "Incomplete ZIPX matrix: " + count);
        for (int index = 0; index < count; index++) {
            Path work = output.resolve("case-" + index);
            verify(corpus, work, manifest, index);
            deleteWork(work);
        }
    }

    /**
     * 空条目互通修复后仅重新生成 XZ 用例，保留无变化的用例。
     * @param corpus 已有完整生产端语料
     * @param mobile 生产端是否运行在 ART
     * @throws Exception 重新生成或生产端认证失败
     */
    public static void refreshXzArchives(Path corpus, boolean mobile) throws Exception {
        Properties manifest = manifest(corpus);
        int index = 4;
        for (boolean password : List.of(false, true)) {
            index = produce(corpus, manifest, index, "archive-XZ-" + password, "archive", ZipxMethod.XZ,
                    password, false, SplitMetadataMode.EMBEDDED, mobile);
        }
        try (OutputStream out = Files.newOutputStream(corpus.resolve("manifest.properties"))) {
            manifest.store(out, "ZIPX XZ archives refreshed; unaffected codec and volume cases retained");
        }
    }

    /**
     * 验证受影响的原始归档，不重复无变化的完整文件卷流程。
     * @param corpus 生产端语料
     * @param output 当前操作拥有的认证目录
     * @throws Exception 任意认证或还原失败
     */
    public static void verifyRawArchives(Path corpus, Path output) throws Exception {
        Properties manifest = manifest(corpus);
        for (int index = 0; index < 6; index++) {
            require("archive".equals(manifest.getProperty("case." + index + ".workflow")), "Missing raw archive case");
            Path work = output.resolve("case-" + index);
            verify(corpus, work, manifest, index);
            deleteWork(work);
        }
    }

    /**
     * 加载已有完整语料，用于定向复验。
     * @param corpus 生产端语料
     * @return 已验证的清单
     * @throws IOException 语料不完整
     */
    private static Properties manifest(Path corpus) throws IOException {
        Properties manifest = new Properties();
        try (InputStream in = Files.newInputStream(corpus.resolve("manifest.properties"))) { manifest.load(in); }
        require("14".equals(manifest.getProperty("count")), "Incomplete ZIPX corpus");
        return manifest;
    }

    /**
     * 选择真实分卷，测试元数据格式自动识别。
     * @param directory 已提取的分卷目录
     * @return 选中的分卷
     * @throws IOException 分卷文件缺失
     */
    private static Path splitInput(Path directory) throws IOException {
        try (var paths = Files.walk(directory)) {
            List<Path> chunks = paths.filter(Files::isRegularFile).filter(p -> Splitter.isSplitChunkPath(p.toString())).sorted().toList();
            require(chunks.size() > 1, "Real test file was not split");
            return chunks.getLast();
        }
    }

    /**
     * 计算文件或完整分卷目录树的哈希，包含每个相对文件名。
     * @param artifact 文件或目录
     * @return SHA-256 摘要
     * @throws Exception 哈希计算失败
     */
    private static String treeHash(Path artifact) throws Exception {
        if (Files.isRegularFile(artifact)) return sha256(artifact);
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (var paths = Files.walk(artifact)) {
            for (Path path : paths.filter(Files::isRegularFile).sorted().toList()) {
                digest.update(artifact.relativize(path).toString().replace('\\', '/').getBytes(java.nio.charset.StandardCharsets.UTF_8));
                digest.update(sha256(path).getBytes(java.nio.charset.StandardCharsets.US_ASCII));
            }
        }
        return hex(digest.digest());
    }

    /**
     * 逐字节计算文件哈希，不把完整文件加载到内存。
     * @param path 源文件
     * @return SHA-256 摘要
     * @throws Exception 哈希计算失败
     */
    public static String sha256(Path path) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (InputStream in = Files.newInputStream(path)) {
            byte[] buffer = new byte[65536]; int count;
            while ((count = in.read(buffer)) != -1) digest.update(buffer, 0, count);
        }
        return hex(digest.digest());
    }

    /**
     * 将摘要字节转为可移植的小写十六进制。
     * @param bytes 摘要字节
     * @return 十六进制字符串
     */
    private static String hex(byte[] bytes) {
        StringBuilder text = new StringBuilder();
        for (byte value : bytes) text.append(String.format(Locale.ROOT, "%02x", value & 255));
        return text.toString();
    }

    /**
     * 检查回归测试的不变量。
     * @param condition 必须成立的条件
     * @param message 失败说明
     * @throws IOException 不变量不成立
     */
    private static void require(boolean condition, String message) throws IOException {
        if (!condition) throw new IOException(message);
    }

    /**
     * 仅删除生成的认证目录。
     * @param work 当前操作拥有的测试输出
     * @throws IOException 清理失败
     */
    private static void deleteWork(Path work) throws IOException {
        try (var paths = Files.walk(work)) {
            for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) Files.deleteIfExists(path);
        }
    }
}
