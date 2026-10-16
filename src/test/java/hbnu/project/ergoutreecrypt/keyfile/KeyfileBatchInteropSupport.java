package hbnu.project.ergoutreecrypt.keyfile;

import hbnu.project.ergoutreecrypt.encoding.RsCodecs;
import hbnu.project.ergoutreecrypt.fileops.Splitter;
import hbnu.project.ergoutreecrypt.settings.SplitMetadataMode;
import hbnu.project.ergoutreecrypt.volume.*;
import java.nio.file.*;
import java.util.*;

/** 密钥文件的目录深度、串并行和分卷在真实 JVM/ART 间交换。 */
public final class KeyfileBatchInteropSupport {
    private static final String PASSWORD = "目录密钥🔐";
    private static final List<String> INPUTS = List.of("same.bin", "A/same.bin", "B/same.bin", "A/deep/empty.bin");

    /** 禁止实例化。 */
    private KeyfileBatchInteropSupport() {}

    /**
     * @param corpus 可信语料根
     * @param output 密文输出
     * @param mobile 是否实际 ART
     * @return 目录配置数
     * @throws Exception 生成失败
     */
    public static int produce(Path corpus, Path output, boolean mobile) throws Exception {
        return produce(corpus, output, mobile, true);
    }

    /**
     * @param corpus 可信输入
     * @param output 密文输出
     * @param mobile 是否实际 ART
     * @param profiles 是否额外执行五个生产档位
     * @return 目录配置数
     * @throws Exception 生成失败
     */
    public static int produce(Path corpus, Path output, boolean mobile, boolean profiles) throws Exception {
        Files.createDirectory(output);
        Properties inventory = new Properties();
        inventory.setProperty("vm", System.getProperty("java.vm.name"));
        int count = 0;
        for (int depth : List.of(1, 2, 6)) for (int threads : List.of(1, 3)) for (boolean ordered : List.of(false, true)) {
            Path root = Files.createDirectory(output.resolve("case-" + count));
            Path tree = Files.createDirectory(root.resolve("tree"));
            for (int i = 0; i < INPUTS.size(); i++) {
                Path file = tree.resolve(INPUTS.get(i)); Files.createDirectories(file.getParent());
                byte[] data = Files.readAllBytes(corpus.resolve(i == 3 ? "empty.bin" : "sample.bin"));
                if (data.length > 0) data[0] ^= (byte) i;
                Files.write(file, data);
            }
            Path encrypted = Files.createDirectory(root.resolve("encrypted"));
            FolderCrypt.EncryptOptions options = new FolderCrypt.EncryptOptions();
            options.password = PASSWORD; options.keyfiles = keys(corpus, ordered, false); options.keyfileOrdered = ordered;
            options.rsCodecs = new RsCodecs(); options.argon2MemoryKib = mobile ? 4096 : 8192;
            options.argon2Passes = 1; options.argon2Threads = 2;
            options.encryptDepth = depth; options.threadCount = threads; options.paranoid = true;
            options.reedSolomon = true; options.compress = true; options.split = true; options.chunkSize = 1;
            options.splitMetadataMode = ordered ? SplitMetadataMode.MANIFEST : SplitMetadataMode.EMBEDDED;
            FolderCrypt.encryptFolder(tree, encrypted, options);
            require(options.batchResult.failedCount() == 0 && options.batchResult.succeededCount() > 0, "目录加密失败");
            inventory.setProperty(count + ".ordered", "" + ordered);
            inventory.setProperty(count + ".threads", "" + threads);
            inventory.setProperty(count + ".depth", "" + depth);
            try (var walk = Files.walk(encrypted)) {
                for (Path file : walk.filter(Files::isRegularFile).toList())
                    inventory.setProperty("hash." + relative(output, file), KeyfileInteropSupport.sha256(file));
            }
            KeyfileInteropSupport.delete(tree);
            System.out.println("KEYFILE BATCH PRODUCED " + count++ + " depth=" + depth + " threads=" + threads + " ordered=" + ordered);
        }
        inventory.setProperty("count", "" + count);
        inventory.setProperty("profiles", "" + profiles);
        if (profiles) require(KeyfileInteropSupport.produceProfiles(corpus, output.resolve("profiles"), mobile) == 5, "生产档位数量错误");
        try (var out = Files.newOutputStream(output.resolve("manifest.properties"))) { inventory.store(out, "Keyfile directory interop"); }
        return count;
    }

    /**
     * @param corpus 可信输入
     * @param ciphers 指定生产端的实际产物
     * @param scratch 独占还原目录
     * @return 已通过配置数
     * @throws Exception 认证或还原失败
     */
    public static int verify(Path corpus, Path ciphers, Path scratch) throws Exception {
        Properties inventory = new Properties();
        try (var in = Files.newInputStream(ciphers.resolve("manifest.properties"))) { inventory.load(in); }
        for (String key : inventory.stringPropertyNames()) if (key.startsWith("hash."))
            require(KeyfileInteropSupport.sha256(ciphers.resolve(key.substring(5))).equals(inventory.getProperty(key)), "目录密文搬运损坏");
        int count = Integer.parseInt(inventory.getProperty("count"));
        for (int i = 0; i < count; i++) {
            Path encrypted = ciphers.resolve("case-" + i + "/encrypted/tree");
            boolean ordered = Boolean.parseBoolean(inventory.getProperty(i + ".ordered"));
            List<String> keys = keys(corpus, ordered, true);
            Set<String> bases = new HashSet<>();
            try (var walk = Files.walk(encrypted)) {
                for (Path file : walk.filter(Files::isRegularFile).sorted().toList()) {
                    String base = Splitter.splitChunkBase(file.toString());
                    if (base == null && Splitter.isManifestPath(file.toString())) base = file.toString().substring(0, file.toString().length() - 8);
                    if (base == null || !bases.add(base)) continue;
                    VerifyRequest request = new VerifyRequest(); request.setInputFile(file.toString());
                    request.setPassword(PASSWORD); request.setKeyfiles(keys); request.setRsCodecs(new RsCodecs());
                    require(Verifier.verify(request), "目录分卷认证失败");
                }
            }
            require(!bases.isEmpty(), "没有独立认证目录分卷");
            Path work = Files.createDirectories(scratch.resolve("case-" + i));
            try {
                FolderCrypt.DecryptOptions options = new FolderCrypt.DecryptOptions();
                options.password = PASSWORD; options.keyfiles = keys; options.rsCodecs = new RsCodecs();
                options.threadCount = Integer.parseInt(inventory.getProperty(i + ".threads"));
                options.recursiveExtract = true; options.decryptThenExtract = true;
                FolderCrypt.decryptAuto(encrypted, work, options);
                require(options.batchResult.failedCount() == 0 && options.batchResult.succeededCount() > 0,
                        "目录解密失败 case=" + i + " failures=" + options.batchResult.failures());
                List<Path> files;
                try (var walk = Files.walk(work)) { files = walk.filter(Files::isRegularFile).toList(); }
                int depth = Integer.parseInt(inventory.getProperty(i + ".depth"));
                int retainedArchives = depth == 1 ? 2 : depth == 2 ? 1 : 0;
                require(files.size() == INPUTS.size() + retainedArchives, "还原目录条目数错误: " + files);
                require(files.stream().filter(p -> p.toString().endsWith(".zip")).count() == retainedArchives,
                        "深目录归档保留策略改变");
                for (int j = 0; j < INPUTS.size(); j++) {
                    String suffix = "tree/" + INPUTS.get(j);
                    Path file = files.stream().filter(p -> p.toString().replace('\\', '/').endsWith(suffix)).findFirst().orElseThrow();
                    byte[] expected = Files.readAllBytes(corpus.resolve(j == 3 ? "empty.bin" : "sample.bin"));
                    if (expected.length > 0) expected[0] ^= (byte) j;
                    require(Arrays.equals(expected, Files.readAllBytes(file)), "目录路径或字节改变");
                    Path expectedFile = work.resolve("expected"); Files.write(expectedFile, expected);
                    require(KeyfileInteropSupport.sha256(file).equals(KeyfileInteropSupport.sha256(expectedFile)), "目录明文摘要错误");
                    Files.delete(expectedFile);
                }
            } finally { KeyfileInteropSupport.delete(work); }
            System.out.println("KEYFILE BATCH VERIFIED " + i + " AUTH+DECRYPT+PATHS+BYTES+SHA256");
        }
        if (Boolean.parseBoolean(inventory.getProperty("profiles"))) {
            require(KeyfileInteropSupport.verify(corpus, ciphers.resolve("profiles"), scratch.resolve("profiles")) == 5,
                    "生产档位认证或解密失败");
        }
        return count;
    }

    /**
     * @param corpus 输入根
     * @param ordered 是否有序
     * @param read 是否读取端
     * @return 密钥列表
     */
    private static List<String> keys(Path corpus, boolean ordered, boolean read) {
        String a = corpus.resolve(read ? "改名-a" : "key-a").toString(), b = corpus.resolve(read ? "改名-b" : "key-b").toString();
        return read && !ordered ? List.of(b, a) : List.of(a, b);
    }

    /**
     * @param root 根
     * @param file 文件
     * @return 平台无关路径
     */
    private static String relative(Path root, Path file) { return root.relativize(file).toString().replace('\\', '/'); }

    /**
     * @param condition 断言
     * @param message 详情
     * @throws Exception 验证失败
     */
    private static void require(boolean condition, String message) throws Exception { if (!condition) throw new java.io.IOException(message); }
}
