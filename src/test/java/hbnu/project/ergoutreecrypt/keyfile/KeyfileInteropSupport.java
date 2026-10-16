package hbnu.project.ergoutreecrypt.keyfile;

import hbnu.project.ergoutreecrypt.crypto.BruteForceGuard;
import hbnu.project.ergoutreecrypt.encoding.RsCodecs;
import hbnu.project.ergoutreecrypt.fileops.ArchiveExtractor;
import hbnu.project.ergoutreecrypt.fileops.ArchivePacker;
import hbnu.project.ergoutreecrypt.fileops.Splitter;
import hbnu.project.ergoutreecrypt.settings.SettingsManager;
import hbnu.project.ergoutreecrypt.settings.SplitMetadataMode;
import hbnu.project.ergoutreecrypt.volume.*;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.*;

/** 同一测试桥分别运行在桌面 JVM 和真实 Android ART，交换原始密文。 */
public final class KeyfileInteropSupport {
    private static final String PASSWORD = "é-密钥🔐 ";
    private static final String ARCHIVE_PASSWORD = "独立归档🔑";

    /** 禁止实例化。 */
    private KeyfileInteropSupport() {}

    /**
     * 建立固定输入、异名同内容密钥以及原始音频的可信清单。
     * @param source 真实音频
     * @param corpus 尚不存在的独占目录
     * @throws Exception 读写失败
     */
    public static void prepare(Path source, Path corpus) throws Exception {
        Files.createDirectory(corpus);
        Files.copy(source, corpus.resolve("real.m4a"));
        try (var input = Files.newInputStream(source)) {
            Files.write(corpus.resolve("sample.bin"), input.readNBytes(8193));
        }
        Files.write(corpus.resolve("empty.bin"), new byte[0]);
        Files.write(corpus.resolve("one.bin"), new byte[]{0});
        Files.write(corpus.resolve("key-a"), new byte[]{0, 1, -1, 4, 8, 0, 9});
        Files.write(corpus.resolve("key-b"), "密钥文件\r\n日本語🔐\u0000".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        Files.copy(corpus.resolve("key-a"), corpus.resolve("改名-a"));
        Files.copy(corpus.resolve("key-b"), corpus.resolve("改名-b"));
        Files.write(corpus.resolve("wrong-key"), new byte[]{0, 1, -1, 4, 8, 0, 10});
        Properties manifest = new Properties();
        for (String name : List.of("real.m4a", "sample.bin", "empty.bin", "one.bin", "key-a", "key-b"))
            manifest.setProperty(name, sha256(corpus.resolve(name)));
        store(manifest, corpus.resolve("inputs.properties"));
    }

    /**
     * 生成全因子核心矩阵、七类归档和真实完整音频产物。
     * @param corpus 可信输入
     * @param output 尚不存在的密文目录
     * @param mobile 是否实际 ART
     * @param slow 是否包括真实生产 KDF 和旧可否认层
     * @return 用例数
     * @throws Exception 加密或文件校验失败
     */
    public static int produce(Path corpus, Path output, boolean mobile, boolean slow) throws Exception {
        Files.createDirectory(output);
        Properties inventory = new Properties();
        inventory.setProperty("runtime", System.getProperty("java.runtime.version"));
        inventory.setProperty("vm", System.getProperty("java.vm.name"));
        inventory.setProperty("os", System.getProperty("os.name"));
        inventory.setProperty("source.sha256", sha256(corpus.resolve("real.m4a")));
        int count = 0;
        boolean saved = SettingsManager.isArchiveCustomEncryption();
        boolean fallback = SettingsManager.isArchivePasswordFallback();
        SettingsManager.setArchiveCustomEncryption(true);
        SettingsManager.setArchivePasswordFallback(false);
        try {
            for (int mask = 0; mask < 32; mask++) {
                for (int split = 0; split < 3; split++) {
                    Properties spec = spec("matrix-" + mask + "-" + split, "sample.bin", mask, split);
                    count = produceCase(corpus, output, inventory, count, spec, mobile);
                }
            }
            for (String format : List.of("ZIP", "ZIPX", "GZ", "TAR_GZ", "7Z", "LZ4", "TAR_LZ4")) {
                for (String workflow : List.of("pre", "post")) {
                    for (int ordered = 0; ordered < 2; ordered++) {
                        for (int protectedArchive = 0; protectedArchive < 2; protectedArchive++) {
                            Properties spec = spec("archive-" + format + "-" + workflow + "-" + ordered + "-" + protectedArchive,
                                    "sample.bin", 28 | ordered | (protectedArchive << 1), 1 + ordered);
                            spec.setProperty("format", format);
                            spec.setProperty("workflow", workflow);
                            spec.setProperty("archivePassword", "" + (protectedArchive != 0));
                            count = produceCase(corpus, output, inventory, count, spec, mobile);
                        }
                    }
                }
            }
            for (String input : List.of("empty.bin", "one.bin", "real.m4a")) {
                for (int mask : new int[]{0, 31})
                    count = produceCase(corpus, output, inventory, count, spec("boundary-" + input + "-" + mask, input, mask, mask == 0 ? 0 : 1), mobile);
            }
            for (String keys : List.of("single", "empty", "large")) {
                for (int mask : new int[]{0, 3}) {
                    Properties spec = spec("key-form-" + keys + "-" + mask, "sample.bin", mask, 0);
                    spec.setProperty("keys", keys);
                    count = produceCase(corpus, output, inventory, count, spec, mobile);
                }
            }
            if (slow) {
                for (int mask : new int[]{0, 1, 2, 3}) {
                    Properties spec = spec("production-kdf-" + mask, "sample.bin", mask, 0);
                    spec.setProperty("production", "true");
                    count = produceCase(corpus, output, inventory, count, spec, mobile);
                }
                for (int mask : new int[]{0, 3, 28, 31}) {
                    Properties spec = spec("deniability-" + mask, "sample.bin", mask, 1);
                    spec.setProperty("deniable", "true");
                    count = produceCase(corpus, output, inventory, count, spec, mobile);
                }
            }
        } finally {
            SettingsManager.setArchiveCustomEncryption(saved);
            SettingsManager.setArchivePasswordFallback(fallback);
        }
        inventory.setProperty("count", Integer.toString(count));
        store(inventory, output.resolve("manifest.properties"));
        return count;
    }

    /**
     * @param id 名称
     * @param input 输入名
     * @param mask 有序、无密码、偏执、RS、Zstd 五位开关
     * @param split 0=不分卷，1=嵌入，2=清单
     * @return 用例参数
     */
    private static Properties spec(String id, String input, int mask, int split) {
        Properties spec = new Properties();
        spec.setProperty("id", id); spec.setProperty("input", input);
        spec.setProperty("mask", "" + mask); spec.setProperty("split", "" + split);
        spec.setProperty("keys", "pair"); spec.setProperty("workflow", "");
        return spec;
    }

    /**
     * 五个生产参数覆盖移动自动回退、省电、均衡、桌面强和桌面偏执档。
     * 全部保留非空密码，保证认证确实依赖 KDF 结果。
     * @param corpus 可信输入
     * @param output 独占产物目录
     * @param mobile 是否实际 ART
     * @return 档位数
     * @throws Exception 生成失败
     */
    public static int produceProfiles(Path corpus, Path output, boolean mobile) throws Exception {
        Files.createDirectory(output);
        int[][] profiles = {{32 << 10, 2, 2}, {64 << 10, 2, 2}, {256 << 10, 3, 4}, {1 << 20, 4, 4}, {1 << 20, 8, 8}};
        Properties inventory = new Properties();
        inventory.setProperty("runtime", System.getProperty("java.runtime.version"));
        inventory.setProperty("vm", System.getProperty("java.vm.name"));
        inventory.setProperty("source.sha256", sha256(corpus.resolve("real.m4a")));
        int count = 0;
        for (int[] profile : profiles) {
            Properties spec = spec("tier-" + profile[0] + "-" + profile[1] + "-" + profile[2], "sample.bin", count % 2 == 0 ? 29 : 28, 1);
            spec.setProperty("memory", "" + profile[0]); spec.setProperty("passes", "" + profile[1]);
            spec.setProperty("lanes", "" + profile[2]); spec.setProperty("profile", "true");
            count = produceCase(corpus, output, inventory, count, spec, mobile);
        }
        inventory.setProperty("count", "" + count);
        store(inventory, output.resolve("manifest.properties"));
        return count;
    }

    /**
     * @param corpus 输入根
     * @param output 密文根
     * @param inventory 清单
     * @param index 编号
     * @param spec 参数
     * @param mobile 实际 ART
     * @return 下一编号
     * @throws Exception 加密失败
     */
    private static int produceCase(Path corpus, Path output, Properties inventory, int index, Properties spec, boolean mobile) throws Exception {
        Path directory = Files.createDirectory(output.resolve("case-" + index));
        int mask = Integer.parseInt(spec.getProperty("mask")), split = Integer.parseInt(spec.getProperty("split"));
        EncryptRequest request = new EncryptRequest();
        request.setInputFile(corpus.resolve(spec.getProperty("input")).toString());
        request.setOutputFile(directory.resolve("payload.ergou").toString());
        request.setPassword(password(spec)); request.setKeyfiles(keys(corpus, spec, false));
        request.setKeyfileOrdered((mask & 1) != 0); request.setParanoid((mask & 4) != 0);
        request.setReedSolomon((mask & 8) != 0); request.setCompress((mask & 16) != 0);
        request.setComments("密钥互通🔐 " + spec.getProperty("id")); request.setRsCodecs(new RsCodecs());
        request.setSplit(split != 0); request.setChunkSize(1);
        request.setSplitMetadataMode(split == 2 ? SplitMetadataMode.MANIFEST : SplitMetadataMode.EMBEDDED);
        if (spec.getProperty("memory") != null) {
            request.setArgon2MemoryKib(Integer.parseInt(spec.getProperty("memory")));
            request.setArgon2Passes(Integer.parseInt(spec.getProperty("passes")));
            request.setArgon2Threads(Integer.parseInt(spec.getProperty("lanes")));
        } else if (Boolean.parseBoolean(spec.getProperty("production"))) {
            if (mobile) {
                request.setArgon2MemoryKib(256 << 10); request.setArgon2Passes(3); request.setArgon2Threads(4);
            }
        } else {
            request.setArgon2MemoryKib(mobile ? 4096 : 8192); request.setArgon2Passes(1); request.setArgon2Threads(2);
        }
        request.setDeniability(Boolean.parseBoolean(spec.getProperty("deniable")));
        String archivePassword = Boolean.parseBoolean(spec.getProperty("archivePassword")) ? ARCHIVE_PASSWORD : null;
        if ("pre".equals(spec.getProperty("workflow"))) {
            request.setPreArchiveFormat(spec.getProperty("format")); request.setPreArchivePassword(archivePassword);
        } else if ("post".equals(spec.getProperty("workflow"))) {
            request.setArchiveFormat(spec.getProperty("format")); request.setArchivePassword(archivePassword);
        }
        Encryptor.encrypt(request);
        Path produced = Path.of(request.getOutputFile());
        spec.setProperty("artifact", relative(output, Files.exists(produced) ? produced : directory));
        List<Path> files;
        try (var walk = Files.walk(directory)) { files = walk.filter(Files::isRegularFile).sorted().toList(); }
        spec.setProperty("files", "" + files.size());
        for (int i = 0; i < files.size(); i++) {
            spec.setProperty("file." + i, relative(output, files.get(i)));
            spec.setProperty("hash." + i, sha256(files.get(i)));
        }
        for (String key : spec.stringPropertyNames()) inventory.setProperty(index + "." + key, spec.getProperty(key));
        System.out.println("KEYFILE PRODUCED " + index + " " + spec.getProperty("id"));
        return index + 1;
    }

    /**
     * 每个案例独立认证、解密，流式逐字节和 SHA-256 核对，精选配置执行错误密钥攻击。
     * @param corpus 可信输入
     * @param ciphers 指定生产端产物
     * @param scratch 独占临时目录
     * @return 成功用例数
     * @throws Exception 任一断言失败
     */
    public static int verify(Path corpus, Path ciphers, Path scratch) throws Exception {
        Files.createDirectories(scratch);
        BruteForceGuard.getInstance().init(scratch.resolve("guard"));
        Properties inventory = read(ciphers.resolve("manifest.properties"));
        Properties inputs = read(corpus.resolve("inputs.properties"));
        require(inputs.getProperty("real.m4a").equals(inventory.getProperty("source.sha256")), "错误来源");
        int count = Integer.parseInt(inventory.getProperty("count"));
        for (int i = 0; i < count; i++) {
            Properties spec = new Properties();
            String prefix = i + ".";
            for (String key : inventory.stringPropertyNames())
                if (key.startsWith(prefix)) spec.setProperty(key.substring(prefix.length()), inventory.getProperty(key));
            for (int f = 0; f < Integer.parseInt(spec.getProperty("files")); f++)
                require(sha256(ciphers.resolve(spec.getProperty("file." + f))).equals(spec.getProperty("hash." + f)), "密文搬运损坏");
            Path work = Files.createDirectory(scratch.resolve("case-" + i));
            try {
                Path artifact = ciphers.resolve(spec.getProperty("artifact"));
                String archivePassword = Boolean.parseBoolean(spec.getProperty("archivePassword")) ? ARCHIVE_PASSWORD : null;
                if ("post".equals(spec.getProperty("workflow"))) {
                    Path extracted = work.resolve("volumes");
                    ArchiveExtractor.extractPreserving(artifact, extracted, archivePassword); artifact = extracted;
                }
                Path volume = selectVolume(artifact);
                List<String> keys = keys(corpus, spec, true);
                Set<String> before = names(work);
                require(Verifier.verify(verification(volume, password(spec), keys)), "认证失败 " + spec.getProperty("id"));
                require(before.equals(names(work)), "认证产生明文或残留");
                String extension = "pre".equals(spec.getProperty("workflow"))
                        ? ArchivePacker.extOf(ArchivePacker.parseFormat(spec.getProperty("format"))) : "";
                Path plain = work.resolve("restored" + extension);
                DecryptRequest decrypt = decryption(volume, plain, password(spec), keys);
                Decryptor.decrypt(decrypt);
                if (!extension.isEmpty()) {
                    List<Path> extracted = ArchiveExtractor.extractPreserving(plain, work.resolve("plain"), archivePassword);
                    require(extracted.size() == 1, "归档条目数错误"); plain = extracted.get(0);
                }
                Path source = corpus.resolve(spec.getProperty("input"));
                require(equalBytes(source, plain), "逐字节还原失败 " + spec.getProperty("id"));
                require(sha256(plain).equals(inputs.getProperty(spec.getProperty("input"))), "明文 SHA-256 错误");
                if (!Boolean.parseBoolean(spec.getProperty("profile"))
                        && (i < 6 || spec.getProperty("id").startsWith("matrix-31-") || spec.getProperty("id").startsWith("key-form-")))
                    attacks(corpus, volume, spec, work);
            } finally { delete(work); }
            System.out.println("KEYFILE VERIFIED " + i + " " + spec.getProperty("id") + " AUTH+DECRYPT+BYTES+SHA256");
        }
        return count;
    }

    /**
     * @param corpus 输入根
     * @param volume 密文
     * @param spec 参数
     * @param work 独占目录
     * @throws Exception 错误凭据被接受
     */
    private static void attacks(Path corpus, Path volume, Properties spec, Path work) throws Exception {
        List<List<String>> attempts = new ArrayList<>();
        attempts.add(List.of()); attempts.add(List.of(corpus.resolve("wrong-key").toString()));
        if ("pair".equals(spec.getProperty("keys"))) {
            attempts.add(List.of(corpus.resolve("key-a").toString()));
            attempts.add(List.of(corpus.resolve("key-a").toString(), corpus.resolve("wrong-key").toString()));
            attempts.add(List.of(corpus.resolve("key-a").toString(), corpus.resolve("key-a").toString(), corpus.resolve("key-b").toString()));
            if ((Integer.parseInt(spec.getProperty("mask")) & 1) != 0)
                attempts.add(List.of(corpus.resolve("key-b").toString(), corpus.resolve("key-a").toString()));
        }
        for (List<String> keys : attempts) reject(volume, work.resolve("forbidden"), password(spec), keys);
        reject(volume, work.resolve("forbidden"), "wrong-password", keys(corpus, spec, true));
    }

    /**
     * @param volume 密文
     * @param output 禁止产生的明文
     * @param password 错误密码或正确密码
     * @param keys 错误密钥或正确密钥
     * @throws Exception 错误凭据被接受
     */
    private static void reject(Path volume, Path output, String password, List<String> keys) throws Exception {
        BruteForceGuard.getInstance().resetCounter(volume.toString());
        boolean rejected = false;
        try { Verifier.verify(verification(volume, password, keys)); } catch (Exception expected) { rejected = true; }
        require(rejected, "错误密钥通过认证"); rejected = false;
        try { Decryptor.decrypt(decryption(volume, output, password, keys)); } catch (Exception expected) { rejected = true; }
        require(rejected && !Files.exists(output) && !Files.exists(Path.of(output + ".incomplete")), "错误密钥产生明文");
        BruteForceGuard.getInstance().resetCounter(volume.toString());
    }

    /**
     * @param path 密文
     * @param password 密码
     * @param keys 密钥文件
     * @return 认证请求
     */
    private static VerifyRequest verification(Path path, String password, List<String> keys) {
        VerifyRequest request = new VerifyRequest(); request.setInputFile(path.toString());
        request.setPassword(password); request.setKeyfiles(keys); request.setRsCodecs(new RsCodecs()); return request;
    }

    /**
     * @param path 密文
     * @param output 明文
     * @param password 密码
     * @param keys 密钥文件
     * @return 解密请求
     */
    private static DecryptRequest decryption(Path path, Path output, String password, List<String> keys) {
        DecryptRequest request = new DecryptRequest(); request.setInputFile(path.toString()); request.setOutputFile(output.toString());
        request.setPassword(password); request.setKeyfiles(keys); request.setRsCodecs(new RsCodecs()); return request;
    }

    /**
     * @param corpus 输入根
     * @param spec 参数
     * @param renamed 读取端使用异名文件并颠倒无序列表
     * @return 密钥列表
     */
    private static List<String> keys(Path corpus, Properties spec, boolean renamed) {
        String kind = spec.getProperty("keys");
        if ("empty".equals(kind)) return List.of(corpus.resolve("empty.bin").toString());
        if ("large".equals(kind)) return List.of(corpus.resolve("real.m4a").toString());
        String a = corpus.resolve(renamed ? "改名-a" : "key-a").toString();
        if ("single".equals(kind)) return List.of(a);
        String b = corpus.resolve(renamed ? "改名-b" : "key-b").toString();
        return renamed && (Integer.parseInt(spec.getProperty("mask")) & 1) == 0 ? List.of(b, a) : List.of(a, b);
    }

    /**
     * @param spec 参数
     * @return 保留 Unicode 与尾随空格的密码，或空密码
     */
    private static String password(Properties spec) {
        return (Integer.parseInt(spec.getProperty("mask")) & 2) == 0 ? PASSWORD : "";
    }

    /**
     * @param artifact 文件或分卷目录
     * @return 可读取的密文入口
     * @throws IOException 未找到入口
     */
    private static Path selectVolume(Path artifact) throws IOException {
        if (Files.isRegularFile(artifact)) return artifact;
        try (var walk = Files.walk(artifact)) {
            return walk.filter(Files::isRegularFile).filter(p -> Splitter.isSplitChunkPath(p.toString()) || Splitter.isManifestPath(p.toString()) || p.toString().endsWith(".ergou"))
                    .sorted().findFirst().orElseThrow(() -> new IOException("缺少密文入口"));
        }
    }

    /**
     * @param root 根
     * @param file 文件
     * @return 平台无关相对路径
     */
    private static String relative(Path root, Path file) { return root.relativize(file).toString().replace('\\', '/'); }

    /**
     * @param root 目录
     * @return 相对文件清单
     * @throws IOException 读取失败
     */
    private static Set<String> names(Path root) throws IOException {
        try (var walk = Files.walk(root)) { return new HashSet<>(walk.map(p -> relative(root, p)).toList()); }
    }

    /**
     * @param left 原始文件
     * @param right 还原文件
     * @return 是否逐字节相等
     * @throws IOException 读取失败
     */
    private static boolean equalBytes(Path left, Path right) throws IOException {
        if (Files.size(left) != Files.size(right)) return false;
        try (var a = Files.newInputStream(left); var b = Files.newInputStream(right)) {
            while (true) { byte[] x = a.readNBytes(1 << 20), y = b.readNBytes(1 << 20); if (!Arrays.equals(x, y)) return false; if (x.length == 0) return true; }
        }
    }

    /**
     * @param path 文件
     * @return SHA-256
     * @throws Exception 读取失败
     */
    public static String sha256(Path path) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (var input = Files.newInputStream(path)) { byte[] buffer = new byte[1 << 20]; int n; while ((n = input.read(buffer)) != -1) digest.update(buffer, 0, n); }
        return HexFormat.of().formatHex(digest.digest());
    }

    /**
     * @param properties 清单
     * @param path 输出文件
     * @throws IOException 写入失败
     */
    private static void store(Properties properties, Path path) throws IOException {
        try (var output = Files.newOutputStream(path)) { properties.store(output, "Keyfile interoperability audit"); }
    }

    /**
     * @param path 清单文件
     * @return 清单
     * @throws IOException 读取失败
     */
    private static Properties read(Path path) throws IOException {
        Properties properties = new Properties(); try (var input = Files.newInputStream(path)) { properties.load(input); } return properties;
    }

    /**
     * @param root 本次独占目录
     * @throws IOException 清理失败
     */
    public static void delete(Path root) throws IOException {
        if (!Files.exists(root)) return;
        try (var walk = Files.walk(root)) { for (Path path : walk.sorted(Comparator.reverseOrder()).toList()) Files.delete(path); }
    }

    /**
     * @param condition 必须成立的条件
     * @param message 错误详情
     * @throws IOException 断言失败
     */
    private static void require(boolean condition, String message) throws IOException { if (!condition) throw new IOException(message); }
}
