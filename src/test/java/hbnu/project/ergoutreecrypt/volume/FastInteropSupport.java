package hbnu.project.ergoutreecrypt.volume;

import hbnu.project.ergoutreecrypt.crypto.BruteForceGuard;
import hbnu.project.ergoutreecrypt.exception.CryptoException;
import hbnu.project.ergoutreecrypt.exception.ErrorKind;
import hbnu.project.ergoutreecrypt.header.VolumeFormatProbe;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Properties;

/** 同一份源码运行于桌面 JVM 与实际 ART，搬运完全相同的产物逐项认证和解密。 */
public final class FastInteropSupport {
    private static final String PASSWORD = "e\u0301-极速🔐 ";
    private static final String READER_PASSWORD = "é-极速🔐 ";
    private static final int[] SIZES = {
        0, 1, 15, 16, 17, (1 << 20) - 57, (1 << 20) - 56, (1 << 20) - 55,
        2 * (1 << 20) - 73, 2 * (1 << 20) - 72, 2 * (1 << 20) - 71,
        3 * (1 << 20) + 17
    };

    /** 禁止实例化工具类。 */
    private FastInteropSupport() {}

    /**
     * 从用户真实文件建立独占测试语料，保存来源与各项 SHA-256。
     * @param source 真实输入文件
     * @param root 尚不存在的语料目录
     * @throws Exception 读写或加密失败
     */
    public static void generate(Path source, Path root) throws Exception {
        Files.createDirectory(root);
        Path inputs = Files.createDirectory(root.resolve("inputs"));
        byte[] prefix;
        try (var in = Files.newInputStream(source)) {
            prefix = in.readNBytes(SIZES[SIZES.length - 1]);
        }
        require(prefix.length == SIZES[SIZES.length - 1], "真实文件太小");
        Properties manifest = new Properties();
        manifest.setProperty("source.sha256", sha256(source));
        manifest.setProperty("count", Integer.toString(SIZES.length + 1));
        for (int i = 0; i <= SIZES.length; i++) {
            Path input = inputs.resolve(i + ".bin");
            if (i == SIZES.length) Files.copy(source, input);
            else Files.write(input, Arrays.copyOf(prefix, SIZES[i]));
            manifest.setProperty(i + ".sha256", sha256(input));
            manifest.setProperty(i + ".size", Long.toString(Files.size(input)));
        }
        Files.copy(inputs.resolve("1.bin"), inputs.resolve("中文🔐.bin"));
        Files.copy(inputs.resolve((SIZES.length - 1) + ".bin"), inputs.resolve("日本語.bin"));
        try (var out = Files.newOutputStream(root.resolve("manifest.properties"))) {
            manifest.store(out, null);
        }
        produce(root, root.resolve("ciphers"));
    }

    /**
     * 用本端生产 FAST 密文，记录每个输出的 SHA-256 以验证搬运完整性。
     * @param corpus 原始桌面语料与可信清单
     * @param output 尚不存在的本端密文目录
     * @throws Exception 加密或校验失败
     */
    public static void produce(Path corpus, Path output) throws Exception {
        Files.createDirectory(output);
        Properties expected = manifest(corpus), hashes = new Properties();
        hashes.setProperty("runtime", System.getProperty("java.runtime.version"));
        hashes.setProperty("os", System.getProperty("os.name"));
        hashes.setProperty("arch", System.getProperty("os.arch"));
        hashes.setProperty("provider", javax.crypto.Cipher.getInstance("AES/GCM/NoPadding").getProvider().getName());
        hashes.setProperty("suite", "2");
        hashes.setProperty("kdf", "Argon2id/65536/3/4");
        for (int i = 0; i < Integer.parseInt(expected.getProperty("count")); i++) {
            Path input = corpus.resolve("inputs/" + i + ".bin"),
                    cipher = output.resolve(i + ".fast");
            require(sha256(input).equals(expected.getProperty(i + ".sha256")), "输入搬运校验失败");
            var request = new EncryptRequest();
            request.setMode(EncryptionMode.FAST);
            request.setInputFile(input.toString());
            request.setOutputFile(cipher.toString());
            request.setPassword(PASSWORD);
            Encryptor.encrypt(request);
            hashes.setProperty(i + ".sha256", sha256(cipher));
        }
        Path legacy = output.resolve("legacy.ergou");
        var standard = new EncryptRequest();
        standard.setInputFile(corpus.resolve("inputs/日本語.bin").toString());
        standard.setOutputFile(legacy.toString()); standard.setPassword(READER_PASSWORD);
        standard.setRsCodecs(new hbnu.project.ergoutreecrypt.encoding.RsCodecs());
        standard.setArgon2MemoryKib(65536); standard.setArgon2Passes(3); standard.setArgon2Threads(4);
        Encryptor.encrypt(standard);
        hashes.setProperty("legacy.sha256", sha256(legacy));
        try (var out = Files.newOutputStream(output.resolve("cipher-hashes.properties"))) {
            hashes.store(out, null);
        }
        FastArchiveInteropSupport.produce(corpus, output);
    }

    /**
     * 独立完整认证不产生文件；默认解密必须逐字节等于桌面原始输入。
     * @param corpus 桌面原始语料
     * @param ciphers 指定生产端的密文
     * @param scratch 本次独占、已存在的临时目录
     * @throws Exception 认证、字节或搬运校验失败
     */
    public static void verify(Path corpus, Path ciphers, Path scratch) throws Exception {
        Properties expected = manifest(corpus), hashes = new Properties();
        try (var in = Files.newInputStream(ciphers.resolve("cipher-hashes.properties"))) {
            hashes.load(in);
        }
        for (int i = 0; i < Integer.parseInt(expected.getProperty("count")); i++) {
            Path cipher = ciphers.resolve(i + ".fast"),
                    plain = scratch.resolve("还原🔐-" + i + ".plain");
            require(sha256(cipher).equals(hashes.getProperty(i + ".sha256")), "密文搬运校验失败");
            require(VolumeFormatProbe.isFast(cipher), "FAST 标识丢失");
            var before = names(scratch);
            require(Verifier.verify(verification(cipher)), "完整认证失败");
            require(before.equals(names(scratch)), "独立认证产生了文件");
            Decryptor.decrypt(decryption(cipher, plain));
            require(
                    Files.size(plain) == Long.parseLong(expected.getProperty(i + ".size")),
                    "明文长度错误");
            require(sha256(plain).equals(expected.getProperty(i + ".sha256")), "明文摘要错误");
            require(equalBytes(corpus.resolve("inputs/" + i + ".bin"), plain), "逐字节比对失败");
            Files.delete(plain);
            require(before.equals(names(scratch)), "解密残留临时文件");
        }
        rejectAttacks(ciphers, scratch);
        commitRace(scratch);
        FastArchiveInteropSupport.verify(corpus, ciphers, scratch);
        mixedBatch(corpus, ciphers, scratch, hashes.getProperty("legacy.sha256"));
    }

    /**
     * @param corpus 原始输入
     * @param ciphers 本端产物
     * @param scratch 独占目录
     * @param hash 旧卷搬运摘要
     * @throws Exception 混合批量失败
     */
    private static void mixedBatch(Path corpus, Path ciphers, Path scratch, String hash) throws Exception {
        Path work = Files.createDirectory(scratch.resolve("mixed"));
        try {
            require(sha256(ciphers.resolve("legacy.ergou")).equals(hash), "旧卷搬运摘要不同");
            Path fast = work.resolve("fast.ergou"), legacy = work.resolve("legacy.ergou");
            Files.copy(ciphers.resolve((SIZES.length - 1) + ".fast"), fast);
            Files.copy(ciphers.resolve("legacy.ergou"), legacy);
            var auth = verification(legacy);
            auth.setRsCodecs(new hbnu.project.ergoutreecrypt.encoding.RsCodecs());
            require(Verifier.verify(auth), "混合旧卷认证失败");
            Path output = Files.createDirectory(work.resolve("output"));
            var opts = new FolderCrypt.DecryptOptions();
            opts.password = READER_PASSWORD;
            FolderCrypt.decryptFiles(List.of(legacy, fast), output, opts);
            require(opts.batchResult.succeededCount() == 2 && opts.batchResult.failedCount() == 0, "混合解密失败");
            require(equalBytes(corpus.resolve("inputs/日本語.bin"), output.resolve("legacy")), "旧卷还原不同");
            require(equalBytes(corpus.resolve("inputs/日本語.bin"), output.resolve("fast")), "FAST 还原不同");
        } finally {
            try (var walk = Files.walk(work)) {
                for (Path path : walk.sorted(java.util.Comparator.reverseOrder()).toList()) Files.delete(path);
            }
        }
    }

    /**
     * 在当前平台的真实提交实现中验证竞争窗口保护与私有权限。
     * @param scratch 独占临时目录
     * @throws Exception 用户文件被覆盖或私有权限不满足
     */
    private static void commitRace(Path scratch) throws Exception {
        Path target = scratch.resolve("竞争🔐.txt");
        try (var stage = FastOutput.create(target)) {
            if (Files.getFileAttributeView(
                            stage.path(), java.nio.file.attribute.PosixFileAttributeView.class)
                    != null) {
                require(
                        Files.getPosixFilePermissions(stage.path())
                                .equals(
                                        java.nio.file.attribute.PosixFilePermissions.fromString(
                                                "rw-------")),
                        "临时明文权限过宽");
            }
            Files.write(stage.path(), "本任务内容".getBytes(java.nio.charset.StandardCharsets.UTF_8));
            Files.write(target, "用户已有内容".getBytes(java.nio.charset.StandardCharsets.UTF_8));
            boolean rejected = false;
            try {
                stage.commit();
            } catch (java.nio.file.FileAlreadyExistsException expected) {
                rejected = true;
            }
            require(rejected, "提交竞争没有拒绝");
        }
        require(
                new String(Files.readAllBytes(target), java.nio.charset.StandardCharsets.UTF_8)
                        .equals("用户已有内容"),
                "用户文件被覆盖");
        Files.delete(target);
        require(names(scratch).isEmpty(), "提交竞争残留临时文件");
    }

    /**
     * 在当前读取端验证同一生产端的头部、分段、EOF 与跨文件攻击均拒绝。
     * @param ciphers 生产端产物
     * @param scratch 独占临时目录
     * @throws Exception 攻击被接受或留下输出
     */
    private static void rejectAttacks(Path ciphers, Path scratch) throws Exception {
        byte[] original = Files.readAllBytes(ciphers.resolve((SIZES.length - 1) + ".fast"));
        byte[] other = Files.readAllBytes(ciphers.resolve(SIZES.length + ".fast"));
        var attacks = new ArrayList<byte[]>();
        for (int at :
                new int[] {
                    8, 10, 14, 16, 36, 37, 40, 56, 127, 159,
                    12,
                    20,
                    24,
                    28,
                    32,
                    38,
                    88,
                    96,
                    128,
                    160,
                    200,
                    160 + (1 << 20) + 19,
                    original.length - 1
                }) {
            byte[] invalid = original.clone();
            invalid[at] ^= 1;
            attacks.add(invalid);
        }
        attacks.add(Arrays.copyOf(original, original.length - 1));
        attacks.add(Arrays.copyOf(original, original.length + 1));
        byte[] swapped = original.clone();
        System.arraycopy(original, 160 + (1 << 20), swapped, 160 + 2 * (1 << 20), 1 << 20);
        System.arraycopy(original, 160 + 2 * (1 << 20), swapped, 160 + (1 << 20), 1 << 20);
        attacks.add(swapped);
        byte[] duplicate = original.clone();
        System.arraycopy(original, 160 + (1 << 20), duplicate, 160 + 2 * (1 << 20), 1 << 20);
        attacks.add(duplicate);
        byte[] transplanted = original.clone();
        System.arraycopy(other, 160 + (1 << 20), transplanted, 160 + (1 << 20), 1 << 20);
        attacks.add(transplanted);
        for (int offset : new int[]{24, 28, 32}) {
            byte[] enormous = original.clone();
            java.nio.ByteBuffer.wrap(enormous).putInt(offset, Integer.MAX_VALUE);
            attacks.add(enormous);
        }
        for (int start : new int[]{160, 160 + (1 << 20), 160 + 2 * (1 << 20)}) {
            byte[] removed = new byte[original.length - (1 << 20)];
            System.arraycopy(original, 0, removed, 0, start);
            System.arraycopy(original, start + (1 << 20), removed, start,
                    original.length - start - (1 << 20));
            attacks.add(removed);
        }
        attacks.add(Arrays.copyOf(original, 160 + 3 * (1 << 20)));
        attacks.add(Arrays.copyOf(original, 160 + (1 << 20)));
        byte[] concatenated = Arrays.copyOf(original, original.length * 2);
        System.arraycopy(original, 0, concatenated, original.length, original.length);
        attacks.add(concatenated);
        byte[] randomTail = Arrays.copyOf(original, original.length + 31);
        Arrays.fill(randomTail, original.length, randomTail.length, (byte) 0x71);
        attacks.add(randomTail);
        byte[] wholePayload = original.clone();
        System.arraycopy(other, 160, wholePayload, 160, original.length - 160);
        attacks.add(wholePayload);
        byte[] legacy = Files.readAllBytes(ciphers.resolve("legacy.ergou"));
        int legacyHeader = hbnu.project.ergoutreecrypt.header.HeaderLayout.headerSize(0, "v2.16");
        byte[] fastHeadOldPayload = Arrays.copyOf(original, 160 + legacy.length - legacyHeader);
        System.arraycopy(legacy, legacyHeader, fastHeadOldPayload, 160, legacy.length - legacyHeader);
        attacks.add(fastHeadOldPayload);
        byte[] oldHeadFastPayload = Arrays.copyOf(legacy, legacyHeader + original.length - 160);
        System.arraycopy(original, 160, oldHeadFastPayload, legacyHeader, original.length - 160);
        attacks.add(oldHeadFastPayload);
        for (byte[] invalid : attacks) {
            Path input = scratch.resolve("attack.fast"), output = scratch.resolve("attack.plain");
            Files.write(input, invalid);
            var before = names(scratch);
            BruteForceGuard.getInstance().resetCounter(input.toString());
            boolean rejected = false;
            try {
                Verifier.verify(verification(input));
            } catch (CryptoException failure) {
                require(failure.kind() != ErrorKind.BRUTE_FORCE_LOCKED, "锁定不能代替认证拒绝");
                rejected = true;
            }
            require(rejected, "认证接受攻击");
            rejected = false;
            try {
                Decryptor.decrypt(decryption(input, output));
            } catch (CryptoException failure) {
                require(failure.kind() != ErrorKind.BRUTE_FORCE_LOCKED, "锁定不能代替解密拒绝");
                rejected = true;
            }
            require(rejected && !Files.exists(output), "攻击产生最终明文");
            require(before.equals(names(scratch)), "攻击残留临时文件");
            Files.delete(input);
        }
        Path forcedOutput = scratch.resolve("force.plain");
        var forced = decryption(ciphers.resolve("0.fast"), forcedOutput);
        forced.setForceDecrypt(true);
        boolean rejected = false;
        try { Decryptor.decrypt(forced); }
        catch (CryptoException expected) { rejected = expected.kind() == ErrorKind.UNSUPPORTED_FORMAT; }
        require(rejected && !Files.exists(forcedOutput), "FAST 允许跳过认证");
    }

    /**
     *
     * @param input 密文
     * @return 无高级选项的认证请求
     */
    private static VerifyRequest verification(Path input) {
        var request = new VerifyRequest();
        request.setInputFile(input.toString());
        request.setPassword(READER_PASSWORD);
        request.setRsCodecs(new hbnu.project.ergoutreecrypt.encoding.RsCodecs());
        return request;
    }

    /**
     *
     * @param input 密文
     * @param output 明文
     * @return 无模式字段的默认解密请求
     */
    private static DecryptRequest decryption(Path input, Path output) {
        var request = new DecryptRequest();
        request.setInputFile(input.toString());
        request.setOutputFile(output.toString());
        request.setPassword(READER_PASSWORD);
        request.setRsCodecs(new hbnu.project.ergoutreecrypt.encoding.RsCodecs());
        return request;
    }

    /**
     *
     * @param root 语料目录
     * @return 桌面原始清单
     * @throws Exception 读取失败
     */
    private static Properties manifest(Path root) throws Exception {
        var properties = new Properties();
        try (var in = Files.newInputStream(root.resolve("manifest.properties"))) {
            properties.load(in);
        }
        return properties;
    }

    /**
     *
     * @param path 普通文件
     * @return SHA-256 十六进制
     * @throws Exception 读取或摘要失败
     */
    public static String sha256(Path path) throws Exception {
        var digest = MessageDigest.getInstance("SHA-256");
        byte[] buffer = new byte[256 * 1024];
        try (var in = Files.newInputStream(path)) {
            for (int n; (n = in.read(buffer)) != -1; ) digest.update(buffer, 0, n);
        }
        return HexFormat.of().formatHex(digest.digest());
    }

    /**
     * 用双端均可用的有界流实现逐字节比较。
     * @param left 原始输入
     * @param right 还原文件
     * @return 所有字节及 EOF 是否相同
     * @throws Exception 读取失败
     */
    static boolean equalBytes(Path left, Path right) throws Exception {
        try (var a = Files.newInputStream(left);
                var b = Files.newInputStream(right)) {
            byte[] first = new byte[256 * 1024], second = new byte[first.length];
            for (; ; ) {
                int n = a.readNBytes(first, 0, first.length),
                        m = b.readNBytes(second, 0, second.length);
                if (n != m || !Arrays.equals(first, 0, n, second, 0, m)) return false;
                if (n == 0) return true;
            }
        }
    }

    /**
     *
     * @param path 目录
     * @return 排序后的名称快照
     * @throws Exception 读取失败
     */
    private static List<String> names(Path path) throws Exception {
        try (var entries = Files.list(path)) {
            return entries.map(p -> p.getFileName().toString()).sorted().toList();
        }
    }

    /**
     *
     * @param condition 必须成立的条件
     * @param message 失败原因
     */
    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
