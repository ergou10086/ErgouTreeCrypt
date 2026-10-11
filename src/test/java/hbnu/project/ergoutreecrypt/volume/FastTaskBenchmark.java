package hbnu.project.ergoutreecrypt.volume;

import hbnu.project.ergoutreecrypt.crypto.Argon2Kdf;
import hbnu.project.ergoutreecrypt.crypto.SecureZero;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

/** 完整生产入口基准：计入 KDF、认证、文件关闭和 force，保留三轮交替原始数据。 */
public final class FastTaskBenchmark {
    private static final String PASSWORD = "FAST-P4-production-密码🔐";
    /** 禁止实例化性能入口。 */
    private FastTaskBenchmark() {}

    /**
     * 解析输入与标准 KDF 参数并运行基准。
     * @param args 输入、新输出目录、标准 KDF 的 m/t/p
     * @throws Exception 加解密或比对失败
     */
    public static void main(String[] args) throws Exception {
        if (args.length != 5) throw new IllegalArgumentException("input new-directory memory passes lanes");
        run(Path.of(args[0]), Path.of(args[1]), Integer.parseInt(args[2]),
                Integer.parseInt(args[3]), Integer.parseInt(args[4]));
    }

    /**
     * 顺序预热并执行三轮完整生产任务。
     * @param input 真实输入
     * @param directory 新目录
     * @param memory 标准内存 KiB
     * @param passes 标准轮数
     * @param lanes 标准并行度
     * @throws Exception 验证失败
     */
    public static void run(Path input, Path directory, int memory, int passes, int lanes) throws Exception {
        Files.createDirectory(directory);
        String environment = "runtime=" + System.getProperty("java.runtime.version")
                + ",os=" + System.getProperty("os.name") + ",arch=" + System.getProperty("os.arch")
                + ",maxHeap=" + Runtime.getRuntime().maxMemory()
                + ",provider=" + javax.crypto.Cipher.getInstance("AES/GCM/NoPadding").getProvider().getName()
                + ",bytes=" + Files.size(input) + ",sha256=" + FastInteropSupport.sha256(input)
                + ",standardKdf=" + memory + "/" + passes + "/" + lanes
                + ",standardKdfNanos=" + kdf(memory, passes, lanes)
                + ",fastKdfNanos=" + kdf(65536, 3, 4)
                + ",cache=warm,force=true,includesKdf=true,compareOutsideTimer=true\n";
        Files.write(directory.resolve("environment.txt"), environment.getBytes(StandardCharsets.UTF_8));
        System.out.print(environment);
        try (var csv = Files.newBufferedWriter(directory.resolve("measurements.csv"))) {
            csv.write("round,profile,mode,operation,bytes,nanos,MB_per_s,MiB_per_s\n");
            for (int round = 0; round <= 3; round++) {
                for (String profile : new String[]{"DEFAULT", "SAME_KDF"}) {
                    EncryptionMode[] order = round % 2 == 0 ? new EncryptionMode[]{EncryptionMode.STANDARD, EncryptionMode.FAST}
                            : new EncryptionMode[]{EncryptionMode.FAST, EncryptionMode.STANDARD};
                    if (profile.equals("DEFAULT")) {
                        Path copied = directory.resolve("copy.bin");
                        long start = System.nanoTime();
                        Files.copy(input, copied);
                        force(copied);
                        long nanos = System.nanoTime() - start;
                        if (!FastInteropSupport.equalBytes(input, copied)) throw new AssertionError("复制不同");
                        Files.delete(copied);
                        if (round > 0) row(csv, round, profile, "COPY", "copy", Files.size(input), nanos);
                    }
                    for (EncryptionMode mode : order) {
                        Path cipher = directory.resolve("task.ergou"), plain = directory.resolve("restored.bin");
                        try {
                            var request = new EncryptRequest();
                            request.setMode(mode); request.setInputFile(input.toString());
                            request.setOutputFile(cipher.toString()); request.setPassword(PASSWORD);
                            request.setRsCodecs(new hbnu.project.ergoutreecrypt.encoding.RsCodecs());
                            if (mode == EncryptionMode.STANDARD) {
                                request.setArgon2MemoryKib(profile.equals("DEFAULT") ? memory : 65536);
                                request.setArgon2Passes(profile.equals("DEFAULT") ? passes : 3);
                                request.setArgon2Threads(profile.equals("DEFAULT") ? lanes : 4);
                            }
                            long start = System.nanoTime();
                            Encryptor.encrypt(request); force(cipher);
                            long encrypted = System.nanoTime() - start;
                            var auth = new VerifyRequest();
                            auth.setInputFile(cipher.toString()); auth.setPassword(PASSWORD);
                            auth.setRsCodecs(new hbnu.project.ergoutreecrypt.encoding.RsCodecs());
                            start = System.nanoTime();
                            if (!Verifier.verify(auth)) throw new AssertionError("认证失败");
                            long verified = System.nanoTime() - start;
                            var decrypt = new DecryptRequest();
                            decrypt.setInputFile(cipher.toString()); decrypt.setOutputFile(plain.toString());
                            decrypt.setPassword(PASSWORD);
                            decrypt.setRsCodecs(new hbnu.project.ergoutreecrypt.encoding.RsCodecs());
                            start = System.nanoTime();
                            Decryptor.decrypt(decrypt); force(plain);
                            long decrypted = System.nanoTime() - start;
                            if (!FastInteropSupport.equalBytes(input, plain)) throw new AssertionError("生产入口还原不同");
                            if (round > 0) {
                                row(csv, round, profile, mode.name(), "encrypt", Files.size(input), encrypted);
                                row(csv, round, profile, mode.name(), "verify", Files.size(input), verified);
                                row(csv, round, profile, mode.name(), "decrypt", Files.size(input), decrypted);
                            }
                        } finally { Files.deleteIfExists(cipher); Files.deleteIfExists(plain); }
                    }
                }
            }
        }
    }

    /**
     * 测量一次独立 Argon2id 派生，及时清除密码和密钥。
     * @param memory 内存 KiB
     * @param passes 轮数
     * @param lanes 并行度
     * @return 独立 KDF 耗时 ns
     * @throws Exception 派生失败
     */
    private static long kdf(int memory, int passes, int lanes) throws Exception {
        byte[] password = PASSWORD.getBytes(StandardCharsets.UTF_8);
        long start = System.nanoTime();
        try {
            byte[] key = Argon2Kdf.deriveKey(password, new byte[16], false, memory, passes, lanes);
            long nanos = System.nanoTime() - start;
            SecureZero.zero(key);
            return nanos;
        } finally { SecureZero.zero(password); }
    }

    /**
     * 将已经关闭的输出显式刷新到存储。
     * @param path 已关闭的输出
     * @throws Exception 持久化失败
     */
    private static void force(Path path) throws Exception {
        try (var channel = FileChannel.open(path, StandardOpenOption.WRITE)) { channel.force(true); }
    }

    /**
     * 同时记录原始纳秒与两种吞吐单位。
     * @param csv 原始记录
     * @param round 轮次
     * @param profile KDF 对照
     * @param mode 模式
     * @param operation 操作
     * @param bytes 输入大小
     * @param nanos 耗时
     * @throws Exception 记录失败
     */
    private static void row(java.io.Writer csv, int round, String profile, String mode, String operation, long bytes, long nanos) throws Exception {
        String value = String.format(Locale.ROOT, "%d,%s,%s,%s,%d,%d,%.3f,%.3f%n",
                round, profile, mode, operation, bytes, nanos, bytes / (nanos / 1e9) / 1e6,
                bytes / (nanos / 1e9) / (1 << 20));
        csv.write(value); csv.flush(); System.out.print(value);
    }
}
