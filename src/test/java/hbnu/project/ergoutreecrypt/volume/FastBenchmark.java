package hbnu.project.ergoutreecrypt.volume;

import hbnu.project.ergoutreecrypt.crypto.Argon2Kdf;
import hbnu.project.ergoutreecrypt.crypto.CipherSuite;
import hbnu.project.ergoutreecrypt.crypto.HkdfStream;
import hbnu.project.ergoutreecrypt.crypto.MacFactory;
import hbnu.project.ergoutreecrypt.crypto.SecureZero;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Locale;

/** 可复用 P0 文件流基准；计入文件打开、完整认证与关闭，不把 KDF 降档计作载荷加速。 */
public final class FastBenchmark {
    private static final byte[] AAD = "EGTC-P0-prototype".getBytes(StandardCharsets.US_ASCII);
    private FastBenchmark() { }

    /**
     * 运行一次预热及三轮交替测量，仅在新建的输出目录内产生文件。
     * @param args 真实输入文件、尚不存在的输出目录
     * @throws Exception I/O 或认证失败
     */
    public static void main(String[] args) throws Exception {
        if (args.length != 2) throw new IllegalArgumentException("用法：FastBenchmark 输入文件 新建输出目录");
        Path input = Path.of(args[0]).toRealPath();
        Path directory = Files.createDirectory(Path.of(args[1]).toAbsolutePath());
        System.out.println("runtime=" + System.getProperty("java.runtime.version")
                + ",vm=" + System.getProperty("java.vm.name") + ",os=" + System.getProperty("os.name")
                + ",arch=" + System.getProperty("os.arch") + ",maxHeap=" + Runtime.getRuntime().maxMemory()
                + ",provider=" + javax.crypto.Cipher.getInstance("AES/GCM/NoPadding").getProvider().getName());
        byte[] password = "P0-测试-password".getBytes(StandardCharsets.UTF_8);
        long kdfStart = System.nanoTime();
        byte[] key = Argon2Kdf.deriveKey(password, new byte[16], false, 65536, 3, 4);
        long kdfNanos = System.nanoTime() - kdfStart;
        SecureZero.zero(password);
        try (var csv = Files.newBufferedWriter(directory.resolve("measurements.csv"), StandardCharsets.UTF_8,
                StandardOpenOption.CREATE_NEW)) {
            csv.write("round,algorithm,operation,bytes,nanos,MB_per_s,MiB_per_s,kdf_nanos\n");
            for (int round = 0; round <= 3; round++) {
                String[] order = round % 2 == 0 ? new String[]{"COPY", "STANDARD", "AES128", "AES256", "JCA"}
                        : new String[]{"JCA", "AES256", "AES128", "STANDARD", "COPY"};
                for (String algorithm : order) {
                    Path cipher = directory.resolve("payload.bin"), restored = directory.resolve("restored.bin");
                    long start = System.nanoTime();
                    byte[] tag = transform(algorithm, true, input, cipher, key, null);
                    long encrypt = System.nanoTime() - start;
                    start = System.nanoTime();
                    transform(algorithm, false, cipher, restored, key, tag);
                    long decrypt = System.nanoTime() - start;
                    if (Files.mismatch(input, restored) != -1) throw new AssertionError("还原字节不同");
                    if (round != 0) {
                        for (int operation = 0; operation < 2; operation++) {
                            long nanos = operation == 0 ? encrypt : decrypt;
                            String row = String.format(Locale.ROOT,"%d,%s,%s,%d,%d,%.3f,%.3f,%d\n",
                                    round, algorithm, operation == 0 ? "encrypt" : "decrypt", Files.size(input), nanos,
                                    Files.size(input) / (nanos / 1e9) / 1e6,
                                    Files.size(input) / (nanos / 1e9) / (1 << 20), kdfNanos);
                            csv.write(row); csv.flush(); System.out.print(row);
                        }
                    }
                    Files.delete(restored); Files.delete(cipher);
                }
            }
        } finally { SecureZero.zero(key); }
    }

    /**
     * 处理完整文件流，标准模式使用现有套件并验证完整 MAC。
     * @param algorithm 算法或复制对照
     * @param encrypt 是否加密
     * @param source 输入
     * @param destination 输出
     * @param key 原型测试密钥
     * @param expectedTag 标准模式解密时的标签
     * @return 标准模式认证标签，其他模式为空
     * @throws Exception 处理失败
     */
    private static byte[] transform(String algorithm, boolean encrypt, Path source, Path destination,
                                    byte[] key, byte[] expectedTag) throws Exception {
        byte[] buffer = new byte[1 << 20];
        try (InputStream input = Files.newInputStream(source);
             OutputStream output = Files.newOutputStream(destination, StandardOpenOption.CREATE_NEW)) {
            if (algorithm.equals("COPY")) { input.transferTo(output); return null; }
            if (algorithm.equals("JCA")) {
                // 仅作 JCA 分段计算对照；测试固定密钥与计数器不属于生产协议。
                var cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
                var secret = new javax.crypto.spec.SecretKeySpec(Arrays.copyOf(key, 16), "AES");
                long index = 0;
                byte[] nonce = new byte[12];
                for (;;) {
                    byte[] segment = input.readNBytes((1 << 20) + (encrypt ? 0 : 16));
                    if (segment.length == 0) break;
                    java.nio.ByteBuffer.wrap(nonce).putLong(4, index++);
                    cipher.init(encrypt ? javax.crypto.Cipher.ENCRYPT_MODE : javax.crypto.Cipher.DECRYPT_MODE,
                            secret, new javax.crypto.spec.GCMParameterSpec(128, nonce));
                    output.write(cipher.doFinal(segment));
                    SecureZero.zero(segment);
                }
                return null;
            }
            if (algorithm.startsWith("AES")) {
                byte[] streamKey = Arrays.copyOf(key, algorithm.equals("AES128") ? 16 : 32);
                try {
                    var aead = FastPrototypeSupport.primitive(streamKey);
                    if (encrypt) {
                        try (OutputStream stream = aead.newEncryptingStream(output, AAD)) { copy(input, stream, buffer); }
                    } else {
                        try (InputStream stream = aead.newDecryptingStream(input, AAD)) { copy(stream, output, buffer); }
                    }
                    return null;
                } finally { SecureZero.zero(streamKey); }
            }
            var hkdf = new HkdfStream(key, new byte[32]);
            try (var suite = new CipherSuite(key, new byte[24], null, null,
                    MacFactory.create(new byte[32], false), hkdf, false)) {
                byte[] result = new byte[buffer.length];
                try {
                    for (int n; (n = input.read(buffer)) != -1;) {
                        if (encrypt) suite.encrypt(result, buffer, n); else suite.decrypt(result, buffer, n);
                        output.write(result, 0, n);
                    }
                    byte[] tag = suite.sum();
                    if (!encrypt && !MessageDigest.isEqual(expectedTag, tag)) throw new AssertionError("标准模式 MAC 失败");
                    return tag;
                } finally { SecureZero.zero(result); }
            }
        } finally { SecureZero.zero(buffer); }
    }

    /**
     * 使用可复用缓冲读取到真实 EOF。
     * @param input 输入
     * @param output 输出
     * @param buffer 缓冲
     * @throws java.io.IOException I/O 或认证失败
     */
    private static void copy(InputStream input, OutputStream output, byte[] buffer) throws java.io.IOException {
        for (int n; (n = input.read(buffer)) != -1;) output.write(buffer, 0, n);
    }
}
