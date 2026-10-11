package hbnu.project.ergoutreecrypt.volume;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.charset.StandardCharsets;

/** 跨 32 位长度的真实非稀疏文件专项；只保留摘要与计时。 */
public final class FastLargeFileSupport {
    /** 禁止实例化测试工具。 */
    private FastLargeFileSupport() {}

    /**
     * 从命令行启动超过 32 位长度的实文件专项。
     * @param args 真实源文件和新建工作目录
     * @throws Exception 专项验证失败
     */
    public static void main(String[] args) throws Exception { run(Path.of(args[0]), Path.of(args[1])); }

    /**
     * 实际写入大文件并验证加密、认证与完整还原。
     * @param source 可重复读取的真实非空文件
     * @param directory 新目录
     * @throws Exception 加密、认证或比对失败
     */
    public static void run(Path source, Path directory) throws Exception {
        if (Files.size(source) == 0) throw new IllegalArgumentException("需要非空真实源文件");
        Files.createDirectory(directory);
        Path input = directory.resolve("large.bin"), cipher = directory.resolve("large.ergou"),
                plain = directory.resolve("restored.bin");
        try {
            try (var output = Files.newOutputStream(input, StandardOpenOption.CREATE_NEW)) {
                long written = 0;
                byte[] buffer = new byte[1 << 20];
                while (written <= (1L << 32)) {
                    try (var stream = Files.newInputStream(source)) {
                        int count;
                        while ((count = stream.read(buffer)) >= 0) {
                            output.write(buffer, 0, count);
                            written += count;
                        }
                    }
                }
            }
            var request = new EncryptRequest();
            request.setMode(EncryptionMode.FAST); request.setPassword("大文件专项🔐");
            request.setInputFile(input.toString()); request.setOutputFile(cipher.toString());
            long start = System.nanoTime();
            Encryptor.encrypt(request);
            long encrypted = System.nanoTime() - start;
            var auth = new VerifyRequest();
            auth.setInputFile(cipher.toString()); auth.setPassword("大文件专项🔐");
            start = System.nanoTime();
            if (!Verifier.verify(auth)) throw new AssertionError("大文件认证失败");
            long verified = System.nanoTime() - start;
            var decrypt = new DecryptRequest();
            decrypt.setInputFile(cipher.toString()); decrypt.setOutputFile(plain.toString());
            decrypt.setPassword("大文件专项🔐");
            start = System.nanoTime();
            Decryptor.decrypt(decrypt);
            long decrypted = System.nanoTime() - start;
            if (!FastInteropSupport.equalBytes(input, plain)) throw new AssertionError("32位边界还原不同");
            String result = "bytes=" + Files.size(input) + "\nsha256=" + FastInteropSupport.sha256(input)
                    + "\nencryptNanos=" + encrypted + "\nverifyNanos=" + verified + "\ndecryptNanos=" + decrypted + "\n";
            Files.write(directory.resolve("large-result.txt"), result.getBytes(StandardCharsets.UTF_8));
            System.out.print(result);
        } finally {
            Files.deleteIfExists(input); Files.deleteIfExists(cipher); Files.deleteIfExists(plain);
        }
    }
}
