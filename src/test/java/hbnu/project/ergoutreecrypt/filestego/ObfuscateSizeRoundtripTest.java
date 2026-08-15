package hbnu.project.ergoutreecrypt.filestego;

import hbnu.project.ergoutreecrypt.filestego.api.Argon2Params;
import hbnu.project.ergoutreecrypt.filestego.api.FileStegoOptions;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Security;
import java.util.Random;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 文件大小混淆（obfuscateSize）与提取的回归测试。
 *
 * <p>obfuscateSize 会在隐写文件末尾追加随机填充字节，末尾追加型载体
 * （ZIP、PNG-trailer）的提取必须按 {@code meta.payloadSize()} 精确截断，
 * 否则 Payload MAC 校验会把填充字节算入密文而失败。本测试锚定该修复。
 *
 * @author ErgouTree
 * @since 2026/8/14
 */
class ObfuscateSizeRoundtripTest {

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }
    }

    /** 低内存 Argon2 覆写，加速测试。 */
    private static final Argon2Params LOW_MEM = new Argon2Params(64 * 1024, 2, 2);

    private final FileStegoCodec codec = new FileStegoCodec();
    private final byte[] password = "obf-test".getBytes(java.nio.charset.StandardCharsets.UTF_8);

    /**
     * ZIP 载体 + obfuscateSize：提取必须精确截断并还原原文。
     */
    @Test
    void zipWithObfuscateSizeRoundtrip(@TempDir final Path dir) throws Exception {
        Path carrier = createZip(dir, "carrier.zip");
        byte[] secret = randomBytes(64 * 1024);
        Path secretFile = dir.resolve("secret.bin");
        Files.write(secretFile, secret);
        Path stego = dir.resolve("stego.zip");

        long expectedSize = Files.size(carrier) + 200 * 1024;
        FileStegoOptions options = FileStegoOptions.builder()
                .obfuscateSize(true)
                .targetSizeBytes(expectedSize)
                .argon2Params(LOW_MEM)
                .build();

        codec.hide(carrier, secretFile, stego, password, options);

        assertTrue(Files.size(stego) == expectedSize, "混淆后大小应达到目标");
        Path extracted = codec.extract(stego, dir.resolve("out"), password);
        assertArrayEquals(secret, Files.readAllBytes(extracted),
                "obfuscateSize 下 ZIP 提取内容应与原文一致");
    }

    /**
     * PNG trailer（preferChunk=false）+ obfuscateSize：提取必须精确截断并还原原文。
     */
    @Test
    void pngTrailerWithObfuscateSizeRoundtrip(@TempDir final Path dir) throws Exception {
        Path carrier = createPng(dir, "carrier.png");
        byte[] secret = randomBytes(32 * 1024);
        Path secretFile = dir.resolve("secret.bin");
        Files.write(secretFile, secret);
        Path stego = dir.resolve("stego.png");

        long expectedSize = Files.size(carrier) + 128 * 1024;
        FileStegoOptions options = FileStegoOptions.builder()
                .preferChunk(false)
                .obfuscateSize(true)
                .targetSizeBytes(expectedSize)
                .argon2Params(LOW_MEM)
                .build();

        codec.hide(carrier, secretFile, stego, password, options);

        assertTrue(Files.size(stego) == expectedSize, "混淆后大小应达到目标");
        Path extracted = codec.extract(stego, dir.resolve("out"), password);
        assertArrayEquals(secret, Files.readAllBytes(extracted),
                "obfuscateSize 下 PNG trailer 提取内容应与原文一致");
    }

    /**
     * 生成一张小尺寸有效 PNG。
     */
    private static Path createPng(final Path dir, final String name) throws Exception {
        BufferedImage img = new BufferedImage(32, 32, BufferedImage.TYPE_INT_RGB);
        Random r = new Random(42);
        for (int y = 0; y < 32; y++) {
            for (int x = 0; x < 32; x++) {
                img.setRGB(x, y, r.nextInt());
            }
        }
        Path p = dir.resolve(name);
        ImageIO.write(img, "PNG", p.toFile());
        return p;
    }

    /**
     * 生成一个含单条目的有效 ZIP。
     */
    private static Path createZip(final Path dir, final String name) throws Exception {
        Path p = dir.resolve(name);
        try (ZipOutputStream zos = new ZipOutputStream(Files.newOutputStream(p))) {
            zos.putNextEntry(new ZipEntry("readme.txt"));
            zos.write("hello zip carrier".getBytes(java.nio.charset.StandardCharsets.UTF_8));
            zos.closeEntry();
        }
        return p;
    }

    /**
     * 生成确定性伪随机字节。
     */
    private static byte[] randomBytes(final int size) {
        byte[] b = new byte[size];
        for (int i = 0; i < size; i++) {
            b[i] = (byte) ((i * 31 + 7) & 0xFF);
        }
        return b;
    }
}
