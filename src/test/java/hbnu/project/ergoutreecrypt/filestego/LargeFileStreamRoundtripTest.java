package hbnu.project.ergoutreecrypt.filestego;

import hbnu.project.ergoutreecrypt.filestego.api.Argon2Params;
import hbnu.project.ergoutreecrypt.filestego.api.FileStegoOptions;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.security.Security;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 大载荷流式端到端往返测试（32 MiB 级）。
 *
 * <p>验证流式链路（encodeToFile → embedFromFile → extractFullToFile →
 * decodeToFile）在 paranoid + 完整性校验 + Argon2 覆写下对大文件的
 * 正确性与字节一致性。载荷超过适配器"读入内存"的舒适区，
 * 但远小于测试堆限制，作为 1GB 场景的缩小版回归锚点。
 *
 * @author ErgouTree
 * @since 2026/8/14
 */
class LargeFileStreamRoundtripTest {

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }
    }

    /** 低内存 Argon2 覆写（64 MiB / 2 passes / 2 threads），加速测试。 */
    private static final Argon2Params LOW_MEM = new Argon2Params(64 * 1024, 2, 2);

    private final FileStegoCodec codec = new FileStegoCodec();
    private final byte[] password = "large-stream".getBytes(java.nio.charset.StandardCharsets.UTF_8);

    /**
     * ZIP 载体 + 32 MiB 载荷 + paranoid + 完整性校验：流式往返。
     */
    @Test
    void zipLargePayloadParanoidRoundtrip(@TempDir final Path dir) throws Exception {
        Path carrier = createZip(dir, "carrier.zip");
        Path secret = dir.resolve("large.bin");
        createSecretFile(secret, 32 * 1024 * 1024 + 333);

        Path stego = dir.resolve("stego.zip");
        FileStegoOptions options = FileStegoOptions.builder()
                .paranoid(true)
                .storeIntegrity(true)
                .argon2Params(LOW_MEM)
                .build();

        codec.hide(carrier, secret, stego, password, options);
        assertTrue(Files.size(stego) > 32 * 1024 * 1024L, "隐写输出应大于载荷");

        Path extracted = codec.extract(stego, dir.resolve("out"), password);
        assertFileEquals(secret, extracted);
    }

    /**
     * PNG chunk 载体 + 16 MiB 载荷 + 完整性校验：流式往返。
     */
    @Test
    void pngChunkLargePayloadRoundtrip(@TempDir final Path dir) throws Exception {
        Path carrier = createPng(dir, "carrier.png");
        Path secret = dir.resolve("large.bin");
        createSecretFile(secret, 16 * 1024 * 1024 + 555);

        Path stego = dir.resolve("stego.png");
        FileStegoOptions options = FileStegoOptions.builder()
                .storeIntegrity(true)
                .argon2Params(LOW_MEM)
                .build();

        codec.hide(carrier, secret, stego, password, options);

        Path extracted = codec.extract(stego, dir.resolve("out"), password);
        assertFileEquals(secret, extracted);
    }

    /**
     * 生成一个大文件（确定性内容，占用真实磁盘空间）。
     */
    private static void createSecretFile(final Path path, final int size) throws Exception {
        SecureRandom rnd = new SecureRandom();
        byte[] buf = new byte[1 << 20];
        try (java.io.OutputStream out = Files.newOutputStream(path)) {
            int remaining = size;
            while (remaining > 0) {
                rnd.nextBytes(buf);
                int n = Math.min(remaining, buf.length);
                out.write(buf, 0, n);
                remaining -= n;
            }
        }
    }

    /**
     * 分块比对两个文件内容一致（避免大文件整体读入比对缓冲）。
     */
    private static void assertFileEquals(final Path expected, final Path actual) throws Exception {
        assertEqualsSize(expected, actual);
        try (java.io.InputStream a = Files.newInputStream(expected);
             java.io.InputStream b = Files.newInputStream(actual)) {
            byte[] bufA = new byte[1 << 20];
            byte[] bufB = new byte[1 << 20];
            int n;
            while ((n = a.read(bufA)) > 0) {
                int off = 0;
                while (off < n) {
                    int m = b.read(bufB, off, n - off);
                    if (m < 0) {
                        throw new AssertionError("文件提前结束");
                    }
                    off += m;
                }
                assertArrayEquals(bufA, bufB, "提取内容应与原文一致");
            }
        }
    }

    /**
     * 断言两个文件大小一致。
     */
    private static void assertEqualsSize(final Path expected, final Path actual) throws Exception {
        assertTrue(Files.size(expected) == Files.size(actual),
                "文件大小应一致: " + Files.size(expected) + " vs " + Files.size(actual));
    }

    /**
     * 生成一个含单条目的有效 ZIP。
     */
    private static Path createZip(final Path dir, final String name) throws Exception {
        Path p = dir.resolve(name);
        try (ZipOutputStream zos = new ZipOutputStream(Files.newOutputStream(p))) {
            zos.putNextEntry(new ZipEntry("readme.txt"));
            zos.write("hello".getBytes(java.nio.charset.StandardCharsets.UTF_8));
            zos.closeEntry();
        }
        return p;
    }

    /**
     * 生成一张小尺寸有效 PNG。
     */
    private static Path createPng(final Path dir, final String name) throws Exception {
        java.awt.image.BufferedImage img =
                new java.awt.image.BufferedImage(32, 32, java.awt.image.BufferedImage.TYPE_INT_RGB);
        Path p = dir.resolve(name);
        javax.imageio.ImageIO.write(img, "PNG", p.toFile());
        return p;
    }
}
