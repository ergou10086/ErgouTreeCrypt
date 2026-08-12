package hbnu.project.ergoutreecrypt.filestego;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import hbnu.project.ergoutreecrypt.filestego.api.FileStegoOptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Random;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * 文件隐写 PNG / ZIP 载体端到端往返测试（M1.1 / M1.2）。
 *
 * <p>覆盖 PNG（stEG chunk 与 IEND 追加两套不受限方案）与 ZIP（EOCD 末尾追加），
 * 并在 normal / paranoid / stealth 三种模式下验证 hide → extract 数据一致性、
 * 检测能力与容器可读性。
 *
 * @author ErgouTree
 */
class FileStegoRoundtripTest {

    private static final byte[] PASSWORD = "file-stego-test-pwd".getBytes(StandardCharsets.UTF_8);

    private final FileStegoCodec codec = new FileStegoCodec();

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }
    }

    // ---- 载体与秘密文件构造 ----

    /**
     * 生成一张小尺寸有效 PNG。
     *
     * @param dir  目录
     * @param name 文件名
     * @return PNG 路径
     * @throws Exception 写入失败
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
     * 生成一个含两个条目的有效 ZIP。
     *
     * @param dir  目录
     * @param name 文件名
     * @return ZIP 路径
     * @throws Exception 写入失败
     */
    private static Path createZip(final Path dir, final String name) throws Exception {
        Path p = dir.resolve(name);
        try (ZipOutputStream zos = new ZipOutputStream(Files.newOutputStream(p))) {
            zos.putNextEntry(new ZipEntry("readme.txt"));
            zos.write("hello zip carrier".getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();
            zos.putNextEntry(new ZipEntry("data/blob.bin"));
            zos.write(new byte[] {1, 2, 3, 4, 5, 6, 7, 8});
            zos.closeEntry();
        }
        return p;
    }

    /**
     * 生成指定大小的随机秘密文件。
     */
    private static Path createSecret(final Path dir, final String name, final int size)
            throws Exception {
        byte[] data = new byte[size];
        new SecureRandom().nextBytes(data);
        Path p = dir.resolve(name);
        Files.write(p, data);
        return p;
    }

    // ---- PNG ----

    @Test
    void pngChunkRoundtripNormal(@TempDir final Path dir) throws Exception {
        runPngRoundtrip(dir, true, false, false);
    }

    @Test
    void pngTrailerRoundtripNormal(@TempDir final Path dir) throws Exception {
        runPngRoundtrip(dir, false, false, false);
    }

    @Test
    void pngChunkRoundtripParanoid(@TempDir final Path dir) throws Exception {
        runPngRoundtrip(dir, true, true, false);
    }

    @Test
    void pngChunkRoundtripStealth(@TempDir final Path dir) throws Exception {
        runPngRoundtrip(dir, true, false, true);
    }

    /**
     * PNG 往返核心流程。
     *
     * @param dir         临时目录
     * @param preferChunk true 使用 stEG chunk（方案 A），false 使用 IEND 追加（方案 B）
     * @param paranoid    是否 paranoid 模式
     * @param stealth     是否隐蔽模式
     * @throws Exception 断言或 IO 失败
     */
    private void runPngRoundtrip(final Path dir, final boolean preferChunk,
                                 final boolean paranoid, final boolean stealth)
            throws Exception {
        Path carrier = createPng(dir, "carrier.png");
        // 秘密文件远大于载体，验证"容量无关"
        Path secret = createSecret(dir, "secret.bin", 64 * 1024);
        byte[] original = Files.readAllBytes(secret);
        Path stego = dir.resolve("stego.png");

        FileStegoOptions options = FileStegoOptions.builder()
                .preferChunk(preferChunk)
                .paranoid(paranoid)
                .stealth(stealth)
                .build();

        codec.hide(carrier, secret, stego, PASSWORD, options);

        assertTrue(Files.exists(stego), "隐写输出应存在");
        assertTrue(codec.isStegoFile(stego), "应能检测到隐写数据");
        // 容器仍可被 ImageIO 正常解码为图片
        assertTrue(ImageIO.read(stego.toFile()) != null, "隐写后 PNG 应仍可解码");

        Path outDir = dir.resolve("out");
        Path extracted = codec.extract(stego, outDir, PASSWORD);
        byte[] restored = Files.readAllBytes(extracted);

        assertEquals("secret.bin", extracted.getFileName().toString());
        assertArrayEquals(original, restored, "还原内容应与原文一致");
    }

    // ---- ZIP ----

    @Test
    void zipRoundtripNormal(@TempDir final Path dir) throws Exception {
        runZipRoundtrip(dir, false, false);
    }

    @Test
    void zipRoundtripParanoid(@TempDir final Path dir) throws Exception {
        runZipRoundtrip(dir, true, false);
    }

    @Test
    void zipRoundtripStealth(@TempDir final Path dir) throws Exception {
        runZipRoundtrip(dir, false, true);
    }

    /**
     * 测试超过 64KB 的大 Payload 场景——验证 findEocdOffset 全文件扫描修复。
     *
     * <p>修复前，findEocdOffset 仅扫描末尾 64KB，大 Payload 会导致 EOCD 超出扫描窗口。
     * <p>注意：大 Payload 会使标准 ZIP 工具无法解析（标准工具也限制 64KB 扫描窗口），
     * 因此此测试仅验证隐写数据提取的正确性。
     */
    @Test
    void zipRoundtripLargePayload(@TempDir final Path dir) throws Exception {
        runZipRoundtrip(dir, false, false, 128 * 1024, false);
    }

    /**
     * ZIP 往返核心流程。
     *
     * @param dir      临时目录
     * @param paranoid 是否 paranoid 模式
     * @param stealth  是否隐蔽模式
     * @throws Exception 断言或 IO 失败
     */
    private void runZipRoundtrip(final Path dir, final boolean paranoid, final boolean stealth)
            throws Exception {
        runZipRoundtrip(dir, paranoid, stealth, 40 * 1024, true);
    }
    /**
     * ZIP 往返核心流程（可指定秘密文件大小和是否检查标准 ZIP 可读性）。
     *
     * @param dir              临时目录
     * @param paranoid         是否 paranoid 模式
     * @param stealth          是否隐蔽模式
     * @param secretSize       秘密文件大小（字节）
     * @param checkZipReadable 是否检查隐写后 ZIP 仍可被标准工具读取
     * @throws Exception 断言或 IO 失败
     */
    private void runZipRoundtrip(final Path dir, final boolean paranoid, final boolean stealth,
                                 final int secretSize, final boolean checkZipReadable)
            throws Exception {
        Path carrier = createZip(dir, "carrier.zip");
        Path secret = createSecret(dir, "payload.dat", secretSize);
        byte[] original = Files.readAllBytes(secret);
        Path stego = dir.resolve("stego.zip");

        FileStegoOptions options = FileStegoOptions.builder()
                .paranoid(paranoid)
                .stealth(stealth)
                .build();

        codec.hide(carrier, secret, stego, PASSWORD, options);

        assertTrue(codec.isStegoFile(stego), "应能检测到 ZIP 隐写数据");
        // 隐写后的 ZIP 是否可被标准工具读取：大 Payload 下标准工具也限制 64KB 扫描窗口
        if (checkZipReadable) {
            assertTrue(zipStillReadable(stego), "隐写后 ZIP 应仍可正常解压");
        }

        Path outDir = dir.resolve("out");
        Path extracted = codec.extract(stego, outDir, PASSWORD);
        byte[] restored = Files.readAllBytes(extracted);

        assertEquals("payload.dat", extracted.getFileName().toString());
        assertArrayEquals(original, restored, "ZIP 还原内容应与原文一致");
    }

    /**
     * 校验 ZIP 隐写后原有条目仍可被标准解析器读取。
     */
    private static boolean zipStillReadable(final Path zip) throws Exception {
        try (var zf = new java.util.zip.ZipFile(zip.toFile())) {
            var entry = zf.getEntry("readme.txt");
            if (entry == null) {
                return false;
            }
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            try (var in = zf.getInputStream(entry)) {
                in.transferTo(bos);
            }
            return "hello zip carrier".equals(bos.toString(StandardCharsets.UTF_8));
        }
    }

    // ---- 负向：非隐写文件不应被误判 ----

    @Test
    void cleanCarrierNotDetected(@TempDir final Path dir) throws Exception {
        Path png = createPng(dir, "clean.png");
        Path zip = createZip(dir, "clean.zip");
        assertFalse(codec.isStegoFile(png), "干净 PNG 不应被判为隐写");
        assertFalse(codec.isStegoFile(zip), "干净 ZIP 不应被判为隐写");
    }
}
