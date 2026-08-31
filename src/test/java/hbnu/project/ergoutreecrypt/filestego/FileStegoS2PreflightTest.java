package hbnu.project.ergoutreecrypt.filestego;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import hbnu.project.ergoutreecrypt.compress.ZstdCompressor;
import hbnu.project.ergoutreecrypt.filestego.api.Argon2Params;
import hbnu.project.ergoutreecrypt.filestego.api.FileStegoOptions;
import hbnu.project.ergoutreecrypt.filestego.api.StegoPreflight;
import hbnu.project.ergoutreecrypt.filestego.codec.PayloadCodec;
import hbnu.project.ergoutreecrypt.settings.Argon2DesktopMode;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Random;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * 文件隐写 S2 预检测试（Phase S2 落地验证）。
 *
 * <p>验证 {@link FileStegoCodec#preflight} 的只读探针：
 * <ol>
 *   <li>均衡 / 强档隐写文件：预检读到对应 Argon2 内存参数；</li>
 *   <li>旧格式（无覆写）隐写文件：预检 {@code argon2MemoryKib == null}（回落 1 GiB）；</li>
 *   <li>「加密前压缩」隐写文件：预检 {@code compressed == true}；</li>
 *   <li>普通载体（非隐写）：预检返回 {@link StegoPreflight#UNKNOWN}。</li>
 * </ol>
 *
 * <p>另验证桌面端压缩往返不劣化：桌面端 zstd-jni native 可用时，「加密前压缩」
 * 文件仍可正常提取；移动端（native 不可用）会经 {@code PayloadCodec} 的兜底抛出
 * 友好错误，见移动端侧的 {@code DesktopStegoInteropTest}。
 *
 * @author ErgouTree
 * @since 2026/8/31
 */
class FileStegoS2PreflightTest {

    private static final byte[] PASSWORD = "ergou-stego-s2".getBytes(StandardCharsets.UTF_8);

    private final FileStegoCodec codec = new FileStegoCodec();

    @BeforeAll
    static void setup() {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }
    }

    // ==================== 预检：Argon2 档位 ====================

    /**
     * 均衡 256 MiB 档隐写文件：预检读到 256 MiB 内存参数，且非压缩。
     *
     * @param dir 临时目录
     * @throws Exception 隐写失败
     */
    @Test
    void preflight_readsBalancedTier(@TempDir Path dir) throws Exception {
        Path carrier = createPng(dir, "carrier.png");
        Path secret = createSecret(dir, "s.bin", 16 * 1024);
        Path stego = dir.resolve("stego.png");
        codec.hide(carrier, secret, stego, PASSWORD, options(Argon2DesktopMode.BALANCED), null);

        StegoPreflight p = codec.preflight(stego, PASSWORD);
        assertNotNull(p, "预检应成功");
        assertEquals(256 << 10, p.argon2MemoryKib(), "均衡档内存参数");
        assertFalse(p.compressed(), "均衡档未压缩");
    }

    /**
     * 强 1 GiB 档隐写文件：预检读到 1 GiB 内存参数（移动端据此提示「较慢」）。
     *
     * @param dir 临时目录
     * @throws Exception 隐写失败
     */
    @Test
    void preflight_readsStrongTier(@TempDir Path dir) throws Exception {
        Path carrier = createZip(dir, "carrier.zip");
        Path secret = createSecret(dir, "s.bin", 8 * 1024);
        Path stego = dir.resolve("stego.zip");
        codec.hide(carrier, secret, stego, PASSWORD, options(Argon2DesktopMode.STRONG), null);

        StegoPreflight p = codec.preflight(stego, PASSWORD);
        assertEquals(1 << 20, p.argon2MemoryKib(), "强档内存参数");
    }

    /**
     * 旧格式（无覆写）隐写文件：预检 {@code argon2MemoryKib == null}（回落默认 1 GiB）。
     *
     * @param dir 临时目录
     * @throws Exception 隐写失败
     */
    @Test
    void preflight_oldFileReturnsNullMemory(@TempDir Path dir) throws Exception {
        Path carrier = createZip(dir, "carrier.zip");
        Path secret = createSecret(dir, "s.bin", 8 * 1024);
        Path stego = dir.resolve("stego.zip");
        codec.hide(carrier, secret, stego, PASSWORD,
                FileStegoOptions.builder().storeIntegrity(true).build(), null);

        StegoPreflight p = codec.preflight(stego, PASSWORD);
        assertNotNull(p, "旧格式仍应能预检到元数据");
        assertNull(p.argon2MemoryKib(), "旧格式无参数覆写（回落 1 GiB）");
    }

    // ==================== 预检：压缩标志 ====================

    /**
     * 「加密前压缩」隐写文件：预检读到 {@code compressed == true}。
     *
     * @param dir 临时目录
     * @throws Exception 隐写失败
     */
    @Test
    void preflight_detectsCompressedFlag(@TempDir Path dir) throws Exception {
        Path carrier = createZip(dir, "carrier.zip");
        Path secret = createSecret(dir, "s.bin", 32 * 1024);
        Path stego = dir.resolve("stego.zip");
        codec.hide(carrier, secret, stego, PASSWORD,
                FileStegoOptions.builder()
                        .storeIntegrity(true)
                        .compressed(true)
                        .argon2Params(new Argon2Params(64 << 10, 2, 2))
                        .build(),
                null);

        StegoPreflight p = codec.preflight(stego, PASSWORD);
        assertNotNull(p, "压缩文件应能预检到元数据");
        assertTrue(p.compressed(), "压缩文件应被识别为 compressed");
    }

    /**
     * 普通 PNG（非隐写）：预检返回 {@link StegoPreflight#UNKNOWN}。
     *
     * @param dir 临时目录
     * @throws Exception 生成 PNG 失败
     */
    @Test
    void preflight_plainCarrierReturnsUnknown(@TempDir Path dir) throws Exception {
        Path plainPng = createPng(dir, "plain.png");
        Path plainZip = createZip(dir, "plain.zip");

        assertEquals(StegoPreflight.UNKNOWN, codec.preflight(plainPng, PASSWORD),
                "普通 PNG 应返回 UNKNOWN");
        assertEquals(StegoPreflight.UNKNOWN, codec.preflight(plainZip, PASSWORD),
                "普通 ZIP 应返回 UNKNOWN");
    }

    /**
     * {@link PayloadCodec#isCompressedFlag} 正确解析 Payload 头 FLAGS bit1。
     */
    @Test
    void isCompressedFlagParsing() {
        ByteBuffer compressed = ByteBuffer.allocate(10).order(ByteOrder.BIG_ENDIAN);
        compressed.put(new byte[] {0x53, 0x54, 0x47, 0x32}); // "STG2"
        compressed.putShort((short) 1);                       // version
        compressed.putShort((short) 0x0002);                  // FLAG_COMPRESSED
        compressed.putShort((short) 0);                       // meta length
        assertTrue(PayloadCodec.isCompressedFlag(compressed.array()), "bit1 应判定为压缩");

        ByteBuffer plain = ByteBuffer.allocate(10).order(ByteOrder.BIG_ENDIAN);
        plain.put(new byte[] {0x53, 0x54, 0x47, 0x32});
        plain.putShort((short) 1);
        plain.putShort((short) 0x0000);
        plain.putShort((short) 0);
        assertFalse(PayloadCodec.isCompressedFlag(plain.array()), "无 bit1 不应判定为压缩");

        assertFalse(PayloadCodec.isCompressedFlag(new byte[] {0, 1, 2, 3, 4, 5, 6, 7, 8, 9}),
                "魔数不匹配应返回 false");
    }

    // ==================== 桌面端压缩往返不劣化 ====================

    /**
     * 桌面端 zstd-jni native 可用：压缩文件可正常往返（fallback 不误伤桌面端）。
     *
     * @param dir 临时目录
     * @throws Exception 隐写或提取失败
     */
    @Test
    void compressedRoundtripWorksOnDesktop(@TempDir Path dir) throws Exception {
        assumeTrue(ZstdCompressor.isAvailable(), "桌面端应可用 zstd native");
        Path carrier = createZip(dir, "carrier.zip");
        Path secret = createSecret(dir, "s.bin", 64 * 1024);
        Path stego = dir.resolve("stego.zip");
        codec.hide(carrier, secret, stego, PASSWORD,
                FileStegoOptions.builder()
                        .storeIntegrity(true)
                        .compressed(true)
                        .argon2Params(new Argon2Params(64 << 10, 2, 2))
                        .build(),
                null);

        Path out = Files.createDirectories(dir.resolve("out"));
        Path extracted = codec.extract(stego, out, PASSWORD, FileStegoOptions.builder().build(), null);
        assertEquals(-1L, Files.mismatch(secret, extracted), "桌面端压缩往返应逐字节一致");
    }

    // ==================== 私有辅助 ====================

    /**
     * 构建指定档位的隐写选项（含完整性校验，非压缩）。
     *
     * @param tier 桌面 KDF 档位
     * @return 隐写选项
     */
    private static FileStegoOptions options(final Argon2DesktopMode tier) {
        return FileStegoOptions.builder()
                .storeIntegrity(true)
                .argon2Params(new Argon2Params(
                        tier.getMemoryKib(), tier.getPasses(), tier.getThreads()))
                .build();
    }

    /**
     * 生成一张小尺寸有效 PNG 作为载体。
     *
     * @param dir  目录
     * @param name 文件名
     * @return PNG 路径
     * @throws Exception 写入失败
     */
    private static Path createPng(final Path dir, final String name) throws Exception {
        BufferedImage img = new BufferedImage(48, 48, BufferedImage.TYPE_INT_RGB);
        Random r = new Random(7);
        for (int y = 0; y < 48; y++) {
            for (int x = 0; x < 48; x++) {
                img.setRGB(x, y, r.nextInt());
            }
        }
        Path p = dir.resolve(name);
        ImageIO.write(img, "PNG", p.toFile());
        return p;
    }

    /**
     * 生成一个含两个条目的有效 ZIP 作为载体。
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
            zos.write("ergou stego s2 carrier".getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();
            zos.putNextEntry(new ZipEntry("data/blob.bin"));
            zos.write(new byte[] {4, 5, 6});
            zos.closeEntry();
        }
        return p;
    }

    /**
     * 生成指定大小的随机秘密文件。
     *
     * @param dir  目录
     * @param name 文件名
     * @param size 字节数
     * @return 秘密文件路径
     * @throws Exception 写入失败
     */
    private static Path createSecret(final Path dir, final String name, final int size)
            throws Exception {
        byte[] data = new byte[size];
        new SecureRandom().nextBytes(data);
        Path p = dir.resolve(name);
        Files.write(p, data);
        return p;
    }
}
