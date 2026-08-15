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
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

/**
 * 文件隐写进度回调测试。
 *
 * <p>验证 hide/extract 的 {@code ProgressListener} 在流式处理期间按实际已处理
 * 字节数持续回调，而非仅在开始与结束时各回调一次（旧缺陷：0% 长时间停滞、
 * 完成后瞬间跳到 100%）。断言回调序列：
 * <ul>
 *   <li>单调不减且始终落在 [0.0, 1.0] 区间</li>
 *   <li>存在严格介于 0 与 1 的中间进度</li>
 *   <li>最终精确到达 1.0</li>
 * </ul>
 *
 * @author ErgouTree
 * @since 2026/8/14
 */
class FileStegoProgressTest {

    private static final byte[] PASSWORD = "progress-test-pwd".getBytes(StandardCharsets.UTF_8);

    /** 秘密文件大小（8 MiB，超过流式分块大小以保证多轮进度回调）。 */
    private static final int SECRET_SIZE_MIB = 8;

    private final FileStegoCodec codec = new FileStegoCodec();

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }
    }

    // ---- 载体与秘密文件构造 ----

    /**
     * 生成一张小尺寸有效 PNG 载体（流式嵌入/提取路径）。
     *
     * @param dir 目录
     * @return PNG 路径
     * @throws Exception 写入失败
     */
    private static Path createPng(final Path dir) throws Exception {
        BufferedImage img = new BufferedImage(64, 64, BufferedImage.TYPE_INT_RGB);
        Random r = new Random(7);
        for (int y = 0; y < 64; y++) {
            for (int x = 0; x < 64; x++) {
                img.setRGB(x, y, r.nextInt());
            }
        }
        Path p = dir.resolve("carrier.png");
        ImageIO.write(img, "PNG", p.toFile());
        return p;
    }

    /**
     * 生成指定大小的随机字节秘密文件。
     *
     * @param dir 目录
     * @return 秘密文件路径
     * @throws Exception 写入失败
     */
    private static Path createSecret(final Path dir) throws Exception {
        Path p = dir.resolve("secret.bin");
        byte[] chunk = new byte[1 << 20];
        SecureRandom sr = new SecureRandom();
        try (java.io.OutputStream out = Files.newOutputStream(p)) {
            for (int i = 0; i < SECRET_SIZE_MIB; i++) {
                sr.nextBytes(chunk);
                out.write(chunk);
            }
        }
        return p;
    }

    // ---- 断言 ----

    /**
     * 断言进度序列单调不减、含中间值且终点精确为 1.0。
     *
     * @param fractions 监听器收到的全部进度回调（按时间顺序）
     */
    private static void assertSmoothProgress(final List<Double> fractions) {
        assertFalse(fractions.isEmpty(), "应至少产生一次进度回调");
        boolean hasIntermediate = false;
        double prev = 0.0;
        for (double f : fractions) {
            assertTrue(f >= prev, "进度不应回退: " + f + " < " + prev);
            assertTrue(f >= 0.0 && f <= 1.0, "进度越界: " + f);
            if (f > 0.0 && f < 1.0) {
                hasIntermediate = true;
            }
            prev = f;
        }
        assertEquals(1.0, fractions.get(fractions.size() - 1), 1e-9, "最终进度应为 1.0");
        assertTrue(hasIntermediate, "应存在 0 与 1 之间的中间进度（而非 0% 直接跳到 100%）");
    }

    // ---- 测试 ----

    @Test
    void hideReportsSmoothProgress(@TempDir final Path dir) throws Exception {
        Path carrier = createPng(dir);
        Path secret = createSecret(dir);
        Path output = dir.resolve("out.png");

        List<Double> fractions = new ArrayList<>();
        codec.hide(carrier, secret, output, PASSWORD, FileStegoOptions.defaults(),
                fractions::add);

        assertSmoothProgress(fractions);
        assertTrue(Files.size(output) > 0, "输出文件不应为空");
    }

    @Test
    void extractReportsSmoothProgress(@TempDir final Path dir) throws Exception {
        Path carrier = createPng(dir);
        Path secret = createSecret(dir);
        Path output = dir.resolve("out.png");

        codec.hide(carrier, secret, output, PASSWORD, FileStegoOptions.defaults(), null);

        Path outDir = dir.resolve("extracted");
        List<Double> fractions = new ArrayList<>();
        Path extracted = codec.extract(output, outDir, PASSWORD,
                FileStegoOptions.defaults(), fractions::add);

        assertSmoothProgress(fractions);
        assertArrayEquals(Files.readAllBytes(secret), Files.readAllBytes(extracted),
                "提取内容应与原始秘密文件一致");
    }
}
