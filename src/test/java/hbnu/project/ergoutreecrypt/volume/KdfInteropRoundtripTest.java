package hbnu.project.ergoutreecrypt.volume;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import hbnu.project.ergoutreecrypt.crypto.Argon2Kdf;
import hbnu.project.ergoutreecrypt.encoding.RsCodecs;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * 桌面端与移动端真实加密文件的双向互通 round-trip 测试（Phase 0.3）。
 *
 * <p>用真实加密文件（{@code temp/test}）与真实密码（{@code ergou}）验证解密产物
 * 与原始明文逐字节一致。本测试集内的 {@code *.ergou} 均为<b>通用文件（卷）加密</b>
 * 产物（卷头版本 v2.14/v2.15/v2.16），故统一走 {@link Decryptor} 解密：
 * <ul>
 *   <li>移动端加密 → 桌面端解密（v2.15，记录低内存档位）；</li>
 *   <li>桌面端加密 → 桌面端解密（v2.16 加密前压缩 + 1 GiB 默认档；v2.14 1 GiB 默认档）。</li>
 * </ul>
 *
 * <p>解密产物写入 {@code temp/test/test_output}。真实文件缺失时自动跳过（CI 不携带）。
 * 通过打印当前可用堆与 1 GiB 是否可堆内派生，区分「桌面端堆内路径」与「模拟移动端
 * 离堆路径」——配合小堆 JVM 参数（{@code -Xmx512m}）即可模拟移动端解密桌面 1 GiB 文件。
 *
 * @author ErgouTree
 */
class KdfInteropRoundtripTest {

    private static final String PASSWORD = "ergou";
    private static final RsCodecs RS = new RsCodecs();
    private static final Path ROOT = Path.of("temp/test");
    private static final Path OUT = Path.of("temp/test/test_output");

    /**
     * 移动端加密（v2.15）→ 桌面端解密，验证移动 → 桌面方向互通。
     */
    @Test
    void mobileToDesktop_volume() throws Exception {
        Path enc = ROOT.resolve("andorid/原内容.zip.ergou");
        Path original = ROOT.resolve("原内容/原内容.zip");
        assumeTrue(Files.exists(enc) && Files.exists(original), "缺少移动端真实文件");
        Path out = decryptVolume(enc, OUT.resolve("andorid_原内容.zip"));
        assertByteIdentical(original, out);
    }

    /**
     * 桌面端加密（v2.16，加密前压缩 + 1 GiB）→ 桌面端解密。
     */
    @Test
    void desktopVolume_zip_compressed() throws Exception {
        Path enc = ROOT.resolve("desktop/原内容.zip.ergou");
        Path original = ROOT.resolve("原内容/原内容.zip");
        assumeTrue(Files.exists(enc) && Files.exists(original), "缺少桌面端真实文件");
        Path out = decryptVolume(enc, OUT.resolve("desktop_原内容.zip"));
        assertByteIdentical(original, out);
    }

    /**
     * 桌面端加密（v2.14，MP4 明文）→ 桌面端解密。
     */
    @Test
    void desktopVolume_mp4() throws Exception {
        Path enc = ROOT.resolve("desktop/ミエル 20260505.mp4.ergou");
        Path original = ROOT.resolve("原内容/ミエル 20260505.mp4");
        assumeTrue(Files.exists(enc) && Files.exists(original), "缺少 MP4 真实文件");
        Path out = decryptVolume(enc, OUT.resolve("ミエル 20260505.mp4"));
        assertByteIdentical(original, out);
    }

    /**
     * 桌面端加密（v2.14，MP3 明文）→ 桌面端解密。
     */
    @Test
    void desktopVolume_mp3() throws Exception {
        Path enc = ROOT.resolve("desktop/ミエル2026_05_21お隣さんから丸見え《Fantia》.mp3.ergou");
        Path original = ROOT.resolve("原内容/ミエル2026_05_21お隣さんから丸見え《Fantia》.mp3");
        assumeTrue(Files.exists(enc) && Files.exists(original), "缺少 MP3 真实文件");
        Path out = decryptVolume(enc, OUT.resolve("ミエル2026_05_21お隣さんから丸見え《Fantia》.mp3"));
        assertByteIdentical(original, out);
    }

    /**
     * 解密单个卷文件并输出到目标路径，打印当前 KDF 路径可行性。
     */
    private Path decryptVolume(final Path enc, final Path out) throws Exception {
        Files.createDirectories(out.getParent());
        reportKdfPath(enc);
        DecryptRequest req = new DecryptRequest();
        req.setInputFile(enc.toString());
        req.setOutputFile(out.toString());
        req.setPassword(PASSWORD);
        req.setRsCodecs(RS);
        Decryptor.decrypt(req);
        return out;
    }

    /**
     * 打印当前可用堆与 1 GiB 是否可堆内派生，用于区分桌面/移动 KDF 路径。
     */
    private static void reportKdfPath(final Path enc) {
        Runtime rt = Runtime.getRuntime();
        long avail = rt.maxMemory() - (rt.totalMemory() - rt.freeMemory());
        boolean inHeap = Argon2Kdf.isHeapFeasible(1 << 20);
        System.out.printf("decrypt %s | availHeap=%d MiB | 1GiB inHeap=%s%n",
                enc.getFileName(), avail >> 20, inHeap);
    }

    /**
     * 断言两文件字节完全一致（先比大小，再用 {@code Files.mismatch} 流式比对）。
     */
    private static void assertByteIdentical(final Path expected, final Path actual)
            throws IOException {
        assertEquals(Files.size(expected), Files.size(actual),
                "大小不一致: " + actual.getFileName());
        long mismatch = Files.mismatch(expected, actual);
        assertEquals(-1L, mismatch,
                "内容在字节 " + mismatch + " 处不一致: " + actual.getFileName());
    }
}
