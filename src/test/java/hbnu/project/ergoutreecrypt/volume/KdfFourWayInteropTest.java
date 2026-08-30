package hbnu.project.ergoutreecrypt.volume;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import hbnu.project.ergoutreecrypt.crypto.Argon2Kdf;
import hbnu.project.ergoutreecrypt.encoding.RsCodecs;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/**
 * 桌面端 / 移动端双向加密-解密的 4 路互通测试（真实数据）。
 *
 * <p>以 {@code temp/test/原内容} 的真实文件为明文，验证「手机端加密 / 电脑端加密」
 * 与「电脑端解密 / 手机端解密」的四种组合均逐字节还原：
 * <ol>
 *   <li>手机端加密（256 MiB 覆写）→ 电脑端解密（堆内）</li>
 *   <li>手机端加密（256 MiB 覆写）→ 手机端解密（离堆）</li>
 *   <li>电脑端加密（1 GiB 默认）→ 电脑端解密（堆内）</li>
 *   <li>电脑端加密（1 GiB 默认）→ 手机端解密（离堆）</li>
 * </ol>
 *
 * <p>「电脑端解密 vs 手机端解密」由 JVM 堆大小区分：默认堆下 1 GiB 走堆内 BC（电脑端），
 * 以 {@code -Xmx512m} 运行时 1 GiB 走离堆（手机端）。故本测试需分别在两种堆下各跑一次，
 * 两次结果合起来即覆盖全部四路。加密/解密产物写入 {@code temp/test/test_output/fourway}。
 *
 * @author ErgouTree
 */
class KdfFourWayInteropTest {

    private static final String PASSWORD = "ergou";
    private static final RsCodecs RS = new RsCodecs();
    private static final Path ROOT = Path.of("temp/test");
    private static final Path SOURCES = ROOT.resolve("原内容");
    private static final Path OUT = ROOT.resolve("test_output/fourway");

    /** 手机端「均衡 256 MiB」档位覆写（memoryKiB / passes / threads）。 */
    private static final int MOBILE_MEMORY_KIB = 256 << 10;
    private static final int MOBILE_PASSES = 3;
    private static final int MOBILE_THREADS = 4;

    /**
     * 对 {@code 原内容} 内每个文件执行「手机端加密 + 电脑端加密 → 各自解密 → 逐字节比对」。
     */
    @Test
    void fourWayInterop_allSources() throws Exception {
        assumeTrue(Files.isDirectory(SOURCES), "缺少真实源文件目录");
        List<Path> sources;
        try (var stream = Files.list(SOURCES)) {
            sources = stream.filter(Files::isRegularFile).sorted().toList();
        }
        assumeTrue(!sources.isEmpty(), "源文件目录为空");
        Files.createDirectories(OUT);

        for (Path src : sources) {
            fourWay(src);
        }
    }

    /**
     * 对单个源文件执行两路加密与两路解密，逐字节比对。
     */
    private void fourWay(final Path src) throws Exception {
        String name = src.getFileName().toString();

        // 手机端加密（256 MiB 覆写）→ 解密 → 比对
        Path mobileEnc = OUT.resolve(name + ".mobile.ergou");
        encrypt(src, mobileEnc, true, false);
        Path mobileDec = OUT.resolve(name + ".mobile.dec");
        decrypt(mobileEnc, mobileDec);
        assertByteIdentical(src, mobileDec, name + "（手机端加密）");

        // 电脑端加密（1 GiB 默认）→ 解密 → 比对
        Path desktopEnc = OUT.resolve(name + ".desktop.ergou");
        encrypt(src, desktopEnc, false, false);
        Path desktopDec = OUT.resolve(name + ".desktop.dec");
        decrypt(desktopEnc, desktopDec);
        assertByteIdentical(src, desktopDec, name + "（电脑端加密）");

        // 电脑端加密（1 GiB + 加密前压缩，v2.16）→ 解密 → 比对
        Path compressEnc = OUT.resolve(name + ".desktop-compress.ergou");
        encrypt(src, compressEnc, false, true);
        Path compressDec = OUT.resolve(name + ".desktop-compress.dec");
        decrypt(compressEnc, compressDec);
        assertByteIdentical(src, compressDec, name + "（电脑端压缩加密）");
    }

    /**
     * 加密单个文件。手机端模式写入 256 MiB 覆写参数，电脑端模式走默认 1 GiB。
     */
    private void encrypt(final Path src, final Path out, final boolean mobileMode,
                         final boolean compress) throws Exception {
        EncryptRequest req = new EncryptRequest();
        req.setInputFile(src.toString());
        req.setOutputFile(out.toString());
        req.setPassword(PASSWORD);
        req.setRsCodecs(RS);
        if (mobileMode) {
            req.setArgon2MemoryKib(MOBILE_MEMORY_KIB);
            req.setArgon2Passes(MOBILE_PASSES);
            req.setArgon2Threads(MOBILE_THREADS);
        }
        if (compress) {
            req.setCompress(true);
        }
        Encryptor.encrypt(req);
    }

    /**
     * 解密单个文件并打印当前 KDF 路径可行性。
     */
    private void decrypt(final Path enc, final Path out) throws Exception {
        reportKdfPath(enc);
        DecryptRequest req = new DecryptRequest();
        req.setInputFile(enc.toString());
        req.setOutputFile(out.toString());
        req.setPassword(PASSWORD);
        req.setRsCodecs(RS);
        Decryptor.decrypt(req);
    }

    /**
     * 打印当前可用堆与 1 GiB 是否可堆内派生，用于区分电脑端/手机端 KDF 路径。
     */
    private static void reportKdfPath(final Path enc) {
        Runtime rt = Runtime.getRuntime();
        long avail = rt.maxMemory() - (rt.totalMemory() - rt.freeMemory());
        System.out.printf("decrypt %s | availHeap=%d MiB | 1GiB inHeap=%s%n",
                enc.getFileName(), avail >> 20, Argon2Kdf.isHeapFeasible(1 << 20));
    }

    /**
     * 断言两文件字节完全一致（先比大小，再流式比对）。
     */
    private static void assertByteIdentical(final Path expected, final Path actual,
                                            final String label) throws IOException {
        assertEquals(Files.size(expected), Files.size(actual),
                "大小不一致: " + label + " → " + actual.getFileName());
        long mismatch = Files.mismatch(expected, actual);
        assertEquals(-1L, mismatch,
                "内容在字节 " + mismatch + " 处不一致: " + label + " → " + actual.getFileName());
    }
}
