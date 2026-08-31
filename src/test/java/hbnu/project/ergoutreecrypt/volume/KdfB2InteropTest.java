package hbnu.project.ergoutreecrypt.volume;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import hbnu.project.ergoutreecrypt.encoding.RsCodecs;
import hbnu.project.ergoutreecrypt.header.HeaderReader;
import hbnu.project.ergoutreecrypt.header.VolumeHeader;
import hbnu.project.ergoutreecrypt.settings.Argon2DesktopMode;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/**
 * Phase B2 — 桌面端 KDF 档位选择的真实文件跨平台 / 跨版本互通测试。
 *
 * <p>以 {@code temp/test} 的真实文件为明文与密文，验证：
 * <ol>
 *   <li>档位枚举 {@link Argon2DesktopMode} 正确映射到 KDF 三元组，默认档为均衡 256 MiB；</li>
 *   <li>三档桌面加密（均衡 256 MiB / 强 1 GiB / 偏执 1 GiB）各自的卷头记录正确参数、
 *       且解密产物与明文逐字节一致；</li>
 *   <li>「均衡 256 MiB」档与移动端 {@code BALANCED} 档参数相同，故同时代表
 *       「手机端加密 → 电脑端/手机端解密」方向；</li>
 *   <li>跨版本：旧版桌面端加密文件（{@code temp/test/desktop}）可被当前工具逐字节解密。</li>
 * </ol>
 *
 * <p>「电脑端解密 vs 手机端解密」由 JVM 堆大小区分：默认堆下 1 GiB 走堆内 BouncyCastle
 * （电脑端），以 {@code -Xmx512m} 运行时 1 GiB 走离堆（手机端）。故本测试需分别在两种
 * 堆下各跑一次，两次结果合起来覆盖全部方向。产物写入 {@code temp/test/test_output/b2}。
 *
 * @author ErgouTree
 * @since 2026/8/31
 */
class KdfB2InteropTest {

    private static final String PASSWORD = "ergou";
    private static final RsCodecs RS = new RsCodecs();
    private static final Path ROOT = Path.of("temp/test");
    private static final Path SOURCES = ROOT.resolve("原内容");
    private static final Path DESKTOP = ROOT.resolve("desktop");
    private static final Path OUT = ROOT.resolve("test_output/b2");

    /**
     * 档位枚举 → KDF 三元组映射正确，未知键回退默认「均衡」档。
     */
    @Test
    void tierEnumMapping() {
        assertEquals(256 << 10, Argon2DesktopMode.BALANCED.getMemoryKib());
        assertEquals(3, Argon2DesktopMode.BALANCED.getPasses());
        assertEquals(4, Argon2DesktopMode.BALANCED.getThreads());

        assertEquals(1 << 20, Argon2DesktopMode.STRONG.getMemoryKib());
        assertEquals(4, Argon2DesktopMode.STRONG.getPasses());
        assertEquals(4, Argon2DesktopMode.STRONG.getThreads());

        assertEquals(1 << 20, Argon2DesktopMode.PARANOID.getMemoryKib());
        assertEquals(8, Argon2DesktopMode.PARANOID.getPasses());
        assertEquals(8, Argon2DesktopMode.PARANOID.getThreads());

        assertEquals(Argon2DesktopMode.BALANCED, Argon2DesktopMode.fromKey(null));
        assertEquals(Argon2DesktopMode.BALANCED, Argon2DesktopMode.fromKey("unknown"));
        assertEquals(Argon2DesktopMode.STRONG, Argon2DesktopMode.fromKey("STRONG"));
    }

    /**
     * 跨版本：解密旧版桌面端加密文件，逐字节比对源文件。
     */
    @Test
    void crossVersion_decryptOldDesktopFiles() throws Exception {
        assumeTrue(Files.isDirectory(DESKTOP) && Files.isDirectory(SOURCES), "缺少真实测试文件");
        List<Path> encFiles;
        try (var s = Files.list(DESKTOP)) {
            encFiles = s.filter(p -> p.getFileName().toString().endsWith(".ergou"))
                    .sorted().toList();
        }
        assumeTrue(!encFiles.isEmpty(), "desktop 目录为空");
        Files.createDirectories(OUT);

        for (Path enc : encFiles) {
            String name = enc.getFileName().toString();
            String base = name.substring(0, name.length() - ".ergou".length());
            Path original = SOURCES.resolve(base);
            assumeTrue(Files.exists(original), "源文件缺失: " + original);
            Path out = OUT.resolve("crossver_" + base);
            decrypt(enc, out);
            assertByteIdentical(original, out, "跨版本 " + name);
        }
    }

    /**
     * B2 三档桌面加密全矩阵：每个源文件用三档各加密一次，校验卷头 + 解密 + 逐字节比对。
     *
     * <p>「均衡 256 MiB」档参数与移动端 BALANCED 档一致，等价覆盖「手机端加密」方向。
     */
    @Test
    void b2Tier_roundTripAllSources() throws Exception {
        assumeTrue(Files.isDirectory(SOURCES), "缺少真实源文件目录");
        List<Path> sources;
        try (var s = Files.list(SOURCES)) {
            sources = s.filter(Files::isRegularFile).sorted().toList();
        }
        assumeTrue(!sources.isEmpty(), "源文件目录为空");
        Files.createDirectories(OUT);

        for (Path src : sources) {
            String name = src.getFileName().toString();
            roundTripTier(src, name, Argon2DesktopMode.BALANCED);
            roundTripTier(src, name, Argon2DesktopMode.STRONG);
            roundTripTier(src, name, Argon2DesktopMode.PARANOID);
        }
    }

    /**
     * 用指定档位加密单个源文件，校验卷头参数后解密并逐字节比对。
     */
    private void roundTripTier(Path src, String name, Argon2DesktopMode mode) throws Exception {
        String tag = mode.getKey().toLowerCase();
        Path enc = OUT.resolve(name + "." + tag + ".ergou");

        EncryptRequest req = new EncryptRequest();
        req.setInputFile(src.toString());
        req.setOutputFile(enc.toString());
        req.setPassword(PASSWORD);
        req.setRsCodecs(RS);
        req.setArgon2MemoryKib(mode.getMemoryKib());
        req.setArgon2Passes(mode.getPasses());
        req.setArgon2Threads(mode.getThreads());
        Encryptor.encrypt(req);

        // B1 保证非压缩卷头升级到 v2.15 并记录参数；B2 保证参数等于档位三元组
        VolumeHeader h = readHeader(enc);
        assertEquals(VolumeHeader.VERSION_V215, h.getVersion(), tag + " 卷头版本");
        assertTrue(h.hasArgon2Params(), tag + " 应记录 Argon2 参数");
        assertEquals(mode.getMemoryKib(), h.getArgon2MemoryKib(), tag + " 内存档位");
        assertEquals(mode.getPasses(), h.getArgon2Passes(), tag + " 轮数");
        assertEquals(mode.getThreads(), h.getArgon2Threads(), tag + " 线程");

        Path dec = OUT.resolve(name + "." + tag + ".dec");
        decrypt(enc, dec);
        assertByteIdentical(src, dec, name + "(" + tag + ")");
    }

    /**
     * 解密单个文件到目标路径。
     */
    private void decrypt(Path enc, Path out) throws Exception {
        DecryptRequest req = new DecryptRequest();
        req.setInputFile(enc.toString());
        req.setOutputFile(out.toString());
        req.setPassword(PASSWORD);
        req.setRsCodecs(RS);
        Decryptor.decrypt(req);
    }

    /**
     * 读取加密文件的卷头。
     */
    private static VolumeHeader readHeader(Path enc) throws Exception {
        try (InputStream in = Files.newInputStream(enc)) {
            return new HeaderReader(in, RS).readHeader().getHeader();
        }
    }

    /**
     * 断言两文件字节完全一致（先比大小，再流式比对）。
     */
    private static void assertByteIdentical(Path expected, Path actual, String label)
            throws Exception {
        assertEquals(Files.size(expected), Files.size(actual),
                "大小不一致: " + label + " → " + actual.getFileName());
        long mismatch = Files.mismatch(expected, actual);
        assertEquals(-1L, mismatch,
                "内容在字节 " + mismatch + " 处不一致: " + label + " → " + actual.getFileName());
    }
}
