package hbnu.project.ergoutreecrypt.mediacrypt;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import hbnu.project.ergoutreecrypt.mediacrypt.wav.WavChunk;
import hbnu.project.ergoutreecrypt.mediacrypt.wav.WavParser;
import hbnu.project.ergoutreecrypt.settings.Argon2DesktopMode;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Security;
import java.util.Arrays;
import java.util.List;

/**
 * 格式保持（媒体）加解密 KDF 互通测试（Phase M1 落地验证）。
 *
 * <p>覆盖两个层面：
 * <ol>
 *   <li><b>M1 元数据记录</b>：桌面端按 {@link Argon2DesktopMode} 档位加密媒体时，
 *       {@code MediaMetadata} v2 必须记录实际 Argon2 三元组（而非全零），使移动端
 *       解密时读到真实低内存档位、堆内秒级派生。</li>
 *   <li><b>跨端互通</b>：桌面端档位（均衡 256 MiB / 强 1 GiB）与移动端档位
 *       （256 / 64 / 32 MiB）加密的媒体文件，解密端均能逐字节还原——因解密侧
 *       从元数据读取参数，两端共用同一 {@code MediaCryptCodec}，故桌面加密与移动
 *       加密两个方向的产物都可被另一端正确解密。</li>
 * </ol>
 *
 * <p>真实数据文件（{@code temp/test/原内容} 的 mp3 / mp4）用于端到端逐字节比对；
 * 合成 WAV 夹具用于快速、无外部依赖的元数据断言。产物写入
 * {@code temp/test/test_output/fpe}。
 *
 * @author ErgouTree
 * @since 2026/8/31
 */
class MediaCryptKdfInteropTest {

    /** 测试密码（与真实文件加密互不影响，本测试对源文件独立加密）。 */
    private static final byte[] PASSWORD = "ergou-fpe-interop".getBytes(StandardCharsets.UTF_8);

    /** 真实测试数据根目录与输出目录。 */
    private static final Path ROOT = Path.of("temp/test");
    private static final Path SOURCES = ROOT.resolve("原内容");
    private static final Path OUT = ROOT.resolve("test_output/fpe");

    private final MediaCryptCodec codec = new MediaCryptCodec();

    @BeforeAll
    static void setup() {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }
    }

    // ==================== M1 元数据记录断言（合成 WAV，快速） ====================

    /**
     * M1：均衡 256 MiB 档加密时，WAV 的 {@code EgTc} 元数据记录 256 MiB / 3 / 4。
     */
    @Test
    void m1_balancedTierRecordsParamsInMetadata(@TempDir Path dir) throws Exception {
        Path in = MediaTestFixtures.write(dir, "in.wav",
                MediaTestFixtures.buildWav(MediaTestFixtures.pseudoData(4096)));
        Path enc = dir.resolve("enc.wav");

        MediaCryptOptions opts = tier(Argon2DesktopMode.BALANCED);
        codec.encrypt(in, enc, PASSWORD, opts);

        MediaMetadata meta = readWavMetadata(enc);
        assertTrue(meta.hasArgon2Params(), "均衡档应记录 Argon2 参数");
        assertEquals(256 << 10, meta.argon2MemoryKib(), "均衡档内存参数");
        assertEquals(3, meta.argon2Passes(), "均衡档轮数");
        assertEquals(4, meta.argon2Threads(), "均衡档线程数");

        // 解密侧按元数据参数派生并逐字节还原
        Path dec = dir.resolve("dec.wav");
        codec.decrypt(enc, dec, PASSWORD);
        assertArrayEquals(Files.readAllBytes(in), Files.readAllBytes(dec));
    }

    /**
     * M1：强 1 GiB 档加密时记录 1 GiB / 4 / 4。
     */
    @Test
    void m1_strongTierRecordsParamsInMetadata(@TempDir Path dir) throws Exception {
        Path in = MediaTestFixtures.write(dir, "in.wav",
                MediaTestFixtures.buildWav(MediaTestFixtures.pseudoData(2048)));
        Path enc = dir.resolve("enc.wav");

        codec.encrypt(in, enc, PASSWORD, tier(Argon2DesktopMode.STRONG));

        MediaMetadata meta = readWavMetadata(enc);
        assertTrue(meta.hasArgon2Params());
        assertEquals(1 << 20, meta.argon2MemoryKib(), "强档内存参数");
        assertEquals(4, meta.argon2Passes());
        assertEquals(4, meta.argon2Threads());
    }

    /**
     * M1：偏执 1 GiB 档加密时记录 1 GiB / 8 / 8。
     */
    @Test
    void m1_paranoidTierRecordsParamsInMetadata(@TempDir Path dir) throws Exception {
        Path in = MediaTestFixtures.write(dir, "in.wav",
                MediaTestFixtures.buildWav(MediaTestFixtures.pseudoData(2048)));
        Path enc = dir.resolve("enc.wav");

        codec.encrypt(in, enc, PASSWORD, tier(Argon2DesktopMode.PARANOID));

        MediaMetadata meta = readWavMetadata(enc);
        assertTrue(meta.hasArgon2Params());
        assertEquals(1 << 20, meta.argon2MemoryKib());
        assertEquals(8, meta.argon2Passes(), "偏执档轮数");
        assertEquals(8, meta.argon2Threads(), "偏执档线程数");
    }

    /**
     * 向后兼容基线：未显式设置档位（{@link MediaCryptOptions#defaults()}）时
     * 元数据不记录参数（全零），解密端回落到默认 1 GiB——与 M1 之前的旧文件一致。
     */
    @Test
    void backwardCompat_defaultOptionsRecordNoParams(@TempDir Path dir) throws Exception {
        Path in = MediaTestFixtures.write(dir, "in.wav",
                MediaTestFixtures.buildWav(MediaTestFixtures.pseudoData(2048)));
        Path enc = dir.resolve("enc.wav");

        codec.encrypt(in, enc, PASSWORD, MediaCryptOptions.defaults());

        MediaMetadata meta = readWavMetadata(enc);
        assertFalse(meta.hasArgon2Params(), "无档位覆写时元数据不应记录参数（保持旧格式兼容）");

        Path dec = dir.resolve("dec.wav");
        codec.decrypt(enc, dec, PASSWORD);
        assertArrayEquals(Files.readAllBytes(in), Files.readAllBytes(dec));
    }

    /**
     * 高级选项：偏执标志（Serpent-CTR + HMAC-SHA3）与档位正交，往返逐字节一致。
     */
    @Test
    void paranoidFlagRoundTrip(@TempDir Path dir) throws Exception {
        Path in = MediaTestFixtures.write(dir, "in.wav",
                MediaTestFixtures.buildWav(MediaTestFixtures.pseudoData(4096)));
        Path enc = dir.resolve("enc.wav");

        MediaCryptOptions opts = MediaCryptOptions.builder()
                .paranoid(true)
                .storeIntegrity(true)
                .argon2MemoryKib(Argon2DesktopMode.BALANCED.getMemoryKib())
                .argon2Passes(Argon2DesktopMode.BALANCED.getPasses())
                .argon2Threads(Argon2DesktopMode.BALANCED.getThreads())
                .build();
        codec.encrypt(in, enc, PASSWORD, opts);

        // paranoid 标志与 KDF 档位正交：档位仍为 256 MiB
        MediaMetadata meta = readWavMetadata(enc);
        assertTrue(meta.paranoid(), "paranoid 标志应写入元数据");
        assertEquals(256 << 10, meta.argon2MemoryKib(), "paranoid 下档位仍应生效");

        Path dec = dir.resolve("dec.wav");
        codec.decrypt(enc, dec, PASSWORD);
        assertArrayEquals(Files.readAllBytes(in), Files.readAllBytes(dec));
    }

    // ==================== M2 peekMetadata 只读探测 ====================

    /**
     * M2：{@code peekMetadata} 只读探测记录档位的加密文件，能读回真实 Argon2 参数。
     */
    @Test
    void m2_peekMetadataReadsRecordedParams(@TempDir Path dir) throws Exception {
        Path in = MediaTestFixtures.write(dir, "in.wav",
                MediaTestFixtures.buildWav(MediaTestFixtures.pseudoData(4096)));
        Path enc = dir.resolve("enc.wav");

        codec.encrypt(in, enc, PASSWORD, tier(Argon2DesktopMode.BALANCED));

        MediaMetadata meta = codec.peekMetadata(enc);
        assertNotNull(meta, "peekMetadata 应读取到加密元数据");
        assertTrue(meta.hasArgon2Params());
        assertEquals(256 << 10, meta.argon2MemoryKib());
    }

    /**
     * M2：{@code peekMetadata} 读取旧格式（无参数覆写）加密文件返回 null 参数。
     */
    @Test
    void m2_peekMetadataReadsOldFormatNoParams(@TempDir Path dir) throws Exception {
        Path in = MediaTestFixtures.write(dir, "in.wav",
                MediaTestFixtures.buildWav(MediaTestFixtures.pseudoData(2048)));
        Path enc = dir.resolve("enc.wav");

        codec.encrypt(in, enc, PASSWORD, MediaCryptOptions.defaults());

        MediaMetadata meta = codec.peekMetadata(enc);
        assertNotNull(meta, "peekMetadata 应读取到旧格式元数据");
        assertFalse(meta.hasArgon2Params(), "旧格式无 Argon2 参数覆写");
    }

    /**
     * M2：{@code peekMetadata} 对非本工具加密的普通媒体文件返回 null。
     */
    @Test
    void m2_peekMetadataOnPlainMediaReturnsNull(@TempDir Path dir) throws Exception {
        Path plain = MediaTestFixtures.write(dir, "plain.wav",
                MediaTestFixtures.buildWav(MediaTestFixtures.pseudoData(2048)));
        assertNull(codec.peekMetadata(plain), "普通媒体文件应返回 null");
    }

    /**
     * M2：真实加密媒体文件的 {@code peekMetadata} 与解密侧读参数一致。
     */
    @Test
    void m2_peekMetadataRealEncryptedMedia() throws Exception {
        assumeTrue(Files.isDirectory(OUT), "缺少真实加密产物目录");
        List<Path> encFiles;
        try (var s = Files.list(OUT)) {
            encFiles = s.filter(Files::isRegularFile)
                    .filter(p -> p.getFileName().toString().contains(".enc."))
                    .sorted().toList();
        }
        assumeTrue(!encFiles.isEmpty(), "无真实加密产物");
        for (Path enc : encFiles) {
            MediaMetadata meta = codec.peekMetadata(enc);
            assertNotNull(meta, "真实加密产物应能读到元数据: " + enc.getFileName());
            assertTrue(meta.hasArgon2Params(), "真实加密产物应记录参数: " + enc.getFileName());
        }
    }

    // ==================== 真实数据跨端互通（mp3 / mp4） ====================

    /**
     * 真实媒体文件双向互通：桌面端三档 + 移动端两档加密，解密逐字节还原。
     *
     * <p>移动端档位取 {@code Argon2MobileMode} 的 LIGHT（64 MiB/2/2）与
     * AUTO 兜底（32 MiB/2/2）；桌面端「均衡 256 MiB」与移动端 BALANCED 同参，
     * 二者等价覆盖「手机加密 → 电脑解密」。对 529 MiB 大 mp4 仅做均衡档往返，
     * 控制总时长。
     */
    @Test
    void realMedia_desktopAndMobileTierRoundTrip() throws Exception {
        assumeTrue(Files.isDirectory(SOURCES), "缺少真实源文件目录");
        List<Path> mediaFiles;
        try (var s = Files.list(SOURCES)) {
            mediaFiles = s.filter(Files::isRegularFile)
                    .filter(MediaCryptKdfInteropTest::isMedia)
                    .sorted().toList();
        }
        assumeTrue(!mediaFiles.isEmpty(), "源文件目录无媒体文件");
        Files.createDirectories(OUT);

        for (Path src : mediaFiles) {
            String name = src.getFileName().toString();
            boolean large = Files.size(src) > (256L << 20);

            // 桌面端档位（默认均衡 256 MiB + 强 1 GiB）
            roundTrip(src, name, "desktop_balanced",
                    Argon2DesktopMode.BALANCED.getMemoryKib(),
                    Argon2DesktopMode.BALANCED.getPasses(),
                    Argon2DesktopMode.BALANCED.getThreads());
            if (!large) {
                roundTrip(src, name, "desktop_strong",
                        Argon2DesktopMode.STRONG.getMemoryKib(),
                        Argon2DesktopMode.STRONG.getPasses(),
                        Argon2DesktopMode.STRONG.getThreads());
                // 移动端档位（LIGHT 64 MiB / AUTO 兜底 32 MiB）
                roundTrip(src, name, "mobile_light", 64 << 10, 2, 2);
                roundTrip(src, name, "mobile_auto32", 32 << 10, 2, 2);
            }
        }
    }

    /**
     * 用指定 Argon2 三元组加密真实媒体文件，解密后与源逐字节比对。
     */
    private void roundTrip(Path src, String name, String tag,
                           int memoryKib, int passes, int threads) throws Exception {
        Path enc = OUT.resolve(name + "." + tag + ".enc." + extension(name));
        Path dec = OUT.resolve(name + "." + tag + ".dec." + extension(name));

        MediaCryptOptions opts = MediaCryptOptions.builder()
                .argon2MemoryKib(memoryKib)
                .argon2Passes(passes)
                .argon2Threads(threads)
                .build();
        codec.encrypt(src, enc, PASSWORD, opts);
        codec.decrypt(enc, dec, PASSWORD);

        assertEquals(Files.size(src), Files.size(dec),
                "大小不一致: " + tag + " → " + dec.getFileName());
        long mismatch = Files.mismatch(src, dec);
        assertEquals(-1L, mismatch,
                "内容在字节 " + mismatch + " 处不一致: " + tag + " → " + dec.getFileName());
    }

    // ==================== 辅助 ====================

    /**
     * 依据桌面端档位构建媒体加密选项。
     */
    private static MediaCryptOptions tier(Argon2DesktopMode mode) {
        return MediaCryptOptions.builder()
                .argon2MemoryKib(mode.getMemoryKib())
                .argon2Passes(mode.getPasses())
                .argon2Threads(mode.getThreads())
                .build();
    }

    /**
     * 读取加密 WAV 末尾 {@code EgTc} chunk 内的 {@link MediaMetadata}。
     */
    private static MediaMetadata readWavMetadata(Path enc) throws Exception {
        WavParser parser = WavParser.parse(enc);
        WavChunk meta = parser.findChunk(WavParser.META_CHUNK_ID);
        assertNotNull(meta, "WAV 缺少 EgTc 元数据 chunk");
        byte[] all = Files.readAllBytes(enc);
        byte[] metaBytes = Arrays.copyOfRange(all,
                (int) meta.payloadOffset(), (int) (meta.payloadOffset() + meta.payloadSize()));
        return MediaMetadata.fromBytes(metaBytes);
    }

    /**
     * 判断文件是否为受支持的媒体格式（mp3 / mp4）。
     */
    private static boolean isMedia(Path p) {
        return MediaFormat.fromExtension(p) != null;
    }

    /**
     * 取文件名小写扩展名（不含点）。
     */
    private static String extension(String name) {
        int dot = name.lastIndexOf('.');
        return dot >= 0 ? name.substring(dot + 1).toLowerCase() : "bin";
    }
}
