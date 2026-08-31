package hbnu.project.ergoutreecrypt.filestego;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import hbnu.project.ergoutreecrypt.filestego.api.Argon2Params;
import hbnu.project.ergoutreecrypt.filestego.api.FileStegoOptions;
import hbnu.project.ergoutreecrypt.filestego.carrier.spi.AbstractCarrierAdapter;
import hbnu.project.ergoutreecrypt.filestego.carrier.spi.CarrierAdapter;
import hbnu.project.ergoutreecrypt.filestego.carrier.spi.CarrierMetadata;
import hbnu.project.ergoutreecrypt.filestego.carrier.spi.CarrierRegistry;
import hbnu.project.ergoutreecrypt.settings.Argon2DesktopMode;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * 文件隐写（STEG-V2）KDF 档位与跨端互通测试（Phase S1 落地验证）。
 *
 * <p>覆盖三个层面：
 * <ol>
 *   <li><b>S1 档位记录</b>：桌面端按 {@link Argon2DesktopMode} 档位隐写时，
 *       {@code CarrierMetadata} 的 RESERVED 字段必须记录实际 Argon2 三元组
 *       （而非全零），使移动端提取时读到真实低内存档位、堆内秒级派生。</li>
 *   <li><b>跨端互通</b>：桌面端档位（均衡 256 MiB / 强 1 GiB）与移动端档位
 *       （256 / 64 / 32 MiB）隐写的产物，另一端均能逐字节还原——提取侧的
 *       Argon2 参数从载体元数据读取，与当前设备档位设置无关。</li>
 *   <li><b>高级选项稳定性</b>：偏执 / 完整性 / 隐蔽 / 混淆大小 / PNG 两种嵌入
 *       落点（stEG chunk 与 IEND 追加）在跨端方向上均可正确提取。</li>
 * </ol>
 *
 * <p>真实数据用于端到端逐字节比对：秘密文件取自 {@code temp/test/原内容}
 * （含 {@code 原内容.zip} 内的真实 mp3），载体取自 {@code temp/test/载体}
 * （PNG / ZIP / PDF / WAV / FLAC / MP4 六种容器）。产物写入
 * {@code temp/test/test_output/stego}，可直接拷到真机做端到端确认。
 * 缺少真实数据时相关用例按 {@code Assumptions} 跳过，不影响 CI。
 *
 * @author ErgouTree
 * @since 2026/8/31
 */
class FileStegoKdfInteropTest {

    /** 测试密码（与真实文件的实际使用互不影响，本测试独立加密）。 */
    private static final byte[] PASSWORD = "ergou-stego-interop".getBytes(StandardCharsets.UTF_8);

    /** 真实测试数据根目录、载体目录与输出目录。 */
    private static final Path ROOT = Path.of("temp/test");
    private static final Path SOURCES = ROOT.resolve("原内容");
    private static final Path CARRIERS = ROOT.resolve("载体");
    private static final Path OUT = ROOT.resolve("test_output/stego");

    /** 从真实归档中解出的秘密文件缓存目录。 */
    private static final Path SECRETS = OUT.resolve("_secrets");

    /** 移动端档位参数（{@code Argon2MobileMode} 的三个候选档，与移动端保持同值）。 */
    private static final Argon2Params MOBILE_BALANCED = new Argon2Params(256 << 10, 3, 4);
    private static final Argon2Params MOBILE_LIGHT = new Argon2Params(64 << 10, 2, 2);
    private static final Argon2Params MOBILE_AUTO_MIN = new Argon2Params(32 << 10, 2, 2);

    /** 移动端大文件护栏阈值（典型 256 MiB 堆设备的 availableHeap/4 取值）。 */
    private static final long MOBILE_THRESHOLD_BYTES = 64L << 20;

    /**
     * 真实秘密文件切片大小（12 MiB）：小于 FLAC 载体 16 MiB 的容量上限，
     * 使六种载体都能进入同一矩阵。
     */
    private static final long SECRET_SLICE_BYTES = 12L << 20;

    /** 大文件互通用例的隐写产物上限（超过则跳过元数据探针，避免重复读写整份 Payload）。 */
    private static final long META_PROBE_LIMIT_BYTES = 128L << 20;

    private final FileStegoCodec codec = new FileStegoCodec();

    @BeforeAll
    static void setup() throws Exception {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }
        Files.createDirectories(OUT);
    }

    // ==================== S1 档位记录断言（合成载体，快速） ====================

    /**
     * S1：均衡 256 MiB 档隐写时，载体元数据记录 256 MiB / 3 / 4，且提取逐字节还原。
     *
     * @param dir JUnit 提供的临时目录
     * @throws Exception 隐写或提取失败
     */
    @Test
    void s1_balancedTierRecordsParamsInMetadata(@TempDir Path dir) throws Exception {
        Path carrier = createPng(dir, "carrier.png");
        Path secret = createSecret(dir, "secret.bin", 64 * 1024);
        Path stego = dir.resolve("stego.png");

        codec.hide(carrier, secret, stego, PASSWORD,
                desktopHideOptions(Argon2DesktopMode.BALANCED, true), null);

        CarrierMetadata meta = readCarrierMetadata(stego);
        assertNotNull(meta.argon2Params(), "均衡档应记录 Argon2 参数");
        assertEquals(256 << 10, meta.argon2Params().memoryKiB(), "均衡档内存参数");
        assertEquals(3, meta.argon2Params().passes(), "均衡档轮数");
        assertEquals(4, meta.argon2Params().threads(), "均衡档线程数");

        Path outDir = Files.createDirectories(dir.resolve("out"));
        Path extracted = codec.extract(stego, outDir, PASSWORD, mobileExtractOptions(), null);
        assertEquals(-1L, Files.mismatch(secret, extracted), "提取产物应与源逐字节一致");
    }

    /**
     * S1：强 1 GiB 档隐写时记录 1 GiB / 4 / 4，且提取逐字节还原（模拟桌面选强档 → 移动端提取）。
     *
     * @param dir JUnit 提供的临时目录
     * @throws Exception 隐写或提取失败
     */
    @Test
    void s1_strongTierRecordsParamsInMetadata(@TempDir Path dir) throws Exception {
        Path carrier = createZip(dir, "carrier.zip");
        Path secret = createSecret(dir, "secret.bin", 32 * 1024);
        Path stego = dir.resolve("stego.zip");

        codec.hide(carrier, secret, stego, PASSWORD,
                desktopHideOptions(Argon2DesktopMode.STRONG, false), null);

        CarrierMetadata meta = readCarrierMetadata(stego);
        assertNotNull(meta.argon2Params());
        assertEquals(1 << 20, meta.argon2Params().memoryKiB(), "强档内存参数");
        assertEquals(4, meta.argon2Params().passes());
        assertEquals(4, meta.argon2Params().threads());

        Path outDir = Files.createDirectories(dir.resolve("out"));
        Path extracted = codec.extract(stego, outDir, PASSWORD, mobileExtractOptions(), null);
        assertEquals(-1L, Files.mismatch(secret, extracted), "强档产物提取应逐字节一致");
    }

    /**
     * S1：偏执 1 GiB / 8 轮档隐写时记录 1 GiB / 8 / 8（1 字节字段无溢出）。
     *
     * @param dir JUnit 提供的临时目录
     * @throws Exception 隐写失败
     */
    @Test
    void s1_paranoidTierRecordsParamsInMetadata(@TempDir Path dir) throws Exception {
        Path carrier = createZip(dir, "carrier.zip");
        Path secret = createSecret(dir, "secret.bin", 8 * 1024);
        Path stego = dir.resolve("stego.zip");

        codec.hide(carrier, secret, stego, PASSWORD,
                desktopHideOptions(Argon2DesktopMode.PARANOID, false), null);

        CarrierMetadata meta = readCarrierMetadata(stego);
        assertNotNull(meta.argon2Params());
        assertEquals(1 << 20, meta.argon2Params().memoryKiB(), "偏执档内存参数");
        assertEquals(8, meta.argon2Params().passes(), "8 轮不应在 1 字节字段溢出");
        assertEquals(8, meta.argon2Params().threads(), "8 线程不应在 1 字节字段溢出");
    }

    /**
     * 向后兼容：不透传档位（S1 之前的桌面行为）时 RESERVED 全零、参数解析为 null，
     * 提取侧回落默认 1 GiB 仍能逐字节还原。
     *
     * @param dir JUnit 提供的临时目录
     * @throws Exception 隐写或提取失败
     */
    @Test
    void backwardCompat_noOverrideRecordsNoParams(@TempDir Path dir) throws Exception {
        Path carrier = createZip(dir, "carrier.zip");
        Path secret = createSecret(dir, "secret.bin", 8 * 1024);
        Path stego = dir.resolve("stego.zip");

        codec.hide(carrier, secret, stego, PASSWORD,
                FileStegoOptions.builder().storeIntegrity(true).build(), null);

        assertNull(readCarrierMetadata(stego).argon2Params(),
                "无覆写时 RESERVED 应全零（解析为 null → 默认 1 GiB）");

        Path outDir = Files.createDirectories(dir.resolve("out"));
        Path extracted = codec.extract(stego, outDir, PASSWORD, mobileExtractOptions(), null);
        assertEquals(-1L, Files.mismatch(secret, extracted), "旧格式产物提取应逐字节一致");
    }

    /**
     * 跨端最小档：移动端 AUTO 兜底档（32 MiB / 2 / 2）隐写的产物，桌面端提取逐字节还原。
     *
     * @param dir JUnit 提供的临时目录
     * @throws Exception 隐写或提取失败
     */
    @Test
    void mobileAutoMinTierExtractedByDesktop(@TempDir Path dir) throws Exception {
        Path carrier = createPng(dir, "carrier.png");
        Path secret = createSecret(dir, "secret.bin", 16 * 1024);
        Path stego = dir.resolve("stego.png");

        codec.hide(carrier, secret, stego, PASSWORD,
                mobileHideOptions(MOBILE_AUTO_MIN, true), null);

        assertEquals(MOBILE_AUTO_MIN, readCarrierMetadata(stego).argon2Params(),
                "移动端兜底档应记录 32 MiB / 2 / 2");

        Path outDir = Files.createDirectories(dir.resolve("out"));
        Path extracted = codec.extract(stego, outDir, PASSWORD, desktopExtractOptions(), null);
        assertEquals(-1L, Files.mismatch(secret, extracted), "桌面端应能提取移动端产物");
    }

    // ==================== 真实数据 × 真实载体：跨端互通 ====================

    /**
     * 桌面端隐写 → 移动端提取：六种真实载体容器 × 桌面默认均衡档 × 真实秘密文件。
     *
     * <p>模拟 {@code FileStegoController.doHide}（S1 后透传 {@link Argon2DesktopMode}）
     * 产出，再以移动端 {@code StegoViewModel.extract} 的选项（低内存模式 + 大文件护栏）
     * 提取，断言载体元数据记录 256 MiB 档且产物逐字节一致。
     *
     * @throws Exception 隐写或提取失败
     */
    @Test
    void realCarriers_desktopHideMobileExtract() throws Exception {
        Path secret = prepareRealSecret();
        assumeTrue(secret != null, "缺少真实秘密文件（temp/test/原内容）");
        List<Path> carriers = realCarriers(Files.size(secret));
        assumeTrue(!carriers.isEmpty(), "缺少真实载体文件（temp/test/载体）");

        Argon2Params expected = new Argon2Params(
                Argon2DesktopMode.BALANCED.getMemoryKib(),
                Argon2DesktopMode.BALANCED.getPasses(),
                Argon2DesktopMode.BALANCED.getThreads());
        for (Path carrier : carriers) {
            boolean png = isPng(carrier);
            interop(carrier, secret, "desktop_balanced_to_mobile",
                    desktopHideOptions(Argon2DesktopMode.BALANCED, png),
                    mobileExtractOptions(), expected);
        }
    }

    /**
     * 移动端隐写 → 桌面端提取：六种真实载体容器 × 移动省电档（64 MiB）× 真实秘密文件。
     *
     * <p>模拟 {@code StegoScreen.doHide}（低内存模式 + 按载体决定 preferChunk +
     * 移动档位参数）产出，再以桌面端选项提取。
     *
     * @throws Exception 隐写或提取失败
     */
    @Test
    void realCarriers_mobileHideDesktopExtract() throws Exception {
        Path secret = prepareRealSecret();
        assumeTrue(secret != null, "缺少真实秘密文件（temp/test/原内容）");
        List<Path> carriers = realCarriers(Files.size(secret));
        assumeTrue(!carriers.isEmpty(), "缺少真实载体文件（temp/test/载体）");

        for (Path carrier : carriers) {
            boolean png = isPng(carrier);
            interop(carrier, secret, "mobile_light_to_desktop",
                    mobileHideOptions(MOBILE_LIGHT, png),
                    desktopExtractOptions(), MOBILE_LIGHT);
        }
    }

    /**
     * 大文件跨端互通：整份真实源文件（数百 MiB）藏入 ZIP 载体，桌面端隐写 → 移动端提取。
     *
     * <p>ZIP 适配器支持流式嵌入/提取，故移动端在低内存模式 + 64 MiB 护栏下仍允许处理；
     * 本用例验证「档位透传 + 流式路径」在真实大文件上的端到端正确性。
     *
     * @throws Exception 隐写或提取失败
     */
    @Test
    void realLargeFile_desktopHideMobileExtract() throws Exception {
        Path secret = smallestRealSource();
        assumeTrue(secret != null, "缺少真实源文件（temp/test/原内容）");
        Path zip = CARRIERS.resolve(findCarrierName(".zip"));
        assumeTrue(Files.isRegularFile(zip), "缺少 ZIP 真实载体");

        Argon2Params expected = new Argon2Params(
                Argon2DesktopMode.BALANCED.getMemoryKib(),
                Argon2DesktopMode.BALANCED.getPasses(),
                Argon2DesktopMode.BALANCED.getThreads());
        interop(zip, secret, "large_desktop_balanced_to_mobile",
                desktopHideOptions(Argon2DesktopMode.BALANCED, false),
                mobileExtractOptions(), expected);
    }

    /**
     * 高级选项跨端稳定性：偏执 / 隐蔽 / 完整性 / 混淆大小 / PNG 两种嵌入落点。
     *
     * <p>用真实 PNG 与 ZIP 载体 + 真实秘密文件，逐个组合验证「一端按该组合隐写、
     * 另一端按默认提取」仍能逐字节还原。所有组合统一用移动端可承受的 64 MiB 档位，
     * 以控制总时长（档位与选项正交，不影响结论）。
     *
     * @throws Exception 隐写或提取失败
     */
    @Test
    void realCarriers_advancedOptionsInterop() throws Exception {
        Path secret = prepareRealSecret();
        assumeTrue(secret != null, "缺少真实秘密文件（temp/test/原内容）");
        Path png = CARRIERS.resolve(findCarrierName(".png"));
        Path zip = CARRIERS.resolve(findCarrierName(".zip"));
        assumeTrue(Files.isRegularFile(png) && Files.isRegularFile(zip),
                "缺少 PNG / ZIP 真实载体");

        long padTarget = Files.size(png) + Files.size(secret) + (8L << 20);

        // 桌面端偏执 + 完整性（Serpent-CTR + HMAC-SHA3）→ 移动端提取
        interop(zip, secret, "adv_desktop_paranoid_integrity",
                FileStegoOptions.builder()
                        .paranoid(true)
                        .storeIntegrity(true)
                        .argon2Params(MOBILE_LIGHT)
                        .build(),
                mobileExtractOptions(), MOBILE_LIGHT);

        // 桌面端隐蔽模式（元数据魔数由密码派生）→ 移动端提取
        interop(zip, secret, "adv_desktop_stealth",
                FileStegoOptions.builder()
                        .stealth(true)
                        .storeIntegrity(true)
                        .argon2Params(MOBILE_LIGHT)
                        .build(),
                mobileExtractOptions(), MOBILE_LIGHT);

        // 桌面端 PNG「末尾追加」落点 → 移动端提取（移动端固定 stEG chunk，需能读两种）
        interop(png, secret, "adv_desktop_png_trailer",
                FileStegoOptions.builder()
                        .storeIntegrity(true)
                        .preferChunk(false)
                        .argon2Params(MOBILE_LIGHT)
                        .build(),
                mobileExtractOptions(), MOBILE_LIGHT);

        // 移动端 PNG「stEG chunk」落点 + 混淆大小 → 桌面端提取
        interop(png, secret, "adv_mobile_png_chunk_obfuscate",
                FileStegoOptions.builder()
                        .storeIntegrity(true)
                        .preferChunk(true)
                        .obfuscateSize(true)
                        .targetSizeBytes(padTarget)
                        .argon2Params(MOBILE_LIGHT)
                        .lowMemoryMode(true)
                        .lowMemoryThresholdBytes(MOBILE_THRESHOLD_BYTES)
                        .build(),
                desktopExtractOptions(), MOBILE_LIGHT);

        // 移动端隐蔽 + 完整性 + 均衡档（移动端 UI 开放的组合）→ 桌面端提取
        interop(zip, secret, "adv_mobile_stealth_integrity",
                FileStegoOptions.builder()
                        .storeIntegrity(true)
                        .stealth(true)
                        .argon2Params(MOBILE_BALANCED)
                        .lowMemoryMode(true)
                        .lowMemoryThresholdBytes(MOBILE_THRESHOLD_BYTES)
                        .build(),
                desktopExtractOptions(), MOBILE_BALANCED);
    }

    // ==================== 私有辅助 ====================

    /**
     * 执行一次「隐写 → 提取」互通验证，并把产物留在 {@link #OUT} 供真机复核。
     *
     * @param carrier        载体文件
     * @param secret         待隐藏的秘密文件
     * @param label          产物命名前缀（区分方向与选项组合）
     * @param hideOptions    隐写侧选项（模拟某一端的 UI 组装结果）
     * @param extractOptions 提取侧选项（模拟另一端的 UI 组装结果）
     * @param expectedParams 期望被记录进载体元数据的 Argon2 参数
     * @throws Exception 隐写或提取失败
     */
    private void interop(final Path carrier, final Path secret, final String label,
                         final FileStegoOptions hideOptions,
                         final FileStegoOptions extractOptions,
                         final Argon2Params expectedParams) throws Exception {
        String tag = label + "_" + stem(carrier) + extension(carrier);
        Path stego = OUT.resolve(tag);
        Files.createDirectories(OUT);
        codec.hide(carrier, secret, stego, PASSWORD, hideOptions, null);
        assertTrue(Files.size(stego) > 0, tag + " 应产出非空隐写文件");

        // 元数据探针会把整份 Payload 读出到临时文件，大文件用例跳过以免重复整份 I/O
        if (Files.size(stego) <= META_PROBE_LIMIT_BYTES) {
            CarrierMetadata meta = readCarrierMetadata(stego);
            assertEquals(expectedParams, meta.argon2Params(), tag + " 载体元数据应记录预期档位");
        }

        Path outDir = Files.createDirectories(OUT.resolve(label + "_out_" + stem(carrier)));
        Path extracted = codec.extract(stego, outDir, PASSWORD, extractOptions, null);
        assertEquals(secret.getFileName().toString(), extracted.getFileName().toString(),
                tag + " 应还原原始文件名");
        assertEquals(-1L, Files.mismatch(secret, extracted), tag + " 提取产物应与源逐字节一致");
    }

    /**
     * 构建桌面端隐写选项，模拟 S1 后的 {@code FileStegoController.doHide}。
     *
     * @param tier        桌面 KDF 档位
     * @param preferChunk PNG 是否使用 stEG chunk 落点
     * @return 桌面端隐写选项
     */
    private static FileStegoOptions desktopHideOptions(final Argon2DesktopMode tier,
                                                       final boolean preferChunk) {
        return FileStegoOptions.builder()
                .storeIntegrity(true)
                .preferChunk(preferChunk)
                .argon2Params(new Argon2Params(
                        tier.getMemoryKib(), tier.getPasses(), tier.getThreads()))
                .build();
    }

    /**
     * 构建移动端隐写选项，模拟 {@code StegoScreen.doHide}。
     *
     * @param tier        移动 KDF 档位参数
     * @param preferChunk PNG 载体固定 true、其他载体 false（移动端按扩展名内联决定）
     * @return 移动端隐写选项
     */
    private static FileStegoOptions mobileHideOptions(final Argon2Params tier,
                                                      final boolean preferChunk) {
        return FileStegoOptions.builder()
                .storeIntegrity(true)
                .preferChunk(preferChunk)
                .argon2Params(tier)
                .lowMemoryMode(true)
                .lowMemoryThresholdBytes(MOBILE_THRESHOLD_BYTES)
                .build();
    }

    /**
     * 构建桌面端提取选项（无低内存护栏）。
     *
     * @return 桌面端提取选项
     */
    private static FileStegoOptions desktopExtractOptions() {
        return FileStegoOptions.builder().build();
    }

    /**
     * 构建移动端提取选项，模拟 {@code StegoViewModel.extract}。
     *
     * @return 移动端提取选项
     */
    private static FileStegoOptions mobileExtractOptions() {
        return FileStegoOptions.builder()
                .lowMemoryMode(true)
                .lowMemoryThresholdBytes(MOBILE_THRESHOLD_BYTES)
                .build();
    }

    /**
     * 只读方式解析隐写产物的载体元数据（用于断言记录的 Argon2 档位）。
     *
     * @param stego 隐写产物
     * @return 解析出的载体元数据
     * @throws Exception 载体不可识别或元数据解析失败
     */
    private static CarrierMetadata readCarrierMetadata(final Path stego) throws Exception {
        CarrierAdapter adapter = CarrierRegistry.detectAdapter(stego)
                .orElseThrow(() -> new IllegalStateException("未检测到载体适配器: " + stego));
        Path probe = Files.createTempFile("ergou-stego-meta-probe-", ".tmp");
        try {
            return ((AbstractCarrierAdapter) adapter).extractFullToFile(stego, PASSWORD, probe);
        } finally {
            Files.deleteIfExists(probe);
        }
    }

    /**
     * 选出 {@code 原内容} 下体量最小的真实源文件。
     *
     * @return 真实源文件路径；目录缺失或无可用文件时返回 null
     * @throws Exception 目录遍历失败
     */
    private static Path smallestRealSource() throws Exception {
        if (!Files.isDirectory(SOURCES)) {
            return null;
        }
        try (var s = Files.list(SOURCES)) {
            return s.filter(Files::isRegularFile)
                    .min((a, b) -> Long.compare(sizeOf(a), sizeOf(b)))
                    .orElse(null);
        }
    }

    /**
     * 准备真实秘密文件：取最小真实源文件的前 {@link #SECRET_SLICE_BYTES} 字节。
     *
     * <p>真实源文件均为数百 MiB 量级，直接用于「六载体 × 双方向」矩阵会让单次
     * 回归耗时不可控，且超出 FLAC 载体 16 MiB 的容量上限；故取真实字节前缀作为
     * 秘密文件——内容仍是真实数据（保留原扩展名与非 ASCII 文件名，可覆盖
     * Payload 元数据的文件名往返），体量则可控。整文件互通另见
     * {@link #realLargeFile_desktopHideMobileExtract}。
     *
     * @return 真实秘密文件切片路径；无可用真实数据时返回 null
     * @throws Exception 读写失败
     */
    private static Path prepareRealSecret() throws Exception {
        Path src = smallestRealSource();
        if (src == null) {
            return null;
        }
        Files.createDirectories(SECRETS);
        String name = src.getFileName().toString();
        int dot = name.lastIndexOf('.');
        String base = dot >= 0 ? name.substring(0, dot) : name;
        String ext = dot >= 0 ? name.substring(dot) : "";
        Path out = SECRETS.resolve(base + ".片段" + (SECRET_SLICE_BYTES >> 20) + "MiB" + ext);
        long expect = Math.min(SECRET_SLICE_BYTES, Files.size(src));
        if (Files.isRegularFile(out) && Files.size(out) == expect) {
            return out;
        }
        try (InputStream in = Files.newInputStream(src);
             OutputStream o = Files.newOutputStream(out)) {
            byte[] buf = new byte[1 << 20];
            long remaining = expect;
            while (remaining > 0) {
                int n = in.read(buf, 0, (int) Math.min(buf.length, remaining));
                if (n < 0) {
                    break;
                }
                o.write(buf, 0, n);
                remaining -= n;
            }
        }
        return out;
    }

    /**
     * 读取文件大小，失败时返回 {@link Long#MAX_VALUE} 以便排序时靠后。
     *
     * @param p 文件路径
     * @return 字节数
     */
    private static long sizeOf(final Path p) {
        try {
            return Files.size(p);
        } catch (Exception e) {
            return Long.MAX_VALUE;
        }
    }

    /**
     * 列出可用于本次秘密文件体量的真实载体（按适配器容量过滤，避免必然失败的组合）。
     *
     * @param secretSize 秘密文件字节数
     * @return 可用载体列表（缺目录时为空）
     * @throws Exception 目录遍历失败
     */
    private static List<Path> realCarriers(final long secretSize) throws Exception {
        if (!Files.isDirectory(CARRIERS)) {
            return List.of();
        }
        List<Path> result = new ArrayList<>();
        try (var s = Files.list(CARRIERS)) {
            for (Path p : s.filter(Files::isRegularFile).sorted().toList()) {
                CarrierAdapter adapter = CarrierRegistry
                        .findByExtension(extension(p)).orElse(null);
                if (adapter == null) {
                    continue;
                }
                long capacity = adapter.capacity(p);
                if (capacity != Long.MAX_VALUE && secretSize > capacity) {
                    continue;
                }
                result.add(p);
            }
        }
        return result;
    }

    /**
     * 在载体目录中查找首个指定扩展名的文件名。
     *
     * @param ext 扩展名（含 "." 前缀）
     * @return 文件名；未找到返回一个不存在的占位名
     * @throws Exception 目录遍历失败
     */
    private static String findCarrierName(final String ext) throws Exception {
        if (!Files.isDirectory(CARRIERS)) {
            return "__missing__" + ext;
        }
        try (var s = Files.list(CARRIERS)) {
            return s.filter(Files::isRegularFile)
                    .map(p -> p.getFileName().toString())
                    .filter(n -> n.toLowerCase().endsWith(ext))
                    .sorted()
                    .findFirst()
                    .orElse("__missing__" + ext);
        }
    }

    /**
     * 判断载体是否为 PNG（移动端据此内联决定 preferChunk）。
     *
     * @param carrier 载体文件
     * @return true 表示 PNG 载体
     */
    private static boolean isPng(final Path carrier) {
        return ".png".equals(extension(carrier));
    }

    /**
     * 取文件扩展名（小写，含 "." 前缀）。
     *
     * @param p 文件路径
     * @return 扩展名；无扩展名返回空串
     */
    private static String extension(final Path p) {
        String name = p.getFileName().toString().toLowerCase();
        int dot = name.lastIndexOf('.');
        return dot >= 0 ? name.substring(dot) : "";
    }

    /**
     * 取文件主名并压成文件系统安全的短标识（保留非 ASCII 字符，仅去掉非法符号与空白）。
     *
     * @param p 文件路径
     * @return 短标识
     */
    private static String stem(final Path p) {
        String name = p.getFileName().toString();
        int dot = name.lastIndexOf('.');
        String base = dot >= 0 ? name.substring(0, dot) : name;
        String safe = base.replaceAll("[<>:\"/\\\\|?*\\s]+", "_");
        if (safe.isEmpty()) {
            safe = "carrier";
        }
        return safe.length() > 24 ? safe.substring(0, 24) : safe;
    }

    /**
     * 生成一张小尺寸有效 PNG 作为合成载体。
     *
     * @param dir  目录
     * @param name 文件名
     * @return PNG 路径
     * @throws Exception 写入失败
     */
    private static Path createPng(final Path dir, final String name) throws Exception {
        BufferedImage img = new BufferedImage(64, 64, BufferedImage.TYPE_INT_RGB);
        Random r = new Random(2026);
        for (int y = 0; y < 64; y++) {
            for (int x = 0; x < 64; x++) {
                img.setRGB(x, y, r.nextInt());
            }
        }
        Path p = dir.resolve(name);
        ImageIO.write(img, "PNG", p.toFile());
        return p;
    }

    /**
     * 生成一个含两个条目的有效 ZIP 作为合成载体。
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
            zos.write("ergou stego kdf tier carrier".getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();
            zos.putNextEntry(new ZipEntry("data/blob.bin"));
            zos.write(new byte[] {9, 8, 7, 6, 5, 4, 3, 2, 1});
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
