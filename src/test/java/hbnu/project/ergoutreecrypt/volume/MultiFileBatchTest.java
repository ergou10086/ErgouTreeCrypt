package hbnu.project.ergoutreecrypt.volume;

import hbnu.project.ergoutreecrypt.encoding.RsCodecs;
import hbnu.project.ergoutreecrypt.fileops.ArchiveExtractor;
import hbnu.project.ergoutreecrypt.fileops.Splitter;
import hbnu.project.ergoutreecrypt.settings.SettingsManager;
import net.lingala.zip4j.ZipFile;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 通用加密 / 解密的多文件批处理测试套件。
 *
 * <p>多文件按「同一个文件夹里的多个文件」处理：
 * <ul>
 *   <li>不打包：输出到 {@code 输出目录/批名/文件名.ergou}；</li>
 *   <li>压缩后加密：合并成单个归档后整体加密；</li>
 *   <li>加密后压缩：逐个加密后在临时目录暂存，再打成 {@code 输出目录/批名.扩展名}；</li>
 *   <li>分卷：每个文件各自成为碎片子文件夹。</li>
 * </ul>
 *
 * <p>同时锁定「不可处理条目跳过并汇报」「进度单调收敛到 100%」「已选源文件不被改动」
 * 这三条批处理契约。使用低 Argon2 参数保证秒级完成。
 *
 * @author ErgouTree
 */
final class MultiFileBatchTest {

    /**
     * 测试用 Argon2 内存参数（KiB）。
     */
    private static final int FAST_MEMORY_KIB = 32;

    /**
     * 测试用 Argon2 迭代次数。
     */
    private static final int FAST_PASSES = 1;

    /**
     * 测试用 Argon2 并行度。
     */
    private static final int FAST_THREADS = 1;

    private static RsCodecs rs;

    /** 测试前保存的「工具特有加密」开关，用于还原。 */
    private static boolean savedCustomEnc;

    /** 测试前保存的「归档密码回退」开关，用于还原。 */
    private static boolean savedFallback;

    @BeforeAll
    static void setUp() {
        rs = new RsCodecs();
        savedCustomEnc = SettingsManager.isArchiveCustomEncryption();
        savedFallback = SettingsManager.isArchivePasswordFallback();
        SettingsManager.setArchiveCustomEncryption(true);
        SettingsManager.setArchivePasswordFallback(false);
    }

    @AfterAll
    static void tearDown() {
        SettingsManager.setArchiveCustomEncryption(savedCustomEnc);
        SettingsManager.setArchivePasswordFallback(savedFallback);
    }

    // ================================================================
    // A. 仅加密：扁平输出到 批名/ 目录
    // ================================================================

    /**
     * 三个文件各自加密为 {@code 批名/文件名.ergou}，源文件保持原样。
     */
    @Test
    void batchEncryptWithoutArchive(@TempDir Path tempDir) throws Exception {
        Path src = tempDir.resolve("src");
        Files.createDirectories(src);
        byte[] d1 = rand(6 * 1024, 1);
        byte[] d2 = rand(8 * 1024, 2);
        byte[] d3 = rand(5 * 1024, 3);
        Path f1 = src.resolve("1.mp3");
        Path f2 = src.resolve("2.mp3");
        Path f3 = src.resolve("3.mp3");
        Files.write(f1, d1);
        Files.write(f2, d2);
        Files.write(f3, d3);

        Path out = tempDir.resolve("out");
        FolderCrypt.EncryptOptions opts = options("multi-pw");
        opts.batchName = "music";
        FolderCrypt.encryptFiles(List.of(f1, f2, f3), out, opts);

        Path resultDir = out.resolve("music");
        assertEquals(List.of("1.mp3.ergou", "2.mp3.ergou", "3.mp3.ergou"),
                listNames(resultDir));
        assertNotNull(opts.batchResult);
        assertEquals(3, opts.batchResult.succeededCount());
        assertEquals(0, opts.batchResult.failedCount());

        // 源文件不得被改动
        assertArrayEquals(d1, Files.readAllBytes(f1));
        assertEquals(List.of("1.mp3", "2.mp3", "3.mp3"), listNames(src));

        // 整目录解密还原
        Path decOut = tempDir.resolve("dec");
        Files.createDirectories(decOut);
        FolderCrypt.DecryptOptions dop = new FolderCrypt.DecryptOptions();
        dop.password = "multi-pw";
        dop.rsCodecs = rs;
        FolderCrypt.decryptAuto(resultDir, decOut, dop);
        assertArrayEquals(d1, Files.readAllBytes(decOut.resolve("music/1.mp3")));
        assertArrayEquals(d2, Files.readAllBytes(decOut.resolve("music/2.mp3")));
        assertArrayEquals(d3, Files.readAllBytes(decOut.resolve("music/3.mp3")));
    }

    /**
     * 批名缺省时回退为 {@code files}，避免产出无名的输出目录。
     */
    @Test
    void batchNameFallsBackToDefault(@TempDir Path tempDir) throws Exception {
        Path src = tempDir.resolve("s");
        Files.createDirectories(src);
        Path f = src.resolve("a.bin");
        Files.write(f, rand(1024, 4));

        Path out = tempDir.resolve("out");
        FolderCrypt.EncryptOptions opts = options("pw");
        opts.batchName = null;
        FolderCrypt.encryptFiles(List.of(f), out, opts);

        assertTrue(Files.isDirectory(out.resolve("files")), "批名为空时应回退为 files");
    }

    /**
     * 分卷：每个文件各自成为一个碎片子文件夹。
     */
    @Test
    void batchEncryptWithSplit(@TempDir Path tempDir) throws Exception {
        Path src = tempDir.resolve("s");
        Files.createDirectories(src);
        byte[] big = rand(3 * 1024 * 1024, 5);
        byte[] small = rand(100 * 1024, 6);
        Path f1 = src.resolve("big.bin");
        Path f2 = src.resolve("small.bin");
        Files.write(f1, big);
        Files.write(f2, small);

        Path out = tempDir.resolve("out");
        FolderCrypt.EncryptOptions opts = options("split-pw");
        opts.batchName = "bundle";
        opts.split = true;
        opts.chunkSize = 1;
        FolderCrypt.encryptFiles(List.of(f1, f2), out, opts);

        Path chunkDir = out.resolve("bundle/big.bin");
        assertTrue(Files.isDirectory(chunkDir), "分卷时应生成同名碎片夹");
        assertTrue(listNames(chunkDir).size() > 1, "大文件应切出多个碎片");
        // 小文件不足一卷，仍应有碎片
        assertTrue(Files.isDirectory(out.resolve("bundle/small.bin")));

        Path decOut = tempDir.resolve("dec");
        Files.createDirectories(decOut);
        FolderCrypt.DecryptOptions dop = new FolderCrypt.DecryptOptions();
        dop.password = "split-pw";
        dop.rsCodecs = rs;
        FolderCrypt.decryptAuto(out.resolve("bundle"), decOut, dop);
        assertArrayEquals(big, Files.readAllBytes(decOut.resolve("bundle/big.bin")));
        assertArrayEquals(small, Files.readAllBytes(decOut.resolve("bundle/small.bin")));
    }

    // ================================================================
    // B. 加密后压缩：只打包密文，源文件不动
    // ================================================================

    /**
     * 多文件 + 加密后压缩：产物为单个 {@code 批名.zip}，其中只有密文条目，
     * 且被选中的源文件一个都不能少、一个都不能变。
     */
    @Test
    void batchEncryptWithPostArchive(@TempDir Path tempDir) throws Exception {
        Path src = tempDir.resolve("s");
        Files.createDirectories(src);
        byte[] d1 = rand(4 * 1024, 11);
        byte[] d2 = rand(7 * 1024, 12);
        Path f1 = src.resolve("alpha.txt");
        Path f2 = src.resolve("beta.dat");
        Files.write(f1, d1);
        Files.write(f2, d2);

        Path out = tempDir.resolve("out");
        FolderCrypt.EncryptOptions opts = options("post-pw");
        opts.batchName = "bundle";
        opts.archiveFormat = "ZIP";
        FolderCrypt.encryptFiles(List.of(f1, f2), out, opts);

        Path archive = out.resolve("bundle.zip");
        assertTrue(Files.exists(archive), "应产出 bundle.zip");
        assertEquals(List.of("bundle.zip"), listNames(out), "不得残留临时暂存目录");

        try (ZipFile zf = new ZipFile(archive.toFile())) {
            List<String> entries = zf.getFileHeaders().stream()
                    .map(h -> h.getFileName().replace('\\', '/'))
                    .sorted()
                    .toList();
            assertEquals(List.of("alpha.txt.ergou", "beta.dat.ergou"), entries,
                    "压缩包内只能有密文条目");
            assertFalse(zf.isEncrypted(), "未填归档密码时压缩包不应加密");
        }

        // 源文件完好
        assertArrayEquals(d1, Files.readAllBytes(f1));
        assertArrayEquals(d2, Files.readAllBytes(f2));
        assertEquals(List.of("alpha.txt", "beta.dat"), listNames(src));

        // 解密还原
        Path decOut = tempDir.resolve("dec");
        Files.createDirectories(decOut);
        FolderCrypt.DecryptOptions dop = new FolderCrypt.DecryptOptions();
        dop.password = "post-pw";
        dop.rsCodecs = rs;
        FolderCrypt.decryptAuto(archive, decOut, dop);
        assertArrayEquals(d1, Files.readAllBytes(decOut.resolve("bundle/alpha.txt")));
        assertArrayEquals(d2, Files.readAllBytes(decOut.resolve("bundle/beta.dat")));
    }

    /**
     * 加密后压缩 + 归档密码：压缩包受保护，源文件不动。
     */
    @Test
    void batchEncryptWithPostArchivePassword(@TempDir Path tempDir) throws Exception {
        Path src = tempDir.resolve("s");
        Files.createDirectories(src);
        Path f = src.resolve("x.bin");
        byte[] data = rand(2048, 21);
        Files.write(f, data);

        Path out = tempDir.resolve("out");
        FolderCrypt.EncryptOptions opts = options("file-pw");
        opts.batchName = "pack";
        opts.archiveFormat = "ZIP";
        opts.archivePassword = "zip-pw";
        FolderCrypt.encryptFiles(List.of(f), out, opts);

        try (ZipFile zf = new ZipFile(out.resolve("pack.zip").toFile())) {
            assertTrue(zf.isEncrypted(), "填了归档密码时压缩包应加密");
        }
        assertArrayEquals(data, Files.readAllBytes(f));
    }

    /**
     * 多文件 + Zstandard 加密前压缩：解密后内容逐字节还原。
     */
    @Test
    void batchEncryptWithZstdCompression(@TempDir Path tempDir) throws Exception {
        Path src = tempDir.resolve("s");
        Files.createDirectories(src);
        byte[] compressible = compressible(200 * 1024);
        Path f = src.resolve("data.bin");
        Files.write(f, compressible);

        Path out = tempDir.resolve("out");
        FolderCrypt.EncryptOptions opts = options("zstd-pw");
        opts.batchName = "z";
        opts.compress = true;
        opts.compressionLevel = 3;
        FolderCrypt.encryptFiles(List.of(f), out, opts);

        Path enc = out.resolve("z/data.bin.ergou");
        assertTrue(Files.exists(enc));

        Path decOut = tempDir.resolve("dec");
        Files.createDirectories(decOut);
        FolderCrypt.DecryptOptions dop = new FolderCrypt.DecryptOptions();
        dop.password = "zstd-pw";
        dop.rsCodecs = rs;
        FolderCrypt.decryptAuto(out.resolve("z"), decOut, dop);
        assertArrayEquals(compressible, Files.readAllBytes(decOut.resolve("z/data.bin")));
    }

    // ================================================================
    // C. 不可处理条目：跳过并在批结果中汇报
    // ================================================================

    /**
     * 不存在的路径与目录应被跳过并记入失败列表，其余文件照常处理。
     */
    @Test
    void batchSkipsUnprocessableEntriesAndReports(@TempDir Path tempDir) throws Exception {
        Path src = tempDir.resolve("s");
        Files.createDirectories(src);
        Path good = src.resolve("good.bin");
        byte[] data = rand(2048, 31);
        Files.write(good, data);
        Path missing = src.resolve("does-not-exist.bin");
        Path aDir = src.resolve("subdir");
        Files.createDirectories(aDir);
        Files.write(aDir.resolve("inner.bin"), rand(512, 32));

        Path out = tempDir.resolve("out");
        FolderCrypt.EncryptOptions opts = options("skip-pw");
        opts.batchName = "mixed";
        FolderCrypt.encryptFiles(List.of(good, missing, aDir), out, opts);

        BatchResult result = opts.batchResult;
        assertNotNull(result);
        assertEquals(1, result.succeededCount(), "只有常规文件应被加密");
        assertEquals(2, result.failedCount(), "不存在的路径与目录都应记入失败");
        assertTrue(result.hasFailures());

        List<String> failedNames = result.failures().stream()
                .map(BatchResult.Failure::name).sorted().toList();
        assertEquals(List.of("does-not-exist.bin", "subdir"), failedNames);
        result.failures().forEach(f ->
                assertFalse(f.message().isBlank(), "失败原因不应为空白"));

        assertTrue(Files.exists(out.resolve("mixed/good.bin.ergou")));
        assertArrayEquals(data, Files.readAllBytes(good));
    }

    /**
     * 全部条目都不可处理时应直接失败，而不是静默产出空目录。
     */
    @Test
    void batchAllUnprocessableFails(@TempDir Path tempDir) throws Exception {
        Path out = tempDir.resolve("out");
        FolderCrypt.EncryptOptions opts = options("pw");
        opts.batchName = "none";
        Path dir = tempDir.resolve("just-a-dir");
        Files.createDirectories(dir);

        assertThrows(Exception.class,
                () -> FolderCrypt.encryptFiles(List.of(dir), out, opts));
        assertFalse(Files.exists(out.resolve("none")), "失败时不得留下空产物目录");
    }

    // ================================================================
    // D. 进度：单调不减、阶段正确、最终收敛到 100%
    // ================================================================

    /**
     * 批处理进度必须单调不减并最终到达 100%，且加密阶段出现过 CRYPTO 进度。
     */
    @Test
    void batchProgressIsMonotonicAndReachesCompletion(@TempDir Path tempDir) throws Exception {
        Path src = tempDir.resolve("s");
        Files.createDirectories(src);
        List<Path> files = new ArrayList<>();
        for (int i = 0; i < 4; i++) {
            Path f = src.resolve("f" + i + ".bin");
            Files.write(f, rand(3 * 1024, 100 + i));
            files.add(f);
        }

        RecordingReporter reporter = new RecordingReporter();
        Path out = tempDir.resolve("out");
        FolderCrypt.EncryptOptions opts = options("prog-pw");
        opts.batchName = "prog";
        opts.reporter = reporter;
        opts.threadCount = 2;
        FolderCrypt.encryptFiles(files, out, opts);

        assertTrue(reporter.fractions.size() > 0, "应至少上报一次进度");
        float last = -1f;
        for (float f : reporter.fractions) {
            assertTrue(f >= last - 1e-6, "进度不得回退：" + reporter.fractions);
            assertTrue(f >= 0f && f <= 1f, "进度应在 [0,1]：" + reporter.fractions);
            last = f;
        }
        assertEquals(1f, reporter.maxFraction(), 1e-6, "最终应到达 100%");
        assertTrue(reporter.phases.contains(ProgressPhase.CRYPTO),
                "加密阶段应被上报过：" + reporter.phases);
        assertFalse(reporter.archivingSeen, "未勾选归档时不应出现归档阶段进度");
    }

    /**
     * 加密后压缩时，归档阶段应单独出现在进度阶段序列里。
     */
    @Test
    void batchArchivePhaseIsReported(@TempDir Path tempDir) throws Exception {
        Path src = tempDir.resolve("s");
        Files.createDirectories(src);
        Path f = src.resolve("a.bin");
        Files.write(f, rand(64 * 1024, 41));

        RecordingReporter reporter = new RecordingReporter();
        Path out = tempDir.resolve("out");
        FolderCrypt.EncryptOptions opts = options("phase-pw");
        opts.batchName = "ph";
        opts.archiveFormat = "ZIP";
        opts.reporter = reporter;
        FolderCrypt.encryptFiles(List.of(f), out, opts);

        assertTrue(reporter.archivingSeen, "应上报过归档阶段的进度");
        assertEquals(1f, reporter.maxFraction(), 1e-6);
    }

    // ================================================================
    // E. 多文件解密
    // ================================================================

    /**
     * 多个加密卷一次解密：产物平铺到输出目录，成功计数正确。
     */
    @Test
    void decryptFilesRestoresEachVolume(@TempDir Path tempDir) throws Exception {
        Path src = tempDir.resolve("s");
        Files.createDirectories(src);
        byte[] d1 = rand(2048, 51);
        byte[] d2 = rand(3072, 52);
        Path f1 = src.resolve("one.txt");
        Path f2 = src.resolve("two.txt");
        Files.write(f1, d1);
        Files.write(f2, d2);

        Path encOut = tempDir.resolve("enc");
        FolderCrypt.EncryptOptions eo = options("dec-pw");
        eo.batchName = "v";
        FolderCrypt.encryptFiles(List.of(f1, f2), encOut, eo);
        Path v1 = encOut.resolve("v/one.txt.ergou");
        Path v2 = encOut.resolve("v/two.txt.ergou");
        assertTrue(Files.exists(v1));
        assertTrue(Files.exists(v2));

        Path decOut = tempDir.resolve("dec");
        FolderCrypt.DecryptOptions dop = new FolderCrypt.DecryptOptions();
        dop.password = "dec-pw";
        dop.rsCodecs = rs;
        FolderCrypt.decryptFiles(List.of(v1, v2), decOut, dop);

        assertArrayEquals(d1, Files.readAllBytes(decOut.resolve("one.txt")));
        assertArrayEquals(d2, Files.readAllBytes(decOut.resolve("two.txt")));
        assertNotNull(dop.batchResult);
        assertEquals(2, dop.batchResult.succeededCount());
        assertEquals(0, dop.batchResult.failedCount());
    }

    /**
     * 同属一个卷的多个分卷碎片一起选中时，只合并解密一次，不重复产出。
     */
    @Test
    void decryptFilesRecombinesEachChunkedVolumeOnce(@TempDir Path tempDir) throws Exception {
        Path src = tempDir.resolve("s");
        Files.createDirectories(src);
        byte[] data = rand(3 * 1024 * 1024, 61);
        Path f = src.resolve("big.bin");
        Files.write(f, data);

        Path encOut = tempDir.resolve("enc");
        FolderCrypt.EncryptOptions eo = options("chunk-pw");
        eo.batchName = "c";
        eo.split = true;
        eo.chunkSize = 1;
        FolderCrypt.encryptFiles(List.of(f), encOut, eo);

        Path chunkDir = encOut.resolve("c/big.bin");
        assertTrue(Files.isDirectory(chunkDir));
        List<Path> chunks = listPaths(chunkDir);
        assertTrue(chunks.size() > 1);

        // 用户把全部碎片一起拖进来
        Path decOut = tempDir.resolve("dec");
        FolderCrypt.DecryptOptions dop = new FolderCrypt.DecryptOptions();
        dop.password = "chunk-pw";
        dop.rsCodecs = rs;
        FolderCrypt.decryptFiles(chunks, decOut, dop);

        assertArrayEquals(data, Files.readAllBytes(decOut.resolve("big.bin")));
        assertEquals(1, dop.batchResult.succeededCount(),
                "同一卷的多个碎片应只算一次成功");
    }

    /**
     * 混入不可解密文件时：失败被记录，其余正常解密。
     */
    @Test
    void decryptFilesSkipsUndecryptableAndKeepsGoing(@TempDir Path tempDir) throws Exception {
        Path src = tempDir.resolve("s");
        Files.createDirectories(src);
        byte[] d1 = rand(1500, 71);
        Path f1 = src.resolve("ok.txt");
        Files.write(f1, d1);

        Path encOut = tempDir.resolve("enc");
        FolderCrypt.EncryptOptions eo = options("mix-pw");
        eo.batchName = "m";
        FolderCrypt.encryptFiles(List.of(f1), encOut, eo);
        Path volume = encOut.resolve("m/ok.txt.ergou");

        Path noise = tempDir.resolve("not-encrypted.txt");
        Files.write(noise, "plain text".getBytes());

        Path decOut = tempDir.resolve("dec");
        FolderCrypt.DecryptOptions dop = new FolderCrypt.DecryptOptions();
        dop.password = "mix-pw";
        dop.rsCodecs = rs;
        FolderCrypt.decryptFiles(List.of(volume, noise), decOut, dop);

        assertArrayEquals(d1, Files.readAllBytes(decOut.resolve("ok.txt")));
        assertNotNull(dop.batchResult);
        assertEquals(1, dop.batchResult.succeededCount());
        assertEquals(1, dop.batchResult.failedCount(), "不可解密文件应被记为失败");
        assertTrue(dop.batchResult.failures().getFirst().name().contains("not-encrypted"));
    }

    /**
     * 全部输入都不可解密时应抛出明确的失败，而不是静默返回。
     */
    @Test
    void decryptFilesAllUnusableThrows(@TempDir Path tempDir) throws Exception {
        Path noise = tempDir.resolve("noise.bin");
        Files.write(noise, rand(256, 81));
        Path decOut = tempDir.resolve("dec");

        FolderCrypt.DecryptOptions dop = new FolderCrypt.DecryptOptions();
        dop.password = "pw";
        dop.rsCodecs = rs;
        assertThrows(FolderCrypt.NoDecryptableFilesException.class,
                () -> FolderCrypt.decryptFiles(List.of(noise), decOut, dop));
    }

    // ================================================================
    // F. 归档条目名去重
    // ================================================================

    /**
     * 同名条目应被追加序号去重，避免解压时互相覆盖。
     */
    @Test
    void uniqueEntryNamesDeduplicates(@TempDir Path tempDir) throws Exception {
        Path a = tempDir.resolve("A/same.txt");
        Path b = tempDir.resolve("B/same.txt");
        Files.createDirectories(a.getParent());
        Files.createDirectories(b.getParent());
        Files.write(a, new byte[]{1});
        Files.write(b, new byte[]{2});

        List<String> names = hbnu.project.ergoutreecrypt.fileops.ArchivePacker
                .uniqueEntryNames(null, List.of(a, b));
        assertEquals(List.of("same.txt", "same (2).txt"), names);
    }

    /**
     * 目录结构与无扩展名的条目都能得到合理名字。
     */
    @Test
    void uniqueEntryNamesKeepsDirectoryStructure(@TempDir Path tempDir) throws Exception {
        Path root = tempDir.resolve("root");
        Path nested = root.resolve("sub/noext");
        Files.createDirectories(nested.getParent());
        Files.write(nested, new byte[]{3});
        Files.write(root.resolve("top.bin"), new byte[]{4});

        List<String> names = hbnu.project.ergoutreecrypt.fileops.ArchivePacker
                .uniqueEntryNames(root, List.of(nested, root.resolve("top.bin")));
        assertEquals(List.of("sub/noext", "top.bin"), names);
    }

    // ================================================================
    // 辅助方法
    // ================================================================

    /**
     * 构造低资源占用的多文件加密选项。
     *
     * @param password 加密密码
     * @return 选项对象
     */
    private static FolderCrypt.EncryptOptions options(String password) {
        FolderCrypt.EncryptOptions opts = new FolderCrypt.EncryptOptions();
        opts.password = password;
        opts.rsCodecs = rs;
        opts.threadCount = 1;
        opts.argon2MemoryKib = FAST_MEMORY_KIB;
        opts.argon2Passes = FAST_PASSES;
        opts.argon2Threads = FAST_THREADS;
        return opts;
    }

    /**
     * 列出目录下直接子项的名字（排序后）。
     *
     * @param dir 目录
     * @return 排序后的名字列表
     * @throws IOException 列目录失败
     */
    private static List<String> listNames(Path dir) throws IOException {
        try (Stream<Path> children = Files.list(dir)) {
            return children.map(p -> p.getFileName().toString()).sorted().toList();
        }
    }

    /**
     * 列出目录下直接子项的路径（排序后）。
     *
     * @param dir 目录
     * @return 排序后的路径列表
     * @throws IOException 列目录失败
     */
    private static List<Path> listPaths(Path dir) throws IOException {
        try (Stream<Path> children = Files.list(dir)) {
            return children.sorted().toList();
        }
    }

    /**
     * 生成确定性伪随机数据。
     *
     * @param n    字节数
     * @param seed 种子
     * @return 数据
     */
    private static byte[] rand(int n, int seed) {
        byte[] b = new byte[n];
        new java.util.Random(seed).nextBytes(b);
        return b;
    }

    /**
     * 生成高冗余、易压缩的确定性数据。
     *
     * @param n 字节数
     * @return 数据
     */
    private static byte[] compressible(int n) {
        byte[] b = new byte[n];
        for (int i = 0; i < n; i++) {
            b[i] = (byte) (i % 16);
        }
        return b;
    }

    /**
     * 记录进度回调轨迹的测试用 reporter。
     */
    private static final class RecordingReporter implements ProgressReporter {

        /** 每次上报的进度比例，按上报顺序记录。 */
        private final List<Float> fractions = new ArrayList<>();

        /** 出现过的进度阶段。 */
        private final List<ProgressPhase> phases = new ArrayList<>();

        /** 是否出现过归档阶段的进度上报。 */
        private boolean archivingSeen;

        @Override
        public void setStatus(String text) {
            // 状态文案不参与断言
        }

        @Override
        public void setStatus(String text, ProgressPhase phase) {
            phases.add(phase);
            if (phase == ProgressPhase.ARCHIVE) {
                archivingSeen = true;
            }
        }

        @Override
        public void setProgress(float fraction, String info) {
            fractions.add(fraction);
        }

        @Override
        public void setProgress(float fraction, String info, ProgressPhase phase) {
            fractions.add(fraction);
            phases.add(phase);
            if (phase == ProgressPhase.ARCHIVE) {
                archivingSeen = true;
            }
        }

        @Override
        public void setCanCancel(boolean can) {
            // 不参与断言
        }

        @Override
        public boolean isCancelled() {
            return false;
        }

        /**
         * @return 记录到的最大进度比例
         */
        float maxFraction() {
            float max = 0f;
            for (float f : fractions) {
                max = Math.max(max, f);
            }
            return max;
        }
    }

    /**
     * 递归删除目录树（供需要时手动清理）。
     *
     * @param dir 目录
     */
    @SuppressWarnings("unused")
    private static void rmrf(Path dir) {
        if (!Files.exists(dir)) {
            return;
        }
        try (Stream<Path> w = Files.walk(dir)) {
            w.sorted(Comparator.reverseOrder()).forEach(p -> {
                try {
                    Files.deleteIfExists(p);
                } catch (IOException ignored) {
                    // 清理失败不影响测试结论
                }
            });
        } catch (IOException ignored) {
            // 清理失败不影响测试结论
        }
    }

    /**
     * 断言某个路径可被 {@link Splitter} 识别为分卷碎片（保留给未来用例）。
     *
     * @param path 路径
     * @return 是否识别为碎片
     */
    @SuppressWarnings("unused")
    private static boolean isChunk(String path) {
        return Splitter.isSplitChunkPath(path);
    }

    /**
     * 断言某个归档可被识别（保留给未来用例）。
     *
     * @param path 路径
     * @return 是否识别为归档
     */
    @SuppressWarnings("unused")
    private static boolean isArchive(Path path) {
        return ArchiveExtractor.isArchive(path);
    }
}
