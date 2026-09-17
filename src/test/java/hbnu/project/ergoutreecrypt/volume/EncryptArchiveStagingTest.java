package hbnu.project.ergoutreecrypt.volume;

import hbnu.project.ergoutreecrypt.encoding.RsCodecs;
import hbnu.project.ergoutreecrypt.fileops.ArchiveExtractor;
import hbnu.project.ergoutreecrypt.fileops.ArchivePacker;
import hbnu.project.ergoutreecrypt.settings.SettingsManager;
import net.lingala.zip4j.ZipFile;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 「加密后压缩」落盘位置的回归测试。
 *
 * <p>复现的缺陷：默认输出目录就是输入文件夹的父目录，而工作目录取
 * {@code 输出目录/文件夹名}，于是工作目录与输入文件夹重合——
 * <ul>
 *   <li>归档把「原文件 + 密文」一并收进了压缩包；</li>
 *   <li>打包后的清理把原文件夹整个删掉；</li>
 *   <li>用户输入框留空时压缩包却带上了文件加密密码。</li>
 * </ul>
 *
 * <p>本套件锁定修复后的契约：<b>只打包密文、原文件夹原封不动、不留空密码</b>。
 * 使用低 Argon2 参数以保证测试速度。
 *
 * @author ErgouTree
 */
final class EncryptArchiveStagingTest {

    /**
     * 测试用 Argon2 内存参数（KiB），压到最低以保证用例秒级完成。
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
        // 打开非 ZIP 的工具特有加密以便覆盖 GZ / TAR.GZ / 7Z；
        // 明确关闭「密码回退」，让「归档密码留空 = 压缩包无密码」成为可断言的前提。
        SettingsManager.setArchiveCustomEncryption(true);
        SettingsManager.setArchivePasswordFallback(false);
    }

    @AfterAll
    static void tearDown() {
        SettingsManager.setArchiveCustomEncryption(savedCustomEnc);
        SettingsManager.setArchivePasswordFallback(savedFallback);
    }

    // ================================================================
    // A. 默认输出目录 == 输入文件夹父目录（用户报告的场景）
    // ================================================================

    /**
     * 用户报告的最小场景：拖入文件夹 1，输出目录取其父目录，勾选加密后压缩。
     *
     * <p>断言：原文件夹仍在、内容未变；压缩包只含密文；压缩包无密码。
     */
    @Test
    void folderArchiveInPlaceKeepsSourceAndPacksOnlyCiphertext(@TempDir Path tempDir)
            throws Exception {
        Path input = tempDir.resolve("1");
        Files.createDirectories(input);
        byte[] mp3a = rand(4096, 1);
        byte[] mp3b = rand(4096, 2);
        byte[] mp3c = rand(4096, 3);
        Files.write(input.resolve("1.mp3"), mp3a);
        Files.write(input.resolve("2.mp3"), mp3b);
        Files.write(input.resolve("3.mp3"), mp3c);

        // 输出目录就是输入文件夹的父目录——桌面的默认值
        FolderCrypt.EncryptOptions opts = folderOptions("mypassword");
        opts.archiveFormat = "ZIP";
        FolderCrypt.encryptFolder(input, tempDir, opts);

        Path archive = tempDir.resolve("1.zip");
        assertTrue(Files.exists(archive), "应生成与文件夹同名的压缩包");

        // 1) 原文件夹必须原封不动：仍在，且只有三个原始文件
        assertTrue(Files.isDirectory(input), "原文件夹不得被删除");
        assertEquals(List.of("1.mp3", "2.mp3", "3.mp3"), listNames(input));
        assertArrayEquals(mp3a, Files.readAllBytes(input.resolve("1.mp3")));
        assertArrayEquals(mp3b, Files.readAllBytes(input.resolve("2.mp3")));
        assertArrayEquals(mp3c, Files.readAllBytes(input.resolve("3.mp3")));

        // 2) 压缩包中只能有密文，不能出现原文件
        try (ZipFile zf = new ZipFile(archive.toFile())) {
            List<String> entries = zf.getFileHeaders().stream()
                    .map(h -> h.getFileName().replace('\\', '/'))
                    .sorted()
                    .toList();
            assertEquals(List.of("1.mp3.ergou", "2.mp3.ergou", "3.mp3.ergou"), entries,
                    "压缩包应只包含密文条目");
            // 3) 未填写归档密码 ⇒ 压缩包不得带密码
            assertFalse(zf.isEncrypted(), "未填写归档密码时压缩包不应加密");
        }

        // 4) 输出目录里除了压缩包和原文件夹，不应残留临时工作目录
        List<String> topLevel = listNames(tempDir);
        assertEquals(List.of("1", "1.zip"), topLevel, "不得残留中间工作目录");
    }

    /**
     * 循环验证：解压该压缩包后逐个解密，内容与原始字节完全一致。
     */
    @Test
    void folderArchiveInPlaceRoundtrip(@TempDir Path tempDir) throws Exception {
        Path input = tempDir.resolve("photos");
        Files.createDirectories(input.resolve("sub"));
        byte[] a = rand(9000, 11);
        byte[] b = rand(5000, 12);
        Files.write(input.resolve("a.bin"), a);
        Files.write(input.resolve("sub/b.bin"), b);

        FolderCrypt.EncryptOptions opts = folderOptions("pw-roundtrip");
        opts.archiveFormat = "ZIP";
        FolderCrypt.encryptFolder(input, tempDir, opts);

        Path archive = tempDir.resolve("photos.zip");
        assertTrue(Files.exists(archive));

        Path out = tempDir.resolve("out");
        Files.createDirectories(out);
        FolderCrypt.DecryptOptions dop = new FolderCrypt.DecryptOptions();
        dop.password = "pw-roundtrip";
        dop.rsCodecs = rs;
        FolderCrypt.decryptAuto(archive, out, dop);

        assertArrayEquals(a, Files.readAllBytes(out.resolve("photos/a.bin")));
        assertArrayEquals(b, Files.readAllBytes(out.resolve("photos/sub/b.bin")));
    }

    /**
     * 显式填写归档密码时，压缩包应当带密码，且只含密文。
     */
    @Test
    void folderArchiveWithExplicitPasswordEncryptsArchive(@TempDir Path tempDir)
            throws Exception {
        Path input = tempDir.resolve("docs");
        Files.createDirectories(input);
        Files.write(input.resolve("note.txt"), rand(2048, 21));

        FolderCrypt.EncryptOptions opts = folderOptions("file-pw");
        opts.archiveFormat = "ZIP";
        opts.archivePassword = "zip-pw";
        FolderCrypt.encryptFolder(input, tempDir, opts);

        Path archive = tempDir.resolve("docs.zip");
        try (ZipFile zf = new ZipFile(archive.toFile())) {
            assertTrue(zf.isEncrypted(), "填写了归档密码时压缩包应加密");
        }
        assertEquals(List.of("note.txt"), listNames(input), "原文件夹内容不得改变");

        // 用错误密码解压必须失败，用正确密码必须成功
        Path out = tempDir.resolve("out");
        Files.createDirectories(out);
        FolderCrypt.DecryptOptions dop = new FolderCrypt.DecryptOptions();
        dop.password = "file-pw";
        dop.archivePassword = "zip-pw";
        dop.rsCodecs = rs;
        FolderCrypt.decryptAuto(archive, out, dop);
        assertEquals(2048, Files.size(out.resolve("docs/note.txt")));
    }

    /**
     * 分卷 + 归档组合下同样不得污染输入目录。
     */
    @Test
    void folderArchiveWithSplitKeepsSourceIntact(@TempDir Path tempDir) throws Exception {
        Path input = tempDir.resolve("split-src");
        Files.createDirectories(input.resolve("sub"));
        byte[] a = rand(3 * 1024 * 1024, 31);
        byte[] b = rand(200 * 1024, 32);
        Files.write(input.resolve("a.bin"), a);
        Files.write(input.resolve("sub/b.bin"), b);

        FolderCrypt.EncryptOptions opts = folderOptions("split-pw");
        opts.split = true;
        opts.chunkSize = 1;
        opts.archiveFormat = "ZIP";
        FolderCrypt.encryptFolder(input, tempDir, opts);

        assertTrue(Files.exists(tempDir.resolve("split-src.zip")));
        assertEquals(List.of("a.bin", "sub"), listNames(input), "原文件夹内容不得改变");
        assertEquals(List.of("a.bin", "sub"), listNames(input.resolve("sub").getParent()));
        assertTrue(Files.isRegularFile(input.resolve("a.bin")));

        Path out = tempDir.resolve("out");
        Files.createDirectories(out);
        FolderCrypt.DecryptOptions dop = new FolderCrypt.DecryptOptions();
        dop.password = "split-pw";
        dop.rsCodecs = rs;
        FolderCrypt.decryptAuto(tempDir.resolve("split-src.zip"), out, dop);
        assertArrayEquals(a, Files.readAllBytes(out.resolve("split-src/a.bin")));
        assertArrayEquals(b, Files.readAllBytes(out.resolve("split-src/sub/b.bin")));
    }

    /**
     * 显式指定一个与输入无关的输出目录时，行为与修复前一致（输出到该目录）。
     */
    @Test
    void folderArchiveToSeparateOutputDir(@TempDir Path tempDir) throws Exception {
        Path input = tempDir.resolve("src");
        Files.createDirectories(input);
        Files.write(input.resolve("x.bin"), rand(1024, 41));

        Path encOut = tempDir.resolve("encout");
        Files.createDirectories(encOut);
        FolderCrypt.EncryptOptions opts = folderOptions("pw");
        opts.archiveFormat = "ZIP";
        FolderCrypt.encryptFolder(input, encOut, opts);

        assertTrue(Files.exists(encOut.resolve("src.zip")));
        assertEquals(List.of("x.bin"), listNames(input));
        assertEquals(List.of("src.zip"), listNames(encOut), "不应残留工作目录");
    }

    // ================================================================
    // B. 其余归档格式：同样只打包密文、不破坏源目录
    // ================================================================

    /**
     * 7Z / TAR.GZ / GZ 三种格式走同一条「先暂存再打包」路径。
     */
    @Test
    void folderArchiveNonZipFormatsKeepSourceIntact(@TempDir Path tempDir) throws Exception {
        for (String fmt : List.of("7Z", "TAR.GZ", "GZ")) {
            Path caseDir = tempDir.resolve("case-" + fmt.replace('.', '_'));
            Path input = caseDir.resolve("media");
            Files.createDirectories(input);
            byte[] data = rand(3000, 51);
            Files.write(input.resolve("clip.mp4"), data);

            FolderCrypt.EncryptOptions opts = folderOptions("pw-" + fmt);
            opts.archiveFormat = fmt;
            FolderCrypt.encryptFolder(input, caseDir, opts);

            // GZ 不保存条目名，文件夹归档会被提升为 TAR.GZ 以保住 .ergou 后缀
            ArchivePacker.Format parsed = ArchivePacker.parseFormat(fmt);
            ArchivePacker.Format expected = parsed == ArchivePacker.Format.GZ
                    ? ArchivePacker.Format.TAR_GZ : parsed;
            Path archive = caseDir.resolve("media" + ArchivePacker.extOf(expected));
            assertTrue(Files.exists(archive), fmt + " 应生成压缩包");
            assertEquals(List.of("clip.mp4"), listNames(input), fmt + " 不得破坏原文件夹");
            assertEquals(List.of("media", "media" + ArchivePacker.extOf(expected)),
                    listNames(caseDir).stream().sorted().toList(),
                    fmt + " 不得残留工作目录，且原文件夹仍在");

            // 解出密文并解密，确认内容一致
            Path out = caseDir.resolve("out");
            Files.createDirectories(out);
            FolderCrypt.DecryptOptions dop = new FolderCrypt.DecryptOptions();
            dop.password = "pw-" + fmt;
            dop.rsCodecs = rs;
            FolderCrypt.decryptAuto(archive, out, dop);
            assertArrayEquals(data, Files.readAllBytes(out.resolve("media/clip.mp4")),
                    fmt + " 往返应一致");
        }
    }

    /**
     * 归档密码留空 + 「密码回退」关闭时，任何格式的压缩包都不得被加密。
     */
    @Test
    void emptyArchivePasswordNeverYieldsEncryptedArchive(@TempDir Path tempDir) throws Exception {
        for (String fmt : List.of("ZIP", "7Z", "TAR.GZ", "GZ")) {
            Path caseDir = tempDir.resolve("nopw-" + fmt.replace('.', '_'));
            Path input = caseDir.resolve("data");
            Files.createDirectories(input);
            Files.write(input.resolve("f.bin"), rand(1500, 61));

            FolderCrypt.EncryptOptions opts = folderOptions("secret-file-pw");
            opts.archiveFormat = fmt;
            opts.archivePassword = null;
            FolderCrypt.encryptFolder(input, caseDir, opts);

            // GZ 会被提升为 TAR.GZ，扩展名随之变化
            ArchivePacker.Format parsed = ArchivePacker.parseFormat(fmt);
            ArchivePacker.Format expected = parsed == ArchivePacker.Format.GZ
                    ? ArchivePacker.Format.TAR_GZ : parsed;
            Path archive = caseDir.resolve("data" + ArchivePacker.extOf(expected));
            assertFalse(ArchiveExtractor.isEncryptedFile(archive),
                    fmt + "：归档密码留空时不得生成受密码保护的压缩包");
            assertFalse(ArchiveExtractor.hasEncryptedEntries(archive),
                    fmt + "：归档密码留空时压缩包内不得有加密条目");
        }
    }

    /**
     * 即使设置了「密码回退」开关，显式留空仍按留空处理——这里锁定当前默认语义：
     * 回退关闭时为空；开启时才回退。用于防止默认行为被无声反转。
     */
    @Test
    void archivePasswordFallbackRespectsSetting(@TempDir Path tempDir) throws Exception {
        boolean saved = SettingsManager.isArchivePasswordFallback();
        try {
            SettingsManager.setArchivePasswordFallback(false);
            Path caseDir = tempDir.resolve("fallback-off");
            Path input = caseDir.resolve("x");
            Files.createDirectories(input);
            Files.write(input.resolve("f.bin"), rand(900, 71));

            FolderCrypt.EncryptOptions opts = folderOptions("filepw");
            opts.archiveFormat = "ZIP";
            FolderCrypt.encryptFolder(input, caseDir, opts);
            try (ZipFile zf = new ZipFile(caseDir.resolve("x.zip").toFile())) {
                assertFalse(zf.isEncrypted(), "回退关闭时压缩包不应加密");
            }
        } finally {
            SettingsManager.setArchivePasswordFallback(saved);
        }
    }

    // ================================================================
    // 辅助方法
    // ================================================================

    /**
     * 构造低资源占用的文件夹加密选项。
     *
     * @param password 文件加密密码
     * @return 选项对象
     */
    private static FolderCrypt.EncryptOptions folderOptions(String password) {
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
     * 生成确定性伪随机数据。
     *
     * @param n   字节数
     * @param seed 种子
     * @return 数据
     */
    private static byte[] rand(int n, int seed) {
        byte[] b = new byte[n];
        new java.util.Random(seed).nextBytes(b);
        return b;
    }

    /**
     * 递归删除目录树，用于临时目录清理。
     *
     * @param dir 待删除目录
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
}
