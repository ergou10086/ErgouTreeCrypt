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
 * 「压缩后加密」完整测试套件。
 *
 * <p>语义：先按所选格式把输入打成一个归档（可选归档密码），再对归档整体加密为单个
 * {@code .ergou}。覆盖单文件、文件夹、多文件三条路径，四种归档格式、归档密码、
 * 分卷、空输入与「留空即无密码」等边界。
 *
 * <p>使用低 Argon2 参数保证用例秒级完成。
 *
 * @author ErgouTree
 */
final class CompressThenEncryptTest {

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
    // A. 单文件
    // ================================================================

    /**
     * 单文件压缩后加密：产物为 {@code <输出名>.zip.ergou}，解密后内容逐字节一致。
     */
    @Test
    void singleFileZipThenEncrypt(@TempDir Path tempDir) throws Exception {
        byte[] data = rand(64 * 1024, 1);
        Path input = tempDir.resolve("song.mp3");
        Files.write(input, data);
        Path out = tempDir.resolve("song.mp3.ergou");

        EncryptRequest req = baseRequest(input, out, "enc-pw");
        req.setPreArchiveFormat("ZIP");
        Encryptor.encrypt(req);

        Path produced = tempDir.resolve("song.mp3.zip.ergou");
        assertTrue(Files.exists(produced), "产物应为 song.mp3.zip.ergou，实际：" + listNames(tempDir));
        assertEquals(List.of("song.mp3", "song.mp3.zip.ergou"),
                listNames(tempDir).stream().sorted().toList());

        Path archive = decryptTo(tempDir, produced, "enc-pw", null);
        assertArrayEquals(data, extractSingle(archive, tempDir, null, "song.mp3"));
    }

    /**
     * 单文件 + 7Z + 归档密码：压缩包受保护，解密解压后内容一致。
     */
    @Test
    void singleFile7zThenEncryptWithArchivePassword(@TempDir Path tempDir) throws Exception {
        byte[] data = rand(40 * 1024, 2);
        Path input = tempDir.resolve("a.bin");
        Files.write(input, data);
        Path out = tempDir.resolve("a.bin.ergou");

        EncryptRequest req = baseRequest(input, out, "enc-pw");
        req.setPreArchiveFormat("7Z");
        req.setPreArchivePassword("zip-pw");
        Encryptor.encrypt(req);

        Path produced = tempDir.resolve("a.bin.7z.ergou");
        assertTrue(Files.exists(produced));
        Path archive = decryptTo(tempDir, produced, "enc-pw", null);

        // 7Z 的归档密码由本工具特有的 MAGIC 包裹实现
        assertTrue(ArchiveExtractor.isEncryptedFile(archive),
                "填写了归档密码时 7Z 应被整体包裹加密");
        byte[] restored = extractSingle(archive, tempDir, "zip-pw", "a.bin");
        assertArrayEquals(data, restored);
    }

    /**
     * 归档密码留空时，先于加密生成的压缩包必须是明文归档。
     */
    @Test
    void singleFileZipEmptyArchivePasswordIsPlain(@TempDir Path tempDir) throws Exception {
        Path input = tempDir.resolve("b.bin");
        Files.write(input, rand(8 * 1024, 3));
        Path out = tempDir.resolve("b.bin.ergou");

        EncryptRequest req = baseRequest(input, out, "enc-pw");
        req.setPreArchiveFormat("ZIP");
        req.setPreArchivePassword(null);
        Encryptor.encrypt(req);

        Path archive = decryptTo(tempDir, tempDir.resolve("b.bin.zip.ergou"), "enc-pw", null);
        try (ZipFile zf = new ZipFile(archive.toFile())) {
            assertFalse(zf.isEncrypted(), "归档密码留空时压缩包不应加密");
        }
    }

    /**
     * 压缩后加密 + 分卷：产物为分卷碎片，重组解密后仍能解出归档。
     */
    @Test
    void singleFileZipThenEncryptWithSplit(@TempDir Path tempDir) throws Exception {
        byte[] data = rand(3 * 1024 * 1024, 4);
        Path input = tempDir.resolve("big.bin");
        Files.write(input, data);
        Path out = tempDir.resolve("big.bin.ergou");

        EncryptRequest req = baseRequest(input, out, "enc-pw");
        req.setPreArchiveFormat("ZIP");
        req.setSplit(true);
        req.setChunkSize(1);
        Encryptor.encrypt(req);

        // 分卷场景下核心会改写 outputFile 指向碎片夹中的基准名
        Path chunkBase = Path.of(req.getOutputFile());
        Path chunkDir = chunkBase.getParent();
        assertTrue(Files.isDirectory(chunkDir), "应生成分卷碎片夹：" + chunkDir);
        List<String> chunkNames = listNames(chunkDir);
        assertTrue(chunkNames.size() > 1, "应切出多个碎片：" + chunkNames);

        DecryptRequest dec = new DecryptRequest();
        dec.setInputFile(chunkBase.toString());
        dec.setOutputFile(tempDir.resolve("recombined.zip").toString());
        dec.setPassword("enc-pw");
        dec.setRecombine(true);
        dec.setRsCodecs(rs);
        Decryptor.decrypt(dec);

        Path archive = tempDir.resolve("recombined.zip");
        assertTrue(Files.isRegularFile(archive));
        assertArrayEquals(data, extractSingle(archive, tempDir, null, "big.bin"));
    }

    // ================================================================
    // B. 文件夹
    // ================================================================

    /**
     * 文件夹压缩后加密：产物是单个 {@code <文件夹名>.<归档扩展名>.ergou}，
     * 输出目录等于输入父目录时也不得改动原文件夹。
     */
    @Test
    void folderZipThenEncryptKeepsSourceAndRoundtrips(@TempDir Path tempDir) throws Exception {
        Path input = tempDir.resolve("album");
        Files.createDirectories(input.resolve("disc1"));
        byte[] a = rand(20 * 1024, 11);
        byte[] b = rand(9 * 1024, 12);
        Files.write(input.resolve("a.mp3"), a);
        Files.write(input.resolve("disc1/b.mp3"), b);

        FolderCrypt.EncryptOptions opts = folderOptions("folder-pw");
        opts.preArchiveFormat = "ZIP";
        FolderCrypt.encryptFolder(input, tempDir, opts);

        Path produced = tempDir.resolve("album.zip.ergou");
        assertTrue(Files.exists(produced), "应生成 album.zip.ergou");
        assertEquals(List.of("album", "album.zip.ergou"),
                listNames(tempDir), "原文件夹必须原封不动，且不得残留中间产物");
        assertArrayEquals(a, Files.readAllBytes(input.resolve("a.mp3")));

        // 端到端：解密 + 解压回同名文件夹，目录结构完整还原
        Path out = tempDir.resolve("out");
        Files.createDirectories(out);
        FolderCrypt.DecryptOptions dop = new FolderCrypt.DecryptOptions();
        dop.password = "folder-pw";
        dop.decryptThenExtract = true;
        dop.rsCodecs = rs;
        FolderCrypt.decryptAuto(produced, out, dop);

        assertArrayEquals(a, Files.readAllBytes(out.resolve("album/a.mp3")));
        assertArrayEquals(b, Files.readAllBytes(out.resolve("album/disc1/b.mp3")));
    }

    /**
     * 文件夹 + TAR.GZ：归档保留目录结构。
     */
    @Test
    void folderTarGzThenEncrypt(@TempDir Path tempDir) throws Exception {
        Path input = tempDir.resolve("tree");
        Files.createDirectories(input.resolve("nested/deep"));
        byte[] data = rand(6 * 1024, 21);
        Files.write(input.resolve("nested/deep/c.txt"), data);

        FolderCrypt.EncryptOptions opts = folderOptions("tgz-pw");
        opts.preArchiveFormat = "TAR.GZ";
        FolderCrypt.encryptFolder(input, tempDir, opts);

        Path produced = tempDir.resolve("tree.tar.gz.ergou");
        assertTrue(Files.exists(produced));

        Path out = tempDir.resolve("out");
        Files.createDirectories(out);
        FolderCrypt.DecryptOptions dop = new FolderCrypt.DecryptOptions();
        dop.password = "tgz-pw";
        dop.decryptThenExtract = true;
        dop.rsCodecs = rs;
        FolderCrypt.decryptAuto(produced, out, dop);
        assertArrayEquals(data, Files.readAllBytes(out.resolve("tree/nested/deep/c.txt")));
    }

    /**
     * 文件夹 + GZ：GZ 不保存条目名，必须提升为 TAR.GZ 才不会丢掉 {@code .ergou} 后缀，
     * 否则本工具无法再识别自己的产物。
     */
    @Test
    void folderGzPromotedToTarGzAndRoundtrips(@TempDir Path tempDir) throws Exception {
        Path input = tempDir.resolve("gzcase");
        Files.createDirectories(input);
        byte[] data = rand(4 * 1024, 31);
        Files.write(input.resolve("only.bin"), data);

        FolderCrypt.EncryptOptions opts = folderOptions("gz-pw");
        opts.preArchiveFormat = "GZ";
        FolderCrypt.encryptFolder(input, tempDir, opts);

        Path produced = tempDir.resolve("gzcase.tar.gz.ergou");
        assertTrue(Files.exists(produced), "GZ 应被提升为 TAR.GZ，产物名为 gzcase.tar.gz.ergou");

        Path archive = decryptTo(tempDir, produced, "gz-pw", null);
        assertTrue(ArchiveExtractor.isArchive(archive), "解密产物应是可识别的归档");

        Path out = tempDir.resolve("out");
        Files.createDirectories(out);
        FolderCrypt.DecryptOptions dop = new FolderCrypt.DecryptOptions();
        dop.password = "gz-pw";
        dop.decryptThenExtract = true;
        dop.rsCodecs = rs;
        FolderCrypt.decryptAuto(produced, out, dop);
        assertArrayEquals(data, Files.readAllBytes(out.resolve("gzcase/only.bin")));
    }

    /**
     * 文件夹 + 归档密码：归档受保护，密码错误时无法解出内容。
     */
    @Test
    void folderZipThenEncryptWithArchivePassword(@TempDir Path tempDir) throws Exception {
        Path input = tempDir.resolve("secret");
        Files.createDirectories(input);
        byte[] data = rand(5 * 1024, 41);
        Files.write(input.resolve("f.bin"), data);

        FolderCrypt.EncryptOptions opts = folderOptions("file-pw");
        opts.preArchiveFormat = "ZIP";
        opts.preArchivePassword = "arch-pw";
        FolderCrypt.encryptFolder(input, tempDir, opts);

        Path produced = tempDir.resolve("secret.zip.ergou");
        Path archive = decryptTo(tempDir, produced, "file-pw", null);
        try (ZipFile zf = new ZipFile(archive.toFile())) {
            assertTrue(zf.isEncrypted(), "填写了归档密码时压缩包应加密");
        }
        // 正确密码可解出
        assertArrayEquals(data, extractSingle(archive, tempDir, "arch-pw", "f.bin"));
        // 空密码应解不出
        Path bad = tempDir.resolve("bad");
        Files.createDirectories(bad);
        assertThrows(IOException.class,
                () -> ArchiveExtractor.extractPreserving(archive, bad, null),
                "缺失归档密码时解压应失败");
    }

    /**
     * 空文件夹应当报错而不是静默产出空归档。
     */
    @Test
    void emptyFolderFails(@TempDir Path tempDir) throws Exception {
        Path input = tempDir.resolve("empty");
        Files.createDirectories(input);

        FolderCrypt.EncryptOptions opts = folderOptions("pw");
        opts.preArchiveFormat = "ZIP";
        assertThrows(Exception.class, () -> FolderCrypt.encryptFolder(input, tempDir, opts));
        assertFalse(Files.exists(tempDir.resolve("empty.zip.ergou")),
                "失败时不得留下半成品");
    }

    /**
     * 压缩后加密 + 分卷：产物为碎片夹，重组后仍能解出归档。
     */
    @Test
    void folderZipThenEncryptWithSplit(@TempDir Path tempDir) throws Exception {
        Path input = tempDir.resolve("splitcase");
        Files.createDirectories(input);
        byte[] data = rand(3 * 1024 * 1024, 51);
        Files.write(input.resolve("big.bin"), data);

        FolderCrypt.EncryptOptions opts = folderOptions("split-pw");
        opts.preArchiveFormat = "ZIP";
        opts.split = true;
        opts.chunkSize = 1;
        FolderCrypt.encryptFolder(input, tempDir, opts);

        Path chunkDir = tempDir.resolve("splitcase.zip");
        assertTrue(Files.isDirectory(chunkDir), "分卷时应生成同名碎片夹");
        List<String> chunks = listNames(chunkDir);
        assertTrue(chunks.size() > 1, "应切出多个碎片：" + chunks);

        DecryptRequest dec = new DecryptRequest();
        dec.setInputFile(chunkDir.resolve("splitcase.zip.ergou").toString());
        dec.setOutputFile(tempDir.resolve("recombined.zip").toString());
        dec.setPassword("split-pw");
        dec.setRecombine(true);
        dec.setRsCodecs(rs);
        Decryptor.decrypt(dec);

        assertArrayEquals(data,
                extractSingle(tempDir.resolve("recombined.zip"), tempDir, null, "big.bin"));
    }

    // ================================================================
    // C. 多文件
    // ================================================================

    /**
     * 多文件压缩后加密：所有文件合并进同一个归档，只有一份 {@code .ergou}。
     */
    @Test
    void multiFileZipThenEncryptSingleArchive(@TempDir Path tempDir) throws Exception {
        Path dir = tempDir.resolve("batch");
        Files.createDirectories(dir);
        byte[] d1 = rand(7 * 1024, 61);
        byte[] d2 = rand(11 * 1024, 62);
        Path f1 = dir.resolve("one.txt");
        Path f2 = dir.resolve("two.dat");
        Files.write(f1, d1);
        Files.write(f2, d2);

        Path out = tempDir.resolve("out");
        FolderCrypt.EncryptOptions opts = folderOptions("batch-pw");
        opts.preArchiveFormat = "ZIP";
        opts.batchName = "batch";
        FolderCrypt.encryptFiles(List.of(f1, f2), out, opts);

        Path produced = out.resolve("batch.zip.ergou");
        assertTrue(Files.exists(produced), "多文件压缩后加密应只产出一个 .ergou");
        assertEquals(List.of("batch.zip.ergou"), listNames(out));

        Path archive = decryptTo(out, produced, "batch-pw", null);
        assertArrayEquals(d1, extractSingle(archive, tempDir, null, "one.txt"));
        assertArrayEquals(d2, extractSingle(archive, tempDir, null, "two.dat"));
    }

    /**
     * 多文件 + GZ：同样提升为 TAR.GZ；条目名重复时自动去重。
     */
    @Test
    void multiFileGzPromotedAndDuplicateNamesDeduped(@TempDir Path tempDir) throws Exception {
        Path dirA = tempDir.resolve("A");
        Path dirB = tempDir.resolve("B");
        Files.createDirectories(dirA);
        Files.createDirectories(dirB);
        byte[] d1 = rand(3 * 1024, 71);
        byte[] d2 = rand(5 * 1024, 72);
        Path f1 = dirA.resolve("same.txt");
        Path f2 = dirB.resolve("same.txt");
        Files.write(f1, d1);
        Files.write(f2, d2);

        Path out = tempDir.resolve("out");
        FolderCrypt.EncryptOptions opts = folderOptions("dup-pw");
        opts.preArchiveFormat = "GZ";
        opts.batchName = "dups";
        FolderCrypt.encryptFiles(List.of(f1, f2), out, opts);

        Path produced = out.resolve("dups.tar.gz.ergou");
        assertTrue(Files.exists(produced), "GZ 应被提升为 TAR.GZ");

        Path archive = decryptTo(out, produced, "dup-pw", null);
        Path extract = tempDir.resolve("unpacked");
        ArchiveExtractor.extractPreserving(archive, extract, null);
        // 同名条目去重后仍能取回两份不同内容
        assertNotNull(extractSingle(archive, tempDir, null, "same.txt"));
        assertArrayEquals(d1, Files.readAllBytes(extract.resolve("same.txt")));
        assertArrayEquals(d2, Files.readAllBytes(extract.resolve("same (2).txt")));
    }

    // ================================================================
    // D. 输出命名规则（两端共用同一纯函数）
    // ================================================================

    /**
     * 压缩后加密的产物名规则：卷后缀永远在最外层。
     */
    @Test
    void preArchiveOutputNamingRule() {
        assertEquals("song.mp3.zip.ergou",
                hbnu.project.ergoutreecrypt.filetypes.OutputNaming
                        .preArchiveEncryptOutputName("song.mp3.ergou", "ZIP"));
        assertEquals("song.mp3.7z.ergou",
                hbnu.project.ergoutreecrypt.filetypes.OutputNaming
                        .preArchiveEncryptOutputName("song.mp3.ergou", "7Z"));
        assertEquals("tree.tar.gz.ergou",
                hbnu.project.ergoutreecrypt.filetypes.OutputNaming
                        .preArchiveEncryptOutputName("tree.ergou", "TAR.GZ"));
        // 旧卷后缀同样被剥掉；没有卷后缀时直接拼接
        assertEquals("old.zip.ergou",
                hbnu.project.ergoutreecrypt.filetypes.OutputNaming
                        .preArchiveEncryptOutputName("old.pcv", "ZIP"));
        assertEquals("plain.zip.ergou",
                hbnu.project.ergoutreecrypt.filetypes.OutputNaming
                        .preArchiveEncryptOutputName("plain", "ZIP"));
    }

    // ================================================================
    // 辅助方法
    // ================================================================

    /**
     * 构造低资源占用的单文件加密请求。
     *
     * @param input    输入文件
     * @param output   输出文件
     * @param password 加密密码
     * @return 请求对象
     */
    private static EncryptRequest baseRequest(Path input, Path output, String password) {
        EncryptRequest req = new EncryptRequest();
        req.setInputFile(input.toString());
        req.setOutputFile(output.toString());
        req.setPassword(password);
        req.setRsCodecs(rs);
        req.setArgon2MemoryKib(FAST_MEMORY_KIB);
        req.setArgon2Passes(FAST_PASSES);
        req.setArgon2Threads(FAST_THREADS);
        return req;
    }

    /**
     * 构造低资源占用的文件夹/多文件加密选项。
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
     * 把加密卷解密为明文归档。
     *
     * @param dir      输出所在目录
     * @param encFile  加密卷
     * @param password 密码
     * @param skipped  未使用，保留以统一签名
     * @return 解密出的归档路径
     * @throws Exception 解密失败
     */
    private static Path decryptTo(Path dir, Path encFile, String password, String skipped)
            throws Exception {
        // 去掉 .ergou 得到的名字才是内层归档，必须保留它的扩展名——
        // ArchiveExtractor 按扩展名分派解压器
        String encName = encFile.getFileName().toString();
        String inner = encName.toLowerCase().endsWith(".ergou")
                ? encName.substring(0, encName.length() - ".ergou".length())
                : encName + ".zip";
        Path out = dir.resolve("dec-" + inner);
        DecryptRequest dec = new DecryptRequest();
        dec.setInputFile(encFile.toString());
        dec.setOutputFile(out.toString());
        dec.setPassword(password);
        dec.setRsCodecs(rs);
        Decryptor.decrypt(dec);
        assertTrue(Files.exists(out), "解密应产出归档文件");
        return out;
    }

    /**
     * 从归档中解出单个文件名的条目内容。
     *
     * @param archive  归档
     * @param dir      解压目录的父目录
     * @param password 归档密码，可为 null
     * @param name     期望的条目名
     * @return 条目字节
     * @throws IOException 解压或读取失败
     */
    private static byte[] extractSingle(Path archive, Path dir, String password, String name)
            throws IOException {
        Path extract = dir.resolve("x-" + System.nanoTime());
        Files.createDirectories(extract);
        ArchiveExtractor.extractPreserving(archive, extract, password);
        Path target = findNamed(extract, name);
        assertNotNull(target, "归档中应存在条目 " + name);
        return Files.readAllBytes(target);
    }

    /**
     * 在解压目录中按文件名查找条目（忽略层级）。
     *
     * @param root 解压目录
     * @param name 文件名
     * @return 找到的路径，未找到返回 null
     * @throws IOException 遍历失败
     */
    private static Path findNamed(Path root, String name) throws IOException {
        try (Stream<Path> walk = Files.walk(root)) {
            return walk.filter(Files::isRegularFile)
                    .filter(p -> p.getFileName().toString().equals(name))
                    .findFirst()
                    .orElse(null);
        }
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
}
