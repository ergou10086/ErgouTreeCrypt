package hbnu.project.ergoutreecrypt.volume;

import hbnu.project.ergoutreecrypt.encoding.RsCodecs;
import hbnu.project.ergoutreecrypt.fileops.ArchiveExtractor;
import hbnu.project.ergoutreecrypt.fileops.ArchivePacker;
import hbnu.project.ergoutreecrypt.settings.SettingsManager;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 加密后压缩（encrypt-then-compress）完整测试套件。
 *
 * <p>覆盖场景：
 * <ul>
 *   <li>单文件 + 四种归档格式（ZIP / 7Z / GZ / TAR.GZ），含密码与无密码</li>
 *   <li>分卷 + 归档组合</li>
 *   <li>多文件输入 + 归档</li>
 *   <li>密码学选项（偏执 / RS / 可否认）+ 归档交叉组合</li>
 *   <li>双卷可否认加密 + 归档</li>
 *   <li>边界条件：空文件、大文件、错误密码、残留文件清理、密码独立性</li>
 * </ul>
 *
 * @author ErgouTree
 */
public final class EncryptCompressTest {

    private static RsCodecs rs;

    /** 测试前保存的「工具特有加密」开关，用于还原。 */
    private static boolean savedCustomEnc;

    /** 测试前保存的「归档密码回退」开关，用于还原。 */
    private static boolean savedFallback;

    /**
     * 初始化：本套件专门测试「加密后压缩 + 归档密码」，需开启「工具特有加密」
     * 使 GZ/TAR.GZ/7Z 可加密；默认关闭「密码回退」，让未显式填写归档密码的
     * 用例仍生成明文归档（个别用例内部会临时开启回退）。
     */
    @BeforeAll
    static void setUp() {
        rs = new RsCodecs();
        savedCustomEnc = SettingsManager.isArchiveCustomEncryption();
        savedFallback = SettingsManager.isArchivePasswordFallback();
        SettingsManager.setArchiveCustomEncryption(true);
        SettingsManager.setArchivePasswordFallback(false);
    }

    /**
     * 还原归档相关设置，避免影响其他测试。
     */
    @AfterAll
    static void tearDown() {
        SettingsManager.setArchiveCustomEncryption(savedCustomEnc);
        SettingsManager.setArchivePasswordFallback(savedFallback);
    }

    // ================================================================
    // A. 单文件 + 归档（无分卷、无其他密码学选项）
    // ================================================================

    @Test
    void singleFileToZip(@TempDir Path tempDir) throws Exception {
        byte[] plaintext = generateTestData(512 * 1024);
        Path input = createFile(tempDir, "input.bin", plaintext);
        Path outputBase = tempDir.resolve("output.ergou");

        EncryptRequest req = buildEncryptRequest(input.toString(), outputBase.toString(),
                "test123", null, false, 0, "ZIP", null);
        Encryptor.encrypt(req);

        Path archive = tempDir.resolve("output.ergou.zip");
        assertTrue(Files.exists(archive), "ZIP archive should exist");
        assertFalse(Files.exists(outputBase), "original .ergou should be deleted");

        byte[] decrypted = extractAndDecryptSingle(archive, tempDir, null, "test123");
        assertArrayEquals(plaintext, decrypted, "roundtrip should be byte-identical");
    }

    @Test
    void singleFileToZipWithPassword(@TempDir Path tempDir) throws Exception {
        byte[] plaintext = generateTestData(300 * 1024);
        Path input = createFile(tempDir, "input.bin", plaintext);
        Path outputBase = tempDir.resolve("output.ergou");

        EncryptRequest req = buildEncryptRequest(input.toString(), outputBase.toString(),
                "enc-pass", null, false, 0, "ZIP", "archive-pass");
        Encryptor.encrypt(req);

        Path archive = tempDir.resolve("output.ergou.zip");
        assertTrue(Files.exists(archive));

        byte[] decrypted = extractAndDecryptSingle(archive, tempDir, "archive-pass", "enc-pass");
        assertArrayEquals(plaintext, decrypted);
    }

    @Test
    void singleFileTo7z(@TempDir Path tempDir) throws Exception {
        // 归档密码留空 + 回退开启：使用加密密码对 7Z 做工具特有包裹
        boolean saved = SettingsManager.isArchivePasswordFallback();
        SettingsManager.setArchivePasswordFallback(true);
        try {
            byte[] plaintext = generateTestData(200 * 1024);
            Path input = createFile(tempDir, "input.bin", plaintext);
            Path outputBase = tempDir.resolve("output.ergou");

            EncryptRequest req = buildEncryptRequest(input.toString(), outputBase.toString(),
                    "pw7z", null, false, 0, "7Z", null);
            Encryptor.encrypt(req);

            Path archive = tempDir.resolve("output.ergou.7z");
            assertTrue(Files.exists(archive));
            assertFalse(Files.exists(outputBase));

            byte[] decrypted = extractAndDecryptSingle(archive, tempDir, "pw7z", "pw7z");
            assertArrayEquals(plaintext, decrypted);
            // 7Z 已放弃原生加密，改用本工具特有的 MAGIC 整体包裹
            assertTrue(ArchiveExtractor.isEncryptedFile(archive),
                    "7Z with fallback password should be wrapped with EGTC_ARCHV1 magic");
        } finally {
            SettingsManager.setArchivePasswordFallback(saved);
        }
    }

    @Test
    void singleFileTo7zWithPassword(@TempDir Path tempDir) throws Exception {
        byte[] plaintext = generateTestData(150 * 1024);
        Path input = createFile(tempDir, "input.bin", plaintext);
        Path outputBase = tempDir.resolve("output.ergou");

        EncryptRequest req = buildEncryptRequest(input.toString(), outputBase.toString(),
                "enc-7z", null, false, 0, "7Z", "arch-7z");
        Encryptor.encrypt(req);

        Path archive = tempDir.resolve("output.ergou.7z");
        assertTrue(Files.exists(archive));

        byte[] decrypted = extractAndDecryptSingle(archive, tempDir, "arch-7z", "enc-7z");
        assertArrayEquals(plaintext, decrypted);
    }

    @Test
    void singleFileToGz(@TempDir Path tempDir) throws Exception {
        byte[] plaintext = generateTestData(100 * 1024);
        Path input = createFile(tempDir, "input.bin", plaintext);
        Path outputBase = tempDir.resolve("output.ergou");

        EncryptRequest req = buildEncryptRequest(input.toString(), outputBase.toString(),
                "pw-gz", null, false, 0, "GZ", null);
        Encryptor.encrypt(req);

        Path archive = tempDir.resolve("output.ergou.gz");
        assertTrue(Files.exists(archive));
        assertFalse(Files.exists(outputBase));

        byte[] decrypted = extractAndDecryptSingle(archive, tempDir, null, "pw-gz");
        assertArrayEquals(plaintext, decrypted);
    }

    @Test
    void singleFileToGzWithPassword(@TempDir Path tempDir) throws Exception {
        byte[] plaintext = generateTestData(80 * 1024);
        Path input = createFile(tempDir, "input.bin", plaintext);
        Path outputBase = tempDir.resolve("output.ergou");

        EncryptRequest req = buildEncryptRequest(input.toString(), outputBase.toString(),
                "enc-gz", null, false, 0, "GZ", "arch-gz-pw");
        Encryptor.encrypt(req);

        Path archive = tempDir.resolve("output.ergou.gz");
        assertTrue(Files.exists(archive));

        // GZ with password uses AES-256-CTR whole-file wrapper
        assertTrue(ArchiveExtractor.isEncryptedFile(archive),
                "GZ with password should have EGTC_ARCHV1 magic");

        byte[] decrypted = extractAndDecryptSingle(archive, tempDir, "arch-gz-pw", "enc-gz");
        assertArrayEquals(plaintext, decrypted);
    }

    @Test
    void singleFileToTarGz(@TempDir Path tempDir) throws Exception {
        byte[] plaintext = generateTestData(256 * 1024);
        Path input = createFile(tempDir, "input.bin", plaintext);
        Path outputBase = tempDir.resolve("output.ergou");

        EncryptRequest req = buildEncryptRequest(input.toString(), outputBase.toString(),
                "pw-targz", null, false, 0, "TAR.GZ", null);
        Encryptor.encrypt(req);

        Path archive = tempDir.resolve("output.ergou.tar.gz");
        assertTrue(Files.exists(archive));
        assertFalse(Files.exists(outputBase));

        byte[] decrypted = extractAndDecryptSingle(archive, tempDir, null, "pw-targz");
        assertArrayEquals(plaintext, decrypted);
    }

    @Test
    void singleFileToTarGzWithPassword(@TempDir Path tempDir) throws Exception {
        byte[] plaintext = generateTestData(180 * 1024);
        Path input = createFile(tempDir, "input.bin", plaintext);
        Path outputBase = tempDir.resolve("output.ergou");

        EncryptRequest req = buildEncryptRequest(input.toString(), outputBase.toString(),
                "enc-targz", null, false, 0, "TAR.GZ", "arch-targz-pw");
        Encryptor.encrypt(req);

        Path archive = tempDir.resolve("output.ergou.tar.gz");
        assertTrue(Files.exists(archive));
        assertTrue(ArchiveExtractor.isEncryptedFile(archive),
                "TAR.GZ with password should have EGTC_ARCHV1 magic");

        byte[] decrypted = extractAndDecryptSingle(archive, tempDir, "arch-targz-pw", "enc-targz");
        assertArrayEquals(plaintext, decrypted);
    }

    // ================================================================
    // B. 单文件 + 分卷 + 归档
    // ================================================================

    @Test
    void singleFileSplitToZip(@TempDir Path tempDir) throws Exception {
        byte[] plaintext = generateTestData(3 * 1024 * 1024 + 777); // ~3 MiB
        Path input = createFile(tempDir, "input.bin", plaintext);
        // 输出名不与源文件名冲突，避免 _ergou_split 降级命名
        Path outputBase = tempDir.resolve("enc_out.ergou");

        EncryptRequest req = buildEncryptRequest(input.toString(), outputBase.toString(),
                "split-zip", null, true, 1, "ZIP", null);
        Encryptor.encrypt(req);

        // 分卷文件夹：enc_out（strip .ergou），归档：enc_out.zip
        Path archive = tempDir.resolve("enc_out.zip");
        assertTrue(Files.exists(archive), "split+ZIP archive should exist");
        assertFalse(Files.exists(outputBase), "unsplit .ergou should be deleted");
        Path chunkDir = tempDir.resolve("enc_out");
        assertFalse(Files.exists(chunkDir), "chunk folder should be cleaned up");

        byte[] decrypted = extractSplitAndDecrypt(archive, tempDir, null, "split-zip");
        assertArrayEquals(plaintext, decrypted);
    }

    @Test
    void singleFileSplitTo7zWithPassword(@TempDir Path tempDir) throws Exception {
        byte[] plaintext = generateTestData(2 * 1024 * 1024 + 500);
        Path input = createFile(tempDir, "input.bin", plaintext);
        Path outputBase = tempDir.resolve("enc_out.ergou");

        EncryptRequest req = buildEncryptRequest(input.toString(), outputBase.toString(),
                "split-7z", null, true, 1, "7Z", "arch-7z-split");
        Encryptor.encrypt(req);

        Path archive = tempDir.resolve("enc_out.7z");
        assertTrue(Files.exists(archive));

        byte[] decrypted = extractSplitAndDecrypt(archive, tempDir, "arch-7z-split", "split-7z");
        assertArrayEquals(plaintext, decrypted);
    }

    @Test
    void singleFileSplitToTarGz(@TempDir Path tempDir) throws Exception {
        byte[] plaintext = generateTestData(3 * 1024 * 1024);
        Path input = createFile(tempDir, "input.bin", plaintext);
        Path outputBase = tempDir.resolve("enc_out.ergou");

        EncryptRequest req = buildEncryptRequest(input.toString(), outputBase.toString(),
                "split-targz", null, true, 1, "TAR.GZ", null);
        Encryptor.encrypt(req);

        Path archive = tempDir.resolve("enc_out.tar.gz");
        assertTrue(Files.exists(archive));

        byte[] decrypted = extractSplitAndDecrypt(archive, tempDir, null, "split-targz");
        assertArrayEquals(plaintext, decrypted);
    }

    @Test
    void singleFileSplitToGz(@TempDir Path tempDir) throws Exception {
        // GZ 多条目时自动提升为 TAR.GZ，扩展名同步调整为 .tar.gz
        byte[] plaintext = generateTestData(2 * 1024 * 1024 + 300);
        Path input = createFile(tempDir, "input.bin", plaintext);
        Path outputBase = tempDir.resolve("enc_out.ergou");

        EncryptRequest req = buildEncryptRequest(input.toString(), outputBase.toString(),
                "split-gz", null, true, 1, "GZ", null);
        Encryptor.encrypt(req);

        // GZ 在多条目时自动升级为 TAR.GZ，扩展名也相应变为 .tar.gz
        Path archive = tempDir.resolve("enc_out.tar.gz");
        assertTrue(Files.exists(archive));

        byte[] decrypted = extractSplitAndDecrypt(archive, tempDir, null, "split-gz");
        assertArrayEquals(plaintext, decrypted);
    }

    // ================================================================
    // C. 多文件输入 + 归档
    // ================================================================

    @Test
    void multiFileToZip(@TempDir Path tempDir) throws Exception {
        byte[] data1 = generateTestData(100 * 1024);
        byte[] data2 = generateTestData(150 * 1024);
        byte[] expected = concat(data1, data2);

        Path f1 = createFile(tempDir, "file_a.bin", data1);
        Path f2 = createFile(tempDir, "file_b.bin", data2);
        Path outputBase = tempDir.resolve("multi_out.ergou");

        EncryptRequest req = new EncryptRequest();
        req.setInputFiles(List.of(f1.toString(), f2.toString()));
        req.setOutputFile(outputBase.toString());
        req.setPassword("multi-pass");
        req.setArchiveFormat("ZIP");
        req.setRsCodecs(rs);
        Encryptor.encrypt(req);

        Path archive = tempDir.resolve("multi_out.ergou.zip");
        assertTrue(Files.exists(archive));

        byte[] decrypted = extractAndDecryptSingle(archive, tempDir, null, "multi-pass");
        assertArrayEquals(expected, decrypted);
    }

    @Test
    void multiFileTo7zWithPassword(@TempDir Path tempDir) throws Exception {
        byte[] data1 = generateTestData(50 * 1024);
        byte[] data2 = generateTestData(70 * 1024);
        byte[] expected = concat(data1, data2);

        Path f1 = createFile(tempDir, "doc_a.bin", data1);
        Path f2 = createFile(tempDir, "doc_b.bin", data2);
        Path outputBase = tempDir.resolve("multi_out.ergou");

        EncryptRequest req = new EncryptRequest();
        req.setInputFiles(List.of(f1.toString(), f2.toString()));
        req.setOutputFile(outputBase.toString());
        req.setPassword("multi-7z-pass");
        req.setArchiveFormat("7Z");
        req.setArchivePassword("multi-arch-pass");
        req.setRsCodecs(rs);
        Encryptor.encrypt(req);

        Path archive = tempDir.resolve("multi_out.ergou.7z");
        assertTrue(Files.exists(archive));

        byte[] decrypted = extractAndDecryptSingle(archive, tempDir, "multi-arch-pass", "multi-7z-pass");
        assertArrayEquals(expected, decrypted);
    }

    @Test
    void multiFileSplitToZip(@TempDir Path tempDir) throws Exception {
        // 多文件先合并为一个临时文件，再加密，最后分卷+归档
        byte[] data1 = generateTestData(500 * 1024);
        byte[] data2 = generateTestData(600 * 1024);
        byte[] data3 = generateTestData(400 * 1024);
        byte[] expected = concat(concat(data1, data2), data3);

        Path f1 = createFile(tempDir, "part1.bin", data1);
        Path f2 = createFile(tempDir, "part2.bin", data2);
        Path f3 = createFile(tempDir, "part3.bin", data3);
        Path outputBase = tempDir.resolve("multi_split_out.ergou");

        EncryptRequest req = new EncryptRequest();
        req.setInputFiles(List.of(f1.toString(), f2.toString(), f3.toString()));
        req.setOutputFile(outputBase.toString());
        req.setPassword("multi-split-pass");
        req.setSplit(true);
        req.setChunkSize(1); // 1 MiB
        req.setArchiveFormat("ZIP");
        req.setRsCodecs(rs);
        Encryptor.encrypt(req);

        Path archive = tempDir.resolve("multi_split_out.zip");
        assertTrue(Files.exists(archive));

        byte[] decrypted = extractSplitAndDecrypt(archive, tempDir, null, "multi-split-pass");
        assertArrayEquals(expected, decrypted);
    }

    // ================================================================
    // D. 密码学选项 + 归档交叉组合
    // ================================================================

    @Test
    void paranoidModeToZip(@TempDir Path tempDir) throws Exception {
        byte[] plaintext = generateTestData(200 * 1024);
        Path input = createFile(tempDir, "input.bin", plaintext);
        Path outputBase = tempDir.resolve("paranoid_out.ergou");

        EncryptRequest req = buildEncryptRequest(input.toString(), outputBase.toString(),
                "paranoid-pass", null, false, 0, "ZIP", null);
        req.setParanoid(true);
        Encryptor.encrypt(req);

        Path archive = tempDir.resolve("paranoid_out.ergou.zip");
        assertTrue(Files.exists(archive));

        byte[] decrypted = extractAndDecryptSingle(archive, tempDir, null, "paranoid-pass");
        assertArrayEquals(plaintext, decrypted);
    }

    @Test
    void reedSolomonToZip(@TempDir Path tempDir) throws Exception {
        byte[] plaintext = generateTestData(2 * 1024 * 1024 + 333);
        Path input = createFile(tempDir, "input.bin", plaintext);
        Path outputBase = tempDir.resolve("rs_out.ergou");

        EncryptRequest req = buildEncryptRequest(input.toString(), outputBase.toString(),
                "rs-pass", null, false, 0, "ZIP", null);
        req.setReedSolomon(true);
        Encryptor.encrypt(req);

        Path archive = tempDir.resolve("rs_out.ergou.zip");
        assertTrue(Files.exists(archive));

        byte[] decrypted = extractAndDecryptSingle(archive, tempDir, null, "rs-pass");
        assertArrayEquals(plaintext, decrypted);
    }

    @Test
    void paranoidRsTo7z(@TempDir Path tempDir) throws Exception {
        byte[] plaintext = generateTestData(300 * 1024);
        Path input = createFile(tempDir, "input.bin", plaintext);
        Path outputBase = tempDir.resolve("pr_out.ergou");

        EncryptRequest req = buildEncryptRequest(input.toString(), outputBase.toString(),
                "pr-pass", null, false, 0, "7Z", "arch-pr");
        req.setParanoid(true);
        req.setReedSolomon(true);
        Encryptor.encrypt(req);

        Path archive = tempDir.resolve("pr_out.ergou.7z");
        assertTrue(Files.exists(archive));

        byte[] decrypted = extractAndDecryptSingle(archive, tempDir, "arch-pr", "pr-pass");
        assertArrayEquals(plaintext, decrypted);
    }

    @Test
    void deniabilityToZip(@TempDir Path tempDir) throws Exception {
        byte[] plaintext = generateTestData(400 * 1024);
        Path input = createFile(tempDir, "input.bin", plaintext);
        Path outputBase = tempDir.resolve("deny_out.ergou");

        EncryptRequest req = buildEncryptRequest(input.toString(), outputBase.toString(),
                "deny-pass", null, false, 0, "ZIP", null);
        req.setDeniability(true);
        Encryptor.encrypt(req);

        Path archive = tempDir.resolve("deny_out.ergou.zip");
        assertTrue(Files.exists(archive));

        // Deniability 包裹在加密之后、分卷/归档之前
        // 解密时需要 deniability=true
        byte[] decrypted = extractAndDecryptSingle(archive, tempDir, null, "deny-pass");
        assertArrayEquals(plaintext, decrypted);
    }

    @Test
    void deniabilitySplitToZip(@TempDir Path tempDir) throws Exception {
        byte[] plaintext = generateTestData(3 * 1024 * 1024);
        Path input = createFile(tempDir, "input.bin", plaintext);
        Path outputBase = tempDir.resolve("deny_split_out.ergou");

        EncryptRequest req = buildEncryptRequest(input.toString(), outputBase.toString(),
                "deny-split-pass", null, true, 1, "ZIP", null);
        req.setDeniability(true);
        Encryptor.encrypt(req);

        Path archive = tempDir.resolve("deny_split_out.zip");
        assertTrue(Files.exists(archive));

        byte[] decrypted = extractSplitAndDecrypt(archive, tempDir, null, "deny-split-pass");
        assertArrayEquals(plaintext, decrypted);
    }

    @Test
    void allOptionsToZip(@TempDir Path tempDir) throws Exception {
        // Paranoid + RS + Deniability + Keyfile + Split + ZIP — 全组合
        byte[] plaintext = generateTestData(300 * 1024);
        Path input = createFile(tempDir, "input.bin", plaintext);
        Path keyfile = createFile(tempDir, "all.key", "all-options-keyfile-secret".getBytes(StandardCharsets.UTF_8));
        Path outputBase = tempDir.resolve("all_out.ergou");

        EncryptRequest req = buildEncryptRequest(input.toString(), outputBase.toString(),
                "all-pass", List.of(keyfile.toString()), true, 50, "ZIP", null);
        req.setParanoid(true);
        req.setReedSolomon(true);
        req.setDeniability(true);
        Encryptor.encrypt(req);

        Path archive = tempDir.resolve("all_out.zip");
        assertTrue(Files.exists(archive), "all-options archive should exist");

        // 解密
        Path extractDir = tempDir.resolve("all_extract");
        Files.createDirectories(extractDir);
        List<Path> extracted = ArchiveExtractor.extract(archive, extractDir, null);
        assertFalse(extracted.isEmpty(), "archive should contain files");

        // 找到第一个分卷碎片，重组解密
        Path firstChunk = extracted.stream()
                .filter(p -> p.getFileName().toString().matches(".*\\.ergou\\.[0-9]+"))
                .findFirst().orElseThrow();

        Path decrypted = tempDir.resolve("all_dec.bin");
        DecryptRequest decReq = new DecryptRequest();
        decReq.setInputFile(firstChunk.toString());
        decReq.setOutputFile(decrypted.toString());
        decReq.setPassword("all-pass");
        decReq.setKeyfiles(List.of(keyfile.toString()));
        decReq.setDeniability(true);
        decReq.setRecombine(true);
        decReq.setRsCodecs(rs);
        Decryptor.decrypt(decReq);

        assertArrayEquals(plaintext, Files.readAllBytes(decrypted));
    }

    // ================================================================
    // E. 双卷可否认加密 + 归档
    // ================================================================

    @Test
    void dualDeniabilityToZip(@TempDir Path tempDir) throws Exception {
        byte[] realData = generateTestData(200 * 1024);
        byte[] decoyData = "Harmless decoy for dual+ZIP test.\n".getBytes(StandardCharsets.UTF_8);

        Path realFile = createFile(tempDir, "secret.bin", realData);
        Path decoyFile = createFile(tempDir, "decoy.txt", decoyData);
        Path output = tempDir.resolve("dual_out.ergou");

        EncryptRequest req = new EncryptRequest();
        req.setInputFile(realFile.toString());
        req.setDecoyFilePath(decoyFile.toString());
        req.setPassword("real-zip");
        req.setFakePassword("fake-zip");
        req.setDualDeniability(true);
        req.setOutputFile(output.toString());
        req.setArchiveFormat("ZIP");
        req.setRsCodecs(rs);
        Encryptor.encrypt(req);

        Path archive = tempDir.resolve("dual_out.ergou.zip");
        assertTrue(Files.exists(archive));
        assertTrue(ArchiveExtractor.isArchive(archive));

        // 用真实密码解密
        byte[] realResult = extractAndDecryptEgtD(archive, tempDir, null, "real-zip");
        assertArrayEquals(realData, realResult, "real password should recover real data from archive");

        // 用钓鱼密码解密
        byte[] fakeResult = extractAndDecryptEgtD(archive, tempDir, null, "fake-zip");
        assertArrayEquals(decoyData, fakeResult, "fake password should recover decoy data from archive");
    }

    @Test
    void dualDeniabilityTo7zWithPassword(@TempDir Path tempDir) throws Exception {
        byte[] realData = generateTestData(150 * 1024);
        byte[] decoyData = "Decoy for dual+7Z.\n".getBytes(StandardCharsets.UTF_8);

        Path realFile = createFile(tempDir, "secret.bin", realData);
        Path decoyFile = createFile(tempDir, "decoy.txt", decoyData);
        Path output = tempDir.resolve("dual_7z.ergou");

        EncryptRequest req = new EncryptRequest();
        req.setInputFile(realFile.toString());
        req.setDecoyFilePath(decoyFile.toString());
        req.setPassword("real-7z-dual");
        req.setFakePassword("fake-7z-dual");
        req.setDualDeniability(true);
        req.setOutputFile(output.toString());
        req.setArchiveFormat("7Z");
        req.setArchivePassword("dual-arch-7z");
        req.setRsCodecs(rs);
        Encryptor.encrypt(req);

        Path archive = tempDir.resolve("dual_7z.ergou.7z");
        assertTrue(Files.exists(archive));

        // 先用真实密码
        byte[] realResult = extractAndDecryptEgtD(archive, tempDir, "dual-arch-7z", "real-7z-dual");
        assertArrayEquals(realData, realResult);

        // 再用钓鱼密码
        byte[] fakeResult = extractAndDecryptEgtD(archive, tempDir, "dual-arch-7z", "fake-7z-dual");
        assertArrayEquals(decoyData, fakeResult);
    }

    @Test
    void dualDeniabilityToTarGz(@TempDir Path tempDir) throws Exception {
        byte[] realData = generateTestData(128 * 1024);
        byte[] decoyData = "TAR.GZ dual deniability decoy.\n".getBytes(StandardCharsets.UTF_8);

        Path realFile = createFile(tempDir, "secret.bin", realData);
        Path decoyFile = createFile(tempDir, "decoy.txt", decoyData);
        Path output = tempDir.resolve("dual_targz.ergou");

        EncryptRequest req = new EncryptRequest();
        req.setInputFile(realFile.toString());
        req.setDecoyFilePath(decoyFile.toString());
        req.setPassword("real-targz");
        req.setFakePassword("fake-targz");
        req.setDualDeniability(true);
        req.setOutputFile(output.toString());
        req.setArchiveFormat("TAR.GZ");
        req.setRsCodecs(rs);
        Encryptor.encrypt(req);

        Path archive = tempDir.resolve("dual_targz.ergou.tar.gz");
        assertTrue(Files.exists(archive));

        byte[] realResult = extractAndDecryptEgtD(archive, tempDir, null, "real-targz");
        assertArrayEquals(realData, realResult);
    }

    @Test
    void dualDeniabilitySplitToZip(@TempDir Path tempDir) throws Exception {
        byte[] realData = generateTestData(3 * 1024 * 1024); // 3 MiB, triggers split
        byte[] decoyData = generateTestData(100 * 1024);

        Path realFile = createFile(tempDir, "secret.bin", realData);
        Path decoyFile = createFile(tempDir, "decoy.bin", decoyData);
        Path output = tempDir.resolve("dual_split_out.ergou");

        EncryptRequest req = new EncryptRequest();
        req.setInputFile(realFile.toString());
        req.setDecoyFilePath(decoyFile.toString());
        req.setPassword("real-split-dual");
        req.setFakePassword("fake-split-dual");
        req.setDualDeniability(true);
        req.setSplit(true);
        req.setChunkSize(1); // 1 MiB
        req.setArchiveFormat("ZIP");
        req.setOutputFile(output.toString());
        req.setRsCodecs(rs);
        Encryptor.encrypt(req);

        // 分卷文件夹名：dual_split_out（strip .ergou），归档：dual_split_out.zip
        Path archive = tempDir.resolve("dual_split_out.zip");
        assertTrue(Files.exists(archive));

        // 真实密码解密
        byte[] realResult = extractSplitAndDecryptEgtD(archive, tempDir, null, "real-split-dual");
        assertArrayEquals(realData, realResult);

        // 钓鱼密码解密
        byte[] fakeResult = extractSplitAndDecryptEgtD(archive, tempDir, null, "fake-split-dual");
        assertArrayEquals(decoyData, fakeResult);
    }

    @Test
    void dualDeniabilitySplitTo7z(@TempDir Path tempDir) throws Exception {
        byte[] realData = generateTestData(2 * 1024 * 1024 + 500);
        byte[] decoyData = generateTestData(50 * 1024);

        Path realFile = createFile(tempDir, "secret.bin", realData);
        Path decoyFile = createFile(tempDir, "decoy.bin", decoyData);
        Path output = tempDir.resolve("dual_split_7z.ergou");

        EncryptRequest req = new EncryptRequest();
        req.setInputFile(realFile.toString());
        req.setDecoyFilePath(decoyFile.toString());
        req.setPassword("real-split-7z");
        req.setFakePassword("fake-split-7z");
        req.setDualDeniability(true);
        req.setSplit(true);
        req.setChunkSize(1);
        req.setArchiveFormat("7Z");
        req.setArchivePassword("dual-arch-split");
        req.setOutputFile(output.toString());
        req.setRsCodecs(rs);
        Encryptor.encrypt(req);

        Path archive = tempDir.resolve("dual_split_7z.7z");
        assertTrue(Files.exists(archive));

        byte[] realResult = extractSplitAndDecryptEgtD(archive, tempDir, "dual-arch-split", "real-split-7z");
        assertArrayEquals(realData, realResult);
    }

    @Test
    void dualDeniabilityAllOptionsToZip(@TempDir Path tempDir) throws Exception {
        // EGTD + paranoid + RS + split + ZIP
        byte[] realData = generateTestData(300 * 1024);
        byte[] decoyData = generateTestData(80 * 1024);

        Path realFile = createFile(tempDir, "secret.bin", realData);
        Path decoyFile = createFile(tempDir, "decoy.bin", decoyData);
        Path output = tempDir.resolve("dual_all.ergou");

        EncryptRequest req = new EncryptRequest();
        req.setInputFile(realFile.toString());
        req.setDecoyFilePath(decoyFile.toString());
        req.setPassword("real-all");
        req.setFakePassword("fake-all");
        req.setDualDeniability(true);
        req.setParanoid(true);
        req.setReedSolomon(true);
        req.setSplit(true);
        req.setChunkSize(50); // 50 KiB
        req.setArchiveFormat("ZIP");
        req.setOutputFile(output.toString());
        req.setRsCodecs(rs);
        Encryptor.encrypt(req);

        Path archive = tempDir.resolve("dual_all.zip");
        assertTrue(Files.exists(archive));

        byte[] realResult = extractSplitAndDecryptEgtD(archive, tempDir, null, "real-all");
        assertArrayEquals(realData, realResult);

        byte[] fakeResult = extractSplitAndDecryptEgtD(archive, tempDir, null, "fake-all");
        assertArrayEquals(decoyData, fakeResult);
    }

    // ================================================================
    // F. 边界条件
    // ================================================================

    @Test
    void emptyFileToZip(@TempDir Path tempDir) throws Exception {
        byte[] plaintext = new byte[0];
        Path input = createFile(tempDir, "empty.bin", plaintext);
        Path outputBase = tempDir.resolve("empty_out.ergou");

        EncryptRequest req = buildEncryptRequest(input.toString(), outputBase.toString(),
                "empty-pass", null, false, 0, "ZIP", null);
        Encryptor.encrypt(req);

        Path archive = tempDir.resolve("empty_out.ergou.zip");
        assertTrue(Files.exists(archive));

        byte[] decrypted = extractAndDecryptSingle(archive, tempDir, null, "empty-pass");
        assertEquals(0, decrypted.length, "empty file roundtrip should produce empty result");
    }

    @Test
    void emptyFileSplitToZip(@TempDir Path tempDir) throws Exception {
        // 空文件分卷：只产生一个分卷碎片
        byte[] plaintext = new byte[0];
        Path input = createFile(tempDir, "empty.bin", plaintext);
        Path outputBase = tempDir.resolve("empty_split_out.ergou");

        EncryptRequest req = buildEncryptRequest(input.toString(), outputBase.toString(),
                "empty-split", null, true, 1, "ZIP", null);
        Encryptor.encrypt(req);

        // 零字节文件加密后有 header，文件大小 > 0，所以分卷会产生至少一个碎片
        Path archive = tempDir.resolve("empty_split_out.zip");
        assertTrue(Files.exists(archive));

        byte[] decrypted = extractSplitAndDecrypt(archive, tempDir, null, "empty-split");
        assertEquals(0, decrypted.length);
    }

    @Test
    void largeFileSplitToZip(@TempDir Path tempDir) throws Exception {
        // 5 MiB+ 文件，1 MiB 分卷 → ≥5 个碎片
        byte[] plaintext = generateTestData(5 * 1024 * 1024 + 12345);
        Path input = createFile(tempDir, "large.bin", plaintext);
        Path outputBase = tempDir.resolve("large_out.ergou");

        EncryptRequest req = buildEncryptRequest(input.toString(), outputBase.toString(),
                "large-split", null, true, 1, "ZIP", null);
        Encryptor.encrypt(req);

        Path archive = tempDir.resolve("large_out.zip");
        assertTrue(Files.exists(archive));

        // 验证归档中碎片数量
        Path extractDir = tempDir.resolve("large_extract");
        Files.createDirectories(extractDir);
        List<Path> extracted = ArchiveExtractor.extract(archive, extractDir, null);
        assertTrue(extracted.size() >= 5,
                "should have at least 5 chunks for 5MiB+ file with 1MiB split");

        byte[] decrypted = extractSplitAndDecrypt(archive, tempDir, null, "large-split");
        assertArrayEquals(plaintext, decrypted);
    }

    @Test
    void noLeftoverFilesAfterArchive(@TempDir Path tempDir) throws Exception {
        byte[] plaintext = generateTestData(100 * 1024);
        Path input = createFile(tempDir, "input.bin", plaintext);
        Path outputBase = tempDir.resolve("clean_out.ergou");

        EncryptRequest req = buildEncryptRequest(input.toString(), outputBase.toString(),
                "clean-pass", null, false, 0, "ZIP", "clean-arch");
        Encryptor.encrypt(req);

        // 验证：不应残留 .incomplete、.tmp、原始 .ergou
        Path archive = tempDir.resolve("clean_out.ergou.zip");
        assertTrue(Files.exists(archive));

        try (Stream<Path> files = Files.list(tempDir)) {
            List<String> names = files.map(p -> p.getFileName().toString()).toList();
            boolean hasIncomplete = names.stream().anyMatch(n -> n.endsWith(".incomplete"));
            boolean hasTmp = names.stream().anyMatch(n -> n.endsWith(".tmp"));
            boolean hasErgou = names.stream().anyMatch(n -> n.endsWith(".ergou") && !n.endsWith(".ergou.zip"));

            assertFalse(hasIncomplete, "no .incomplete files should remain");
            assertFalse(hasTmp, "no .tmp files should remain");
            assertFalse(hasErgou, "original .ergou file should not remain after archiving");
        }
    }

    @Test
    void noLeftoverFilesAfterSplitArchive(@TempDir Path tempDir) throws Exception {
        byte[] plaintext = generateTestData(2 * 1024 * 1024);
        Path input = createFile(tempDir, "input.bin", plaintext);
        Path outputBase = tempDir.resolve("clean_split_out.ergou");

        EncryptRequest req = buildEncryptRequest(input.toString(), outputBase.toString(),
                "clean-split", null, true, 1, "ZIP", null);
        Encryptor.encrypt(req);

        // 分卷文件夹应被删除，只留下归档
        Path archive = tempDir.resolve("clean_split_out.zip");
        assertTrue(Files.exists(archive));

        Path chunkDir = tempDir.resolve("clean_split_out");
        assertFalse(Files.exists(chunkDir),
                "chunk folder should be deleted after archiving");

        try (Stream<Path> files = Files.list(tempDir)) {
            List<String> names = files.map(p -> p.getFileName().toString()).toList();
            boolean hasIncomplete = names.stream().anyMatch(n -> n.endsWith(".incomplete"));
            boolean hasTmp = names.stream().anyMatch(n -> n.endsWith(".tmp"));
            boolean hasErgouFiles = names.stream().anyMatch(n -> n.contains(".ergou."));

            assertFalse(hasIncomplete, "no .incomplete files should remain");
            assertFalse(hasTmp, "no .tmp files should remain");
            assertFalse(hasErgouFiles, "no chunk files should remain outside archive");
        }
    }

    @Test
    void wrongArchivePasswordFails(@TempDir Path tempDir) throws Exception {
        byte[] plaintext = generateTestData(50 * 1024);
        Path input = createFile(tempDir, "input.bin", plaintext);
        Path outputBase = tempDir.resolve("wrong_arch.ergou");

        EncryptRequest req = buildEncryptRequest(input.toString(), outputBase.toString(),
                "enc-pass", null, false, 0, "ZIP", "correct-arch-pass");
        Encryptor.encrypt(req);

        Path archive = tempDir.resolve("wrong_arch.ergou.zip");
        assertTrue(Files.exists(archive));

        // 用错误归档密码尝试解压，应失败
        Path extractDir = tempDir.resolve("wrong_extract");
        Files.createDirectories(extractDir);

        assertThrows(Exception.class, () ->
                ArchiveExtractor.extract(archive, extractDir, "wrong-arch-pass"),
                "wrong archive password should fail extraction");
    }

    @Test
    void differentPasswords(@TempDir Path tempDir) throws Exception {
        // 加密密码和归档密码不同，验证各自独立
        byte[] plaintext = generateTestData(120 * 1024);
        Path input = createFile(tempDir, "input.bin", plaintext);
        Path outputBase = tempDir.resolve("diff_pw.ergou");

        EncryptRequest req = buildEncryptRequest(input.toString(), outputBase.toString(),
                "encryption-password", null, false, 0, "ZIP", "archive-password");
        Encryptor.encrypt(req);

        Path archive = tempDir.resolve("diff_pw.ergou.zip");
        assertTrue(Files.exists(archive));

        // 用正确的归档密码 + 正确的加密密码 → 成功
        byte[] result = extractAndDecryptSingle(archive, tempDir, "archive-password", "encryption-password");
        assertArrayEquals(plaintext, result);

        // 用正确的归档密码 + 错误的加密密码 → 解密失败
        Path extractDir2 = tempDir.resolve("diff_extract2");
        Files.createDirectories(extractDir2);
        List<Path> extracted2 = ArchiveExtractor.extract(archive, extractDir2, "archive-password");
        Path ergouFile = findErgouFile(extracted2);
        assertNotNull(ergouFile, "archive should contain .ergou file");

        DecryptRequest badDec = new DecryptRequest();
        badDec.setInputFile(ergouFile.toString());
        badDec.setOutputFile(tempDir.resolve("bad_dec.bin").toString());
        badDec.setPassword("wrong-encryption-password");
        badDec.setRsCodecs(rs);
        assertThrows(Exception.class, () -> Decryptor.decrypt(badDec),
                "wrong encryption password should fail even with correct archive password");
    }

    // ================================================================
    // G. 密码处理
    // ================================================================

    @Test
    void nullArchivePassword(@TempDir Path tempDir) throws Exception {
        boolean saved = SettingsManager.isArchivePasswordFallback();
        SettingsManager.setArchivePasswordFallback(true);
        try {
            byte[] plaintext = generateTestData(80 * 1024);
            Path input = createFile(tempDir, "input.bin", plaintext);
            Path outputBase = tempDir.resolve("null_arch_pw.ergou");

            EncryptRequest req = buildEncryptRequest(input.toString(), outputBase.toString(),
                    "enc-pass", null, false, 0, "ZIP", null);
            req.setArchivePassword(null);
            Encryptor.encrypt(req);

            Path archive = tempDir.resolve("null_arch_pw.ergou.zip");
            assertTrue(Files.exists(archive));

            // 开启回退时：null/empty 归档密码回退到加密密码，ZIP 必须被原生加密
            assertTrue(ArchivePacker.isNativelyPasswordProtected(archive),
                    "empty archive password should fall back to encryption password");
            assertThrows(Exception.class, () ->
                    ArchiveExtractor.extract(archive, tempDir.resolve("nopwd"), null));
            byte[] decrypted = extractAndDecryptSingle(archive, tempDir, "enc-pass", "enc-pass");
            assertArrayEquals(plaintext, decrypted);
        } finally {
            SettingsManager.setArchivePasswordFallback(saved);
        }
    }

    @Test
    void emptyArchivePassword(@TempDir Path tempDir) throws Exception {
        boolean saved = SettingsManager.isArchivePasswordFallback();
        SettingsManager.setArchivePasswordFallback(true);
        try {
            byte[] plaintext = generateTestData(80 * 1024);
            Path input = createFile(tempDir, "input.bin", plaintext);
            Path outputBase = tempDir.resolve("empty_arch_pw.ergou");

            EncryptRequest req = buildEncryptRequest(input.toString(), outputBase.toString(),
                    "enc-pass", null, false, 0, "ZIP", "");
            Encryptor.encrypt(req);

            Path archive = tempDir.resolve("empty_arch_pw.ergou.zip");
            assertTrue(Files.exists(archive));

            assertTrue(ArchivePacker.isNativelyPasswordProtected(archive));
            byte[] decrypted = extractAndDecryptSingle(archive, tempDir, "enc-pass", "enc-pass");
            assertArrayEquals(plaintext, decrypted);
        } finally {
            SettingsManager.setArchivePasswordFallback(saved);
        }
    }

    @Test
    void archivePasswordOnly(@TempDir Path tempDir) throws Exception {
        // 无加密密码（passwordless）+ 归档密码
        byte[] plaintext = generateTestData(60 * 1024);
        Path input = createFile(tempDir, "input.bin", plaintext);
        Path outputBase = tempDir.resolve("arch_only.ergou");

        EncryptRequest req = buildEncryptRequest(input.toString(), outputBase.toString(),
                null, null, false, 0, "ZIP", "only-arch-pass");
        Encryptor.encrypt(req);

        Path archive = tempDir.resolve("arch_only.ergou.zip");
        assertTrue(Files.exists(archive));

        // 解密时不提供加密密码（passwordless），提供归档密码
        byte[] decrypted = extractAndDecryptSingle(archive, tempDir, "only-arch-pass", null);
        assertArrayEquals(plaintext, decrypted);
    }

    // ================================================================
    // 辅助方法
    // ================================================================

    /**
     * 构建加密请求（便捷方法）。
     */
    private EncryptRequest buildEncryptRequest(String inputFile, String outputFile,
                                                String password, List<String> keyfiles,
                                                boolean split, int chunkSize,
                                                String archiveFormat, String archivePassword) {
        EncryptRequest req = new EncryptRequest();
        req.setInputFile(inputFile);
        req.setOutputFile(outputFile);
        req.setPassword(password);
        if (keyfiles != null) {
            req.setKeyfiles(keyfiles);
        }
        req.setSplit(split);
        req.setChunkSize(chunkSize);
        req.setArchiveFormat(archiveFormat);
        req.setArchivePassword(archivePassword);
        req.setRsCodecs(rs);
        return req;
    }

    /**
     * 创建测试文件。
     */
    private static Path createFile(Path dir, String name, byte[] data) throws IOException {
        Path path = dir.resolve(name);
        Files.write(path, data);
        return path;
    }

    /**
     * 生成确定性测试数据。
     */
    private static byte[] generateTestData(int size) {
        byte[] data = new byte[size];
        for (int i = 0; i < size; i++) {
            data[i] = (byte) ((i * 7 + 1) & 0xff);
        }
        return data;
    }

    /**
     * 拼接两个字节数组。
     */
    private static byte[] concat(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }

    /**
     * 解压归档中的单个 .ergou 文件并解密，返回明文。
     *
     * @param archive    归档文件路径
     * @param destDir    目标目录
     * @param archivePw  归档密码（可为 null）
     * @param encPw      加密密码（可为 null，表示无密码模式）
     * @return 解密后的明文数据
     */
    private byte[] extractAndDecryptSingle(Path archive, Path destDir,
                                            String archivePw, String encPw) throws Exception {
        Path extractDir = destDir.resolve("extract_" + System.nanoTime());
        Files.createDirectories(extractDir);
        List<Path> extracted = ArchiveExtractor.extract(archive, extractDir, archivePw);
        Path ergouFile = findErgouFile(extracted);
        assertNotNull(ergouFile, "extracted files should contain a .ergou file, got: " + extracted);

        Path decrypted = extractDir.resolve("decrypted.bin");
        DecryptRequest decReq = new DecryptRequest();
        decReq.setInputFile(ergouFile.toString());
        decReq.setOutputFile(decrypted.toString());
        decReq.setPassword(encPw);
        decReq.setRsCodecs(rs);
        Decryptor.decrypt(decReq);

        assertTrue(Files.exists(decrypted), "decrypted file should exist");
        return Files.readAllBytes(decrypted);
    }

    /**
     * 解压分卷归档，重组碎片并解密，返回明文。
     */
    private byte[] extractSplitAndDecrypt(Path archive, Path destDir,
                                           String archivePw, String encPw) throws Exception {
        Path extractDir = destDir.resolve("split_extract_" + System.nanoTime());
        Files.createDirectories(extractDir);
        List<Path> extracted = ArchiveExtractor.extract(archive, extractDir, archivePw);
        assertFalse(extracted.isEmpty(), "extracted files should not be empty");

        // 找到第一个分卷碎片
        Path firstChunk = extracted.stream()
                .filter(p -> {
                    String name = p.getFileName().toString();
                    return name.matches(".*\\.ergou\\.[0-9]+") || name.matches(".*\\.pcv\\.[0-9]+");
                })
                .findFirst()
                .orElseThrow(() -> new AssertionError("no split chunk found in: " + extracted));

        Path decrypted = extractDir.resolve("decrypted.bin");
        DecryptRequest decReq = new DecryptRequest();
        decReq.setInputFile(firstChunk.toString());
        decReq.setOutputFile(decrypted.toString());
        decReq.setPassword(encPw);
        decReq.setRecombine(true);
        decReq.setRsCodecs(rs);
        Decryptor.decrypt(decReq);

        assertTrue(Files.exists(decrypted), "decrypted file should exist");
        return Files.readAllBytes(decrypted);
    }

    /**
     * 从归档中提取 EGTD 文件并用指定密码解密。
     *
     * <p>Decryptor 会自动检测 EGTD 格式并选择正确的 MetaBlock。
     *
     * @param archive   归档文件路径
     * @param destDir   目标目录
     * @param archivePw 归档密码（可为 null）
     * @param egtdPw    双卷密码（real 或 fake）
     * @return 解密后的明文数据
     */
    private byte[] extractAndDecryptEgtD(Path archive, Path destDir,
                                          String archivePw, String egtdPw) throws Exception {
        Path extractDir = destDir.resolve("egtd_extract_" + System.nanoTime());
        Files.createDirectories(extractDir);
        List<Path> extracted = ArchiveExtractor.extract(archive, extractDir, archivePw);
        Path egtdFile = findErgouFile(extracted);
        assertNotNull(egtdFile, "extracted files should contain EGTD .ergou file");

        // EGTD 格式会被 Decryptor 自动检测
        Path decrypted = extractDir.resolve("decrypted.bin");
        DecryptRequest decReq = new DecryptRequest();
        decReq.setInputFile(egtdFile.toString());
        decReq.setOutputFile(decrypted.toString());
        decReq.setPassword(egtdPw);
        decReq.setRsCodecs(rs);
        Decryptor.decrypt(decReq);

        assertTrue(Files.exists(decrypted), "decrypted EGTD file should exist");
        return Files.readAllBytes(decrypted);
    }

    /**
     * 解压分卷归档中的 EGTD 文件，重组碎片并解密。
     */
    private byte[] extractSplitAndDecryptEgtD(Path archive, Path destDir,
                                               String archivePw, String egtdPw) throws Exception {
        Path extractDir = destDir.resolve("egtd_split_extract_" + System.nanoTime());
        Files.createDirectories(extractDir);
        List<Path> extracted = ArchiveExtractor.extract(archive, extractDir, archivePw);
        assertFalse(extracted.isEmpty(), "extracted files should not be empty");

        // 找到第一个分卷碎片
        Path firstChunk = extracted.stream()
                .filter(p -> {
                    String name = p.getFileName().toString();
                    return name.matches(".*\\.ergou\\.[0-9]+");
                })
                .findFirst()
                .orElseThrow(() -> new AssertionError("no split chunk found in: " + extracted));

        // EGTD 分卷需要先重组再解密，Decryptor 会自动检测 EGTD
        Path decrypted = extractDir.resolve("decrypted.bin");
        DecryptRequest decReq = new DecryptRequest();
        decReq.setInputFile(firstChunk.toString());
        decReq.setOutputFile(decrypted.toString());
        decReq.setPassword(egtdPw);
        decReq.setRecombine(true);
        decReq.setRsCodecs(rs);
        Decryptor.decrypt(decReq);

        assertTrue(Files.exists(decrypted), "decrypted EGTD file should exist");
        return Files.readAllBytes(decrypted);
    }

    /**
     * 在解压文件列表中查找 .ergou 文件。
     *
     * <p>GZ 解压时临时解密文件的名称可能不含 .ergou 后缀，
     * 此时回退到返回列表中第一个普通文件。
     */
    private static Path findErgouFile(List<Path> files) {
        // 优先匹配已知后缀
        Path match = files.stream()
                .filter(p -> {
                    String name = p.getFileName().toString().toLowerCase();
                    return name.endsWith(".ergou") || name.endsWith(".pcv");
                })
                .findFirst()
                .orElse(null);
        if (match != null) {
            return match;
        }
        // 回退：返回第一个普通文件（GZ 解压后文件名可能不含 .ergou）
        return files.stream()
                .filter(Files::isRegularFile)
                .findFirst()
                .orElse(null);
    }
}
