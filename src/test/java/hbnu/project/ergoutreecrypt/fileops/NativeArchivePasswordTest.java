package hbnu.project.ergoutreecrypt.fileops;

import hbnu.project.ergoutreecrypt.encoding.RsCodecs;
import hbnu.project.ergoutreecrypt.settings.SettingsManager;
import hbnu.project.ergoutreecrypt.volume.EncryptRequest;
import hbnu.project.ergoutreecrypt.volume.Encryptor;
import net.lingala.zip4j.ZipFile;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 归档密码保护测试。
 *
 * <p>覆盖两类加密方式：
 * <ul>
 *   <li><b>ZIP 原生 AES：</b>始终可加密，不受「工具特有加密」开关影响。</li>
 *   <li><b>GZ / TAR.GZ / 7Z 工具特有加密（MAGIC 包裹）：</b>仅当
 *       {@link SettingsManager#isArchiveCustomEncryption()} 开启时才加密；
 *       关闭时忽略密码，生成明文归档。</li>
 * </ul>
 *
 * @author ErgouTree
 */
public final class NativeArchivePasswordTest {

    /** 测试前保存的「工具特有加密」开关，用于还原。 */
    private boolean savedCustomEnc;

    /** 测试前保存的「归档密码回退」开关，用于还原。 */
    private boolean savedFallback;

    /**
     * 保存并复位归档相关设置。
     */
    @BeforeEach
    void saveSettings() {
        savedCustomEnc = SettingsManager.isArchiveCustomEncryption();
        savedFallback = SettingsManager.isArchivePasswordFallback();
        SettingsManager.setArchiveCustomEncryption(false);
        SettingsManager.setArchivePasswordFallback(false);
    }

    /**
     * 还原归档相关设置。
     */
    @AfterEach
    void restoreSettings() {
        SettingsManager.setArchiveCustomEncryption(savedCustomEnc);
        SettingsManager.setArchivePasswordFallback(savedFallback);
    }

    // ================================================================
    // resolveArchivePassword 语义
    // ================================================================

    /**
     * ZIP 不受工具特有加密开关影响：显式密码有效，回退按 fallback 开关。
     */
    @Test
    void resolveForZip() {
        SettingsManager.setArchiveCustomEncryption(false);
        SettingsManager.setArchivePasswordFallback(false);
        assertEquals("arch", ArchivePacker.resolveArchivePassword("arch", "enc",
                ArchivePacker.Format.ZIP));
        assertNull(ArchivePacker.resolveArchivePassword(null, "enc", ArchivePacker.Format.ZIP));

        SettingsManager.setArchivePasswordFallback(true);
        assertEquals("enc", ArchivePacker.resolveArchivePassword(null, "enc",
                ArchivePacker.Format.ZIP));
    }

    /**
     * GZ / TAR.GZ / 7Z：工具特有加密关闭时一律返回 null（明文）。
     */
    @Test
    void resolveForNonZipWhenCustomOff() {
        SettingsManager.setArchiveCustomEncryption(false);
        SettingsManager.setArchivePasswordFallback(true);
        for (ArchivePacker.Format fmt : new ArchivePacker.Format[]{
                ArchivePacker.Format.GZ, ArchivePacker.Format.TAR_GZ, ArchivePacker.Format._7Z}) {
            assertNull(ArchivePacker.resolveArchivePassword("arch", "enc", fmt),
                    "custom encryption off must ignore password for " + fmt);
            assertNull(ArchivePacker.resolveArchivePassword(null, "enc", fmt));
        }
    }

    /**
     * GZ / TAR.GZ / 7Z：工具特有加密开启时，显式密码有效，空则按 fallback 回退。
     */
    @Test
    void resolveForNonZipWhenCustomOn() {
        SettingsManager.setArchiveCustomEncryption(true);
        SettingsManager.setArchivePasswordFallback(false);
        assertEquals("arch", ArchivePacker.resolveArchivePassword("arch", "enc",
                ArchivePacker.Format._7Z));
        assertNull(ArchivePacker.resolveArchivePassword(null, "enc",
                ArchivePacker.Format._7Z));

        SettingsManager.setArchivePasswordFallback(true);
        assertEquals("enc", ArchivePacker.resolveArchivePassword(null, "enc",
                ArchivePacker.Format.GZ));
    }

    // ================================================================
    // ZIP 原生加密
    // ================================================================

    /**
     * ZIP：显式归档密码必须原生加密，无密码解压失败。
     *
     * @param dir 临时目录
     */
    @Test
    void zipExplicitArchivePasswordIsNative(@TempDir Path dir) throws Exception {
        Path plain = dir.resolve("a.txt");
        Files.writeString(plain, "secret-zip", StandardCharsets.UTF_8);
        Path zip = dir.resolve("a.zip");
        ArchivePacker.pack(zip, plain, ArchivePacker.Format.ZIP, "zip-arch-pw");

        assertTrue(ArchivePacker.isNativelyPasswordProtected(zip));
        try (ZipFile zf = new ZipFile(zip.toFile())) {
            assertTrue(zf.isEncrypted());
        }
        assertThrows(Exception.class, () ->
                ArchiveExtractor.extract(zip, dir.resolve("nopwd"), null));
        List<Path> ok = ArchiveExtractor.extract(zip, dir.resolve("ok"), "zip-arch-pw");
        assertEquals("secret-zip", Files.readString(ok.getFirst()));
    }

    // ================================================================
    // 7Z 工具特有加密（MAGIC 包裹）
    // ================================================================

    /**
     * 7Z：工具特有加密开启 + 显式密码 → 生成 MAGIC 包裹，无密码解压失败。
     *
     * @param dir 临时目录
     */
    @Test
    void sevenZCustomEncryptionWraps(@TempDir Path dir) throws Exception {
        SettingsManager.setArchiveCustomEncryption(true);
        Path input = dir.resolve("b.bin");
        Files.write(input, "secret-7z-payload".getBytes(StandardCharsets.UTF_8));
        Path out = dir.resolve("b.ergou");

        EncryptRequest req = new EncryptRequest();
        req.setInputFile(input.toString());
        req.setOutputFile(out.toString());
        req.setPassword("enc-7z");
        req.setArchiveFormat("7Z");
        req.setArchivePassword("arch-7z");
        req.setRsCodecs(new RsCodecs());
        Encryptor.encrypt(req);

        Path archive = dir.resolve("b.ergou.7z");
        assertTrue(Files.exists(archive));
        assertFalse(ArchivePacker.isNativelyPasswordProtected(archive),
                "7Z no longer uses native AES");
        assertTrue(ArchiveExtractor.isEncryptedFile(archive),
                "7Z with password should be MAGIC-wrapped");
        assertThrows(Exception.class, () ->
                ArchiveExtractor.extract(archive, dir.resolve("nopwd"), null));
        List<Path> ok = ArchiveExtractor.extract(archive, dir.resolve("ok"), "arch-7z");
        assertFalse(ok.isEmpty());
    }

    /**
     * 7Z：工具特有加密关闭时，即使填了归档密码也生成明文（无 MAGIC）。
     *
     * @param dir 临时目录
     */
    @Test
    void sevenZPlainWhenCustomOff(@TempDir Path dir) throws Exception {
        SettingsManager.setArchiveCustomEncryption(false);
        Path input = dir.resolve("c.bin");
        Files.write(input, "plain-7z-payload".getBytes(StandardCharsets.UTF_8));
        Path out = dir.resolve("c.ergou");

        EncryptRequest req = new EncryptRequest();
        req.setInputFile(input.toString());
        req.setOutputFile(out.toString());
        req.setPassword("enc-7z");
        req.setArchiveFormat("7Z");
        req.setArchivePassword("arch-7z");
        req.setRsCodecs(new RsCodecs());
        Encryptor.encrypt(req);

        Path archive = dir.resolve("c.ergou.7z");
        assertTrue(Files.exists(archive));
        assertFalse(ArchiveExtractor.isEncryptedFile(archive),
                "custom encryption off should produce plain 7Z");
        // 明文 7Z 可无密码解压得到内部 .ergou
        List<Path> extracted = ArchiveExtractor.extract(archive, dir.resolve("ok"), null);
        assertFalse(extracted.isEmpty());
    }

    // ================================================================
    // GZ / TAR.GZ 工具特有加密
    // ================================================================

    /**
     * GZ：工具特有加密开启 + 密码 → MAGIC 包裹。
     *
     * @param dir 临时目录
     */
    @Test
    void gzCustomEncryptionWraps(@TempDir Path dir) throws Exception {
        SettingsManager.setArchiveCustomEncryption(true);
        Path input = dir.resolve("d.bin");
        Files.write(input, "gz-payload".getBytes(StandardCharsets.UTF_8));
        Path out = dir.resolve("d.ergou");

        EncryptRequest req = new EncryptRequest();
        req.setInputFile(input.toString());
        req.setOutputFile(out.toString());
        req.setPassword("enc-gz");
        req.setArchiveFormat("GZ");
        req.setArchivePassword("arch-gz");
        req.setRsCodecs(new RsCodecs());
        Encryptor.encrypt(req);

        Path archive = dir.resolve("d.ergou.gz");
        assertTrue(Files.exists(archive));
        assertTrue(ArchiveExtractor.isEncryptedFile(archive),
                "GZ with password should be MAGIC-wrapped");
        assertThrows(Exception.class, () ->
                ArchiveExtractor.extract(archive, dir.resolve("nopwd"), null));
        List<Path> ok = ArchiveExtractor.extract(archive, dir.resolve("ok"), "arch-gz");
        assertFalse(ok.isEmpty());
    }

    /**
     * GZ：工具特有加密关闭时生成明文（无 MAGIC）。
     *
     * @param dir 临时目录
     */
    @Test
    void gzPlainWhenCustomOff(@TempDir Path dir) throws Exception {
        SettingsManager.setArchiveCustomEncryption(false);
        Path input = dir.resolve("e.bin");
        Files.write(input, "gz-plain".getBytes(StandardCharsets.UTF_8));
        Path out = dir.resolve("e.ergou");

        EncryptRequest req = new EncryptRequest();
        req.setInputFile(input.toString());
        req.setOutputFile(out.toString());
        req.setPassword("enc-gz");
        req.setArchiveFormat("GZ");
        req.setArchivePassword("arch-gz");
        req.setRsCodecs(new RsCodecs());
        Encryptor.encrypt(req);

        Path archive = dir.resolve("e.ergou.gz");
        assertTrue(Files.exists(archive));
        assertFalse(ArchiveExtractor.isEncryptedFile(archive),
                "custom encryption off should produce plain GZ");
    }

    // ================================================================
    // ZIP 加密后压缩回退
    // ================================================================

    /**
     * ZIP 加密后压缩：归档密码为空 + 回退开启 → 使用加密密码原生加密。
     *
     * @param dir 临时目录
     */
    @Test
    void encryptThenZipFallsBack(@TempDir Path dir) throws Exception {
        SettingsManager.setArchivePasswordFallback(true);
        Path input = dir.resolve("f.bin");
        Files.write(input, "zip-fallback".getBytes(StandardCharsets.UTF_8));
        Path out = dir.resolve("f.ergou");

        EncryptRequest req = new EncryptRequest();
        req.setInputFile(input.toString());
        req.setOutputFile(out.toString());
        req.setPassword("my-enc-password");
        req.setArchiveFormat("ZIP");
        req.setArchivePassword(null);
        req.setRsCodecs(new RsCodecs());
        Encryptor.encrypt(req);

        Path zip = dir.resolve("f.ergou.zip");
        assertTrue(ArchivePacker.isNativelyPasswordProtected(zip));
        List<Path> ok = ArchiveExtractor.extract(zip, dir.resolve("ok"), "my-enc-password");
        assertFalse(ok.isEmpty());
    }

    /**
     * ZIP 加密后压缩：回退关闭 + 空归档密码 → 明文 ZIP。
     *
     * @param dir 临时目录
     */
    @Test
    void encryptThenZipPlainWhenFallbackOff(@TempDir Path dir) throws Exception {
        SettingsManager.setArchivePasswordFallback(false);
        Path input = dir.resolve("g.bin");
        Files.write(input, "zip-plain".getBytes(StandardCharsets.UTF_8));
        Path out = dir.resolve("g.ergou");

        EncryptRequest req = new EncryptRequest();
        req.setInputFile(input.toString());
        req.setOutputFile(out.toString());
        req.setPassword("my-enc-password");
        req.setArchiveFormat("ZIP");
        req.setArchivePassword(null);
        req.setRsCodecs(new RsCodecs());
        Encryptor.encrypt(req);

        Path zip = dir.resolve("g.ergou.zip");
        assertFalse(ArchivePacker.isNativelyPasswordProtected(zip),
                "fallback off + empty archive password should produce plain ZIP");
        List<Path> extracted = ArchiveExtractor.extract(zip, dir.resolve("ok"), null);
        assertFalse(extracted.isEmpty());
    }
}
