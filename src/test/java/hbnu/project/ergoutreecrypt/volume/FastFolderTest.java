package hbnu.project.ergoutreecrypt.volume;

import hbnu.project.ergoutreecrypt.header.VolumeFormatProbe;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;

/** FAST 文件夹与多选任务的模式、固定策略及失败保护回归。 */
final class FastFolderTest {
    /** @param root 独占目录 @throws Exception 模式遗漏或还原不一致 */
    @Test void allDepthsAndBatchUseFast(@TempDir Path root) throws Exception {
        Path source = Files.createDirectories(root.resolve("源/一/二/三"));
        Path file = Files.writeString(source.resolve("中文🔐.txt"), "真实目录模式快照");
        Path output = Files.createDirectory(root.resolve("输出"));
        var opts = options();
        opts.encryptDepth = 1;
        FolderCrypt.encryptFolder(root.resolve("源"), output, opts);
        try (var walk = Files.walk(output)) {
            Path cipher = walk.filter(Files::isRegularFile).findFirst().orElseThrow();
            assertTrue(cipher.endsWith(Path.of("一/二/三/中文🔐.txt.ergou")));
            assertTrue(VolumeFormatProbe.isFast(cipher));
            verify(file, cipher, root.resolve("还原"));
        }
        opts = options();
        opts.batchName = "批量";
        var pendingResult = new BatchResult();
        opts.batchResult = pendingResult;
        FolderCrypt.encryptFiles(java.util.List.of(file), output, opts);
        assertSame(pendingResult, opts.batchResult);
        assertEquals(1, pendingResult.succeededCount());
        verify(file, output.resolve("批量/中文🔐.txt.ergou"), root.resolve("批量还原"));
    }

    /** @param root 独占目录 @throws Exception 冲突晚于文件副作用或覆盖已有输出 */
    @Test void rejectBeforeSideEffectsAndProtectExistingArchive(@TempDir Path root) throws Exception {
        Path input = Files.createDirectory(root.resolve("源"));
        Files.writeString(input.resolve("a"), "原始内容");
        Path output = root.resolve("尚不存在");
        var bad = options();
        bad.split = true;
        bad.preArchiveFormat = "ZIP";
        assertThrows(Exception.class, () -> FolderCrypt.encryptFolder(input, output, bad));
        assertFalse(Files.exists(output));
        Files.createDirectory(output);
        Path existing = Files.writeString(output.resolve("源.zip"), "已有归档");
        var opts = options();
        opts.archiveFormat = "ZIP";
        assertThrows(Exception.class, () -> FolderCrypt.encryptFolder(input, output, opts));
        assertEquals("已有归档", Files.readString(existing));
        try (var walk = Files.walk(output)) {
            assertEquals(java.util.List.of(existing), walk.filter(Files::isRegularFile).toList());
        }
    }

    /** @return 固定 FAST 测试配置 */
    private static FolderCrypt.EncryptOptions options() {
        var opts = new FolderCrypt.EncryptOptions();
        opts.mode = EncryptionMode.FAST;
        opts.password = "目录测试🔐";
        return opts;
    }

    /** @param original 原文件 @param cipher 密文 @param output 还原输出 @throws Exception 认证或比对失败 */
    private static void verify(Path original, Path cipher, Path output) throws Exception {
        var auth = new VerifyRequest();
        auth.setInputFile(cipher.toString());
        auth.setPassword("目录测试🔐");
        assertTrue(Verifier.verify(auth));
        var decrypt = new DecryptRequest();
        decrypt.setInputFile(cipher.toString());
        decrypt.setOutputFile(output.toString());
        decrypt.setPassword("目录测试🔐");
        Decryptor.decrypt(decrypt);
        assertEquals(-1, Files.mismatch(original, output));
    }
}
