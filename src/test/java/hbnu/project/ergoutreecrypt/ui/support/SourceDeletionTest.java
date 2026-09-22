package hbnu.project.ergoutreecrypt.ui.support;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 解密成功后源路径删除规则测试。
 */
class SourceDeletionTest {

    /** 测试临时目录。 */
    @TempDir
    Path tempDir;

    /**
     * 验证普通源文件可以在输出成功后删除。
     *
     * @throws IOException 测试文件创建失败时抛出
     */
    @Test
    void deletesSourceFile() throws IOException {
        Path source = Files.writeString(tempDir.resolve("secret.ergou"), "cipher");
        Path output = Files.writeString(tempDir.resolve("secret.txt"), "plain");

        assertTrue(SourceDeletion.deleteAfterSuccess(source, output));
        assertFalse(Files.exists(source));
        assertTrue(Files.exists(output));
    }

    /**
     * 验证输出位于源目录内部时拒绝删除整个源目录。
     *
     * @throws IOException 测试目录创建失败时抛出
     */
    @Test
    void keepsSourceDirectoryContainingOutput() throws IOException {
        Path source = Files.createDirectory(tempDir.resolve("encrypted-folder"));
        Path output = Files.writeString(source.resolve("restored.txt"), "plain");

        assertFalse(SourceDeletion.deleteAfterSuccess(source, output));
        assertTrue(Files.exists(output));
    }
}
