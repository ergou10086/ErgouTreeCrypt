package hbnu.project.ergoutreecrypt.passwordbook;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** 验证桌面密码本的本地创建、替换和失败保护，不访问真实用户密码本。 */
class DesktopPasswordBookStoreTest {
    @TempDir
    Path directory;

    /** 首次保存自动创建用户数据目录及 CSV 文件。 */
    @Test
    void createsMissingDirectoriesAndRoundTripsPasswords() throws IOException {
        Path path = directory.resolve("新用户/.ergoutreecrypt/password-book.csv");
        List<PasswordBookEntry> entries = List.of(
                new PasswordBookEntry("测试,名称", " test,\"value\" "),
                new PasswordBookEntry("多行", "line1\nline2"));
        assertTrue(DesktopPasswordBookStore.load(path).isEmpty());
        DesktopPasswordBookStore.save(path, entries);
        assertTrue(Files.isRegularFile(path));
        assertEquals(entries, DesktopPasswordBookStore.load(path));
    }

    /** 更新与删除最后一条记录均可以再次读取。 */
    @Test
    void replacesExistingFileAndPersistsEmptyBook() throws IOException {
        Path path = directory.resolve("password-book.csv");
        DesktopPasswordBookStore.save(path, List.of(new PasswordBookEntry("旧名称", "old")));
        List<PasswordBookEntry> updated = List.of(new PasswordBookEntry("新名称", "new"));
        DesktopPasswordBookStore.save(path, updated);
        assertEquals(updated, DesktopPasswordBookStore.load(path));
        DesktopPasswordBookStore.save(path, List.of());
        assertEquals(List.of(), DesktopPasswordBookStore.load(path));
        assertEquals(List.of(path), children(directory));
    }

    /** 损坏文件不会被静默解释为空密码本，也不会被读取操作改写。 */
    @Test
    void reportsCorruptionWithoutChangingFile() throws IOException {
        Path path = directory.resolve("password-book.csv");
        String broken = "name,password\n测试,\"unterminated";
        Files.writeString(path, broken);
        assertThrows(IOException.class, () -> DesktopPasswordBookStore.load(path));
        assertEquals(broken, Files.readString(path));
    }

    /** 路径指向目录时报告错误，只有文件确实不存在才返回空列表。 */
    @Test
    void doesNotHideInvalidStoragePath() {
        assertThrows(IOException.class, () -> DesktopPasswordBookStore.load(directory));
    }

    /** 替换失败时保留已有目标并清理包含明文的临时文件。 */
    @Test
    void failedReplacementCleansTemporaryFile() throws IOException {
        Path target = Files.createDirectory(directory.resolve("password-book.csv"));
        Path existing = Files.writeString(target.resolve("keep.txt"), "existing");
        assertThrows(IOException.class, () -> DesktopPasswordBookStore.save(target,
                List.of(new PasswordBookEntry("测试", "not-a-real-password"))));
        assertEquals("existing", Files.readString(existing));
        assertEquals(List.of(target), children(directory));
    }

    /** 写入尚未完成时出错不能破坏已保存的密码本。 */
    @Test
    void failedWritePreservesPreviousBook() throws IOException {
        Path path = directory.resolve("password-book.csv");
        List<PasswordBookEntry> entries = List.of(new PasswordBookEntry("测试", "value"));
        DesktopPasswordBookStore.save(path, entries);
        assertThrows(NullPointerException.class, () -> DesktopPasswordBookStore.save(path, null));
        assertEquals(entries, DesktopPasswordBookStore.load(path));
        assertEquals(List.of(path), children(directory));
    }

    /**
     * 列出测试目录内容，用于检查临时文件清理。
     *
     * @param path 测试目录
     * @return 子路径列表
     * @throws IOException 列目录失败时抛出
     */
    private static List<Path> children(Path path) throws IOException {
        try (var paths = Files.list(path)) {
            return paths.toList();
        }
    }
}
