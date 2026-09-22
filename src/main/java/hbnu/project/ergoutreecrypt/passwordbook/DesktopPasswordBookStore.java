package hbnu.project.ergoutreecrypt.passwordbook;

import java.io.IOException;
import java.io.Reader;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.List;

/**
 * 桌面端密码本的本地文件存储。
 *
 * <p>密码本保存在当前用户专用配置目录中；导入与导出均复用相同 CSV 格式。
 *
 * @author ErgouTree
 * @since 2026/9/22
 */
public final class DesktopPasswordBookStore {

    private static final Path STORE_PATH = Path.of(
            System.getProperty("user.home"), ".ergoutreecrypt", "password-book.csv");

    private DesktopPasswordBookStore() {
    }

    /**
     * 读取当前用户密码本。
     *
     * @return 密码记录；文件不存在或损坏时返回空列表
     */
    public static synchronized List<PasswordBookEntry> load() {
        if (!Files.isRegularFile(STORE_PATH)) {
            return List.of();
        }
        try (Reader reader = Files.newBufferedReader(STORE_PATH, StandardCharsets.UTF_8)) {
            return PasswordBookCsv.read(reader);
        } catch (IOException ignored) {
            return List.of();
        }
    }

    /**
     * 原子保存当前用户密码本。
     *
     * @param entries 待保存记录
     * @throws IOException 创建目录或写入失败时抛出
     */
    public static synchronized void save(List<PasswordBookEntry> entries) throws IOException {
        Files.createDirectories(STORE_PATH.getParent());
        Path temporary = STORE_PATH.resolveSibling(STORE_PATH.getFileName() + ".tmp");
        try (Writer writer = Files.newBufferedWriter(temporary, StandardCharsets.UTF_8)) {
            PasswordBookCsv.write(entries, writer);
        }
        try {
            Files.move(temporary, STORE_PATH,
                    StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException atomicMoveFailure) {
            Files.move(temporary, STORE_PATH, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    /**
     * 从外部 CSV 文件导入并替换密码本。
     *
     * @param source CSV 文件路径
     * @return 导入后的记录
     * @throws IOException 读取、解析或保存失败时抛出
     */
    public static synchronized List<PasswordBookEntry> importCsv(Path source) throws IOException {
        List<PasswordBookEntry> entries;
        try (Reader reader = Files.newBufferedReader(source, StandardCharsets.UTF_8)) {
            entries = PasswordBookCsv.read(reader);
        }
        save(entries);
        return entries;
    }

    /**
     * 将当前密码本导出到指定 CSV 文件。
     *
     * @param target CSV 文件路径
     * @throws IOException 写入失败时抛出
     */
    public static synchronized void exportCsv(Path target) throws IOException {
        try (Writer writer = Files.newBufferedWriter(target, StandardCharsets.UTF_8)) {
            PasswordBookCsv.write(load(), writer);
        }
    }
}
