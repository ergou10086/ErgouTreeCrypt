package hbnu.project.ergoutreecrypt.passwordbook;

import java.io.IOException;
import java.io.Reader;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
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
     * @return 密码记录；仅文件不存在时返回空列表
     * @throws IOException 文件无法读取或内容损坏时抛出
     */
    public static synchronized List<PasswordBookEntry> load() throws IOException {
        return load(STORE_PATH);
    }

    /**
     * 获取当前用户密码本的实际保存位置，不依赖程序安装目录。
     *
     * @return 本地 CSV 文件路径
     */
    public static Path getStorePath() {
        return STORE_PATH;
    }

    /**
     * 读取指定密码本，不把权限错误或损坏文件伪装为空密码本。
     *
     * @param path 密码本路径
     * @return 密码记录
     * @throws IOException 读取或解析失败时抛出
     */
    static List<PasswordBookEntry> load(Path path) throws IOException {
        try (Reader reader = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
            return PasswordBookCsv.read(reader);
        } catch (NoSuchFileException missing) {
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
        save(STORE_PATH, entries);
    }

    /**
     * 在同目录临时文件写入完成后替换目标文件，失败时清理临时密码副本。
     *
     * @param path 密码本路径
     * @param entries 待保存记录
     * @throws IOException 创建目录或写入失败时抛出
     */
    static void save(Path path, List<PasswordBookEntry> entries) throws IOException {
        Path target = path.toAbsolutePath();
        Files.createDirectories(target.getParent());
        Path temporary = Files.createTempFile(target.getParent(), "password-book-", ".tmp");
        try {
            try (Writer writer = Files.newBufferedWriter(temporary, StandardCharsets.UTF_8)) {
                PasswordBookCsv.write(entries, writer);
            }
            try {
                Files.move(temporary, target,
                        StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException unsupported) {
                Files.move(temporary, target, StandardCopyOption.REPLACE_EXISTING);
            }
        } finally {
            Files.deleteIfExists(temporary);
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
        List<PasswordBookEntry> entries = load();
        save(target, entries);
    }
}
