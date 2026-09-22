package hbnu.project.ergoutreecrypt.ui.support;

import hbnu.project.ergoutreecrypt.log.LogService;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.stream.Stream;

/**
 * 成功恢复输出后安全删除源文件的桌面端辅助工具。
 *
 * @author ErgouTree
 * @since 2026/9/22
 */
public final class SourceDeletion {

    private SourceDeletion() {
    }

    /**
     * 删除源文件或目录，并阻止删除包含输出结果的目录。
     *
     * @param source     待删除源路径
     * @param outputRoot 输出文件或目录路径，可为 null
     * @return 删除成功或源路径已不存在时返回 true
     */
    public static boolean deleteAfterSuccess(Path source, Path outputRoot) {
        if (source == null) {
            return false;
        }
        Path normalizedSource = source.toAbsolutePath().normalize();
        Path normalizedOutput = outputRoot == null
                ? null : outputRoot.toAbsolutePath().normalize();
        if (normalizedOutput != null && (normalizedSource.equals(normalizedOutput)
                || normalizedOutput.startsWith(normalizedSource))) {
            LogService.error("SourceDeletion", "为保护输出结果，未删除包含输出的源路径: "
                    + normalizedSource);
            return false;
        }
        try {
            if (Files.isDirectory(normalizedSource)) {
                try (Stream<Path> paths = Files.walk(normalizedSource)) {
                    for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) {
                        Files.deleteIfExists(path);
                    }
                }
            } else {
                Files.deleteIfExists(normalizedSource);
            }
            return !Files.exists(normalizedSource);
        } catch (IOException exception) {
            LogService.error("SourceDeletion", "删除解密源文件失败: " + normalizedSource,
                    exception);
            return false;
        }
    }
}
