package hbnu.project.ergoutreecrypt.log;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.List;

/**
 * 将日志追加写入滚动文件，便于崩溃后排查。
 *
 * <p>文件位于构造时指定的目录下的 {@code app.log}；超过 {@value #MAX_BYTES}
 * 时轮转为 {@code app.log.1}，仅保留两代。写入失败静默忽略，不影响主流程。
 *
 * @author ErgouTree
 * @since 2026/8/26
 */
public final class FileLogSink implements LogSink {

    /** 单文件大小上限（2 MiB）。 */
    static final long MAX_BYTES = 2L * 1024 * 1024;

    /** 当前日志文件名。 */
    private static final String FILE_NAME = "app.log";

    /** 上一代滚动文件名。 */
    private static final String BACKUP_NAME = "app.log.1";

    /** 日志目录。 */
    private final Path dir;

    /**
     * 创建文件日志接收器。
     *
     * @param dir 日志目录（不存在时自动创建），不允许为 null
     */
    public FileLogSink(Path dir) {
        this.dir = dir;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public synchronized void accept(LogEvent event) {
        if (event == null) {
            return;
        }
        Path file = dir.resolve(FILE_NAME);
        try {
            Files.createDirectories(dir);
            rollIfNeeded(file);
            Files.write(file, List.of(event.formatLine()), StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException ignored) {
            // 文件日志失败不影响主流程
        }
    }

    /**
     * 当前文件超过上限时轮转：{@code app.log} → {@code app.log.1}。
     *
     * @param file 当前日志文件
     */
    private void rollIfNeeded(Path file) {
        try {
            if (!Files.isRegularFile(file) || Files.size(file) < MAX_BYTES) {
                return;
            }
            Path backup = dir.resolve(BACKUP_NAME);
            Files.deleteIfExists(backup);
            Files.move(file, backup);
        } catch (IOException ignored) {
            // 轮转失败时继续向原文件追加
        }
    }
}
