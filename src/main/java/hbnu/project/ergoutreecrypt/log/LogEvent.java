package hbnu.project.ergoutreecrypt.log;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

/**
 * 一条应用日志事件。
 *
 * <p>只携带排障所需的非敏感信息：时间、级别、分类、消息，以及可选的耗时与异常摘要。
 * 不得包含密码、派生密钥、MAC key、密钥文件内容或明文片段。
 * 开启 JVM 底层日志时，{@code exceptionSummary} 可为多行堆栈。
 *
 * @param timestampEpochMillis 事件时间（Unix 毫秒）
 * @param level                日志级别
 * @param category             分类（如 {@code Encryptor}），不允许为 null
 * @param message              消息正文，不允许为 null
 * @param elapsedMillis        可选耗时（毫秒）；无则 {@code null}
 * @param exceptionSummary     可选异常摘要（类型 + message）；无则 {@code null}
 * @author ErgouTree
 * @since 2026/8/26
 */
public record LogEvent(
        long timestampEpochMillis,
        LogLevel level,
        String category,
        String message,
        Long elapsedMillis,
        String exceptionSummary) {

    /** 展示与导出共用的时间格式。 */
    private static final DateTimeFormatter TIME_FORMAT =
            DateTimeFormatter.ofPattern("HH:mm:ss.SSS");

    /**
     * 格式化为文本，供界面展示与文件导出。
     *
     * <p>形如 {@code 14:32:05.123  INFO  [Encryptor] 开始加密 demo.zip (12.3 MiB)}。
     * 开启 JVM 诊断且带异常时，摘要可能跨多行。
     *
     * @return 日志文本
     */
    public String formatLine() {
        StringBuilder sb = new StringBuilder(96);
        sb.append(TIME_FORMAT.format(
                Instant.ofEpochMilli(timestampEpochMillis).atZone(ZoneId.systemDefault())));
        sb.append("  ");
        sb.append(padLevel(level));
        sb.append("  [").append(category == null ? "?" : category).append("] ");
        sb.append(message == null ? "" : message);
        if (elapsedMillis != null) {
            sb.append(" (").append(elapsedMillis).append(" ms)");
        }
        if (exceptionSummary != null && !exceptionSummary.isBlank()) {
            sb.append(" | ").append(exceptionSummary);
        }
        return sb.toString();
    }

    /**
     * 将级别名对齐到 5 字符，便于多行等宽阅读。
     *
     * @param level 级别
     * @return 定宽级别文本
     */
    private static String padLevel(LogLevel level) {
        if (level == null) {
            return "     ";
        }
        String name = level.name();
        if (name.length() >= 5) {
            return name;
        }
        return name + " ".repeat(5 - name.length());
    }

    /**
     * 从异常生成简短摘要：类简名 + {@code getMessage()}。
     *
     * @param throwable 异常，可为 null
     * @return 摘要文本；throwable 为 null 时返回 null
     */
    public static String summarize(Throwable throwable) {
        if (throwable == null) {
            return null;
        }
        String type = throwable.getClass().getSimpleName();
        String msg = throwable.getMessage();
        if (msg == null || msg.isBlank()) {
            return type;
        }
        return type + ": " + msg;
    }

    /**
     * 生成含线程名、堆栈与 cause 链的诊断文本。
     *
     * <p>供 JVM 底层日志开启时使用。帧数与 cause 深度有上限，避免 OOM 时日志再次撑爆内存。
     *
     * @param throwable 异常，可为 null
     * @return 多行堆栈；throwable 为 null 时返回 null
     */
    public static String stackDump(Throwable throwable) {
        if (throwable == null) {
            return null;
        }
        StringBuilder sb = new StringBuilder(512);
        sb.append("thread=").append(Thread.currentThread().getName());
        Throwable current = throwable;
        int depth = 0;
        while (current != null && depth < 8) {
            if (depth == 0) {
                sb.append('\n').append(summarize(current));
            } else {
                sb.append("\nCaused by: ").append(summarize(current));
            }
            StackTraceElement[] frames = current.getStackTrace();
            int limit = Math.min(frames.length, 48);
            for (int i = 0; i < limit; i++) {
                sb.append("\n  at ").append(frames[i]);
            }
            if (frames.length > limit) {
                sb.append("\n  ... ").append(frames.length - limit).append(" more");
            }
            current = current.getCause();
            depth++;
        }
        return sb.toString();
    }
}
