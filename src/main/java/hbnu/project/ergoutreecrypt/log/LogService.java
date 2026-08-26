package hbnu.project.ergoutreecrypt.log;

import java.util.List;

/**
 * 应用日志服务门面。
 *
 * <p>提供进程级静态入口，供各模块记录操作、阶段、进度与错误，而不依赖 UI 或设置实现。
 * 平台启动时通过 {@link #register(MemoryLogBuffer, LogSink)} 注入缓冲与可选文件接收器；
 * 未注册时所有写入静默丢弃。
 *
 * <p>本类与加解密模块无循环依赖：业务只调用本门面，由桌面端负责注册、订阅与展示。
 *
 * @author ErgouTree
 * @since 2026/8/26
 */
public final class LogService {

    /** 内存缓冲，未注册时为 null。 */
    private static volatile MemoryLogBuffer buffer;

    /** 可选的额外接收器（通常为文件），未注册时为 null。 */
    private static volatile LogSink extraSink;

    /** 当前阈值，默认 INFO。 */
    private static volatile LogLevel level = LogLevel.INFO;

    /** 新操作开始时是否清空内存缓冲。 */
    private static volatile boolean clearOnNewOperation = true;

    /** 当前会话名称，供结束日志使用。 */
    private static volatile String sessionName;

    private LogService() {
    }

    /**
     * 注册内存缓冲与可选文件接收器。
     *
     * <p>通常在平台启动时调用一次；重复注册会替换原实现。
     *
     * @param memoryBuffer 内存缓冲；传 null 等价于未注册展示缓冲
     * @param extra        额外接收器（如文件），可为 null
     */
    public static void register(MemoryLogBuffer memoryBuffer, LogSink extra) {
        buffer = memoryBuffer;
        extraSink = extra;
        if (memoryBuffer != null) {
            memoryBuffer.applyLevel(level);
        }
    }

    /**
     * 将字节数格式化为适合日志阅读的短文本（B / KiB / MiB / GiB）。
     *
     * @param bytes 字节数
     * @return 如 {@code 12.30 MiB}
     */
    public static String humanSize(long bytes) {
        if (bytes < 1024L) {
            return bytes + " B";
        }
        double value = bytes;
        String[] units = {"B", "KiB", "MiB", "GiB", "TiB"};
        int unit = 0;
        while (value >= 1024 && unit < units.length - 1) {
            value /= 1024;
            unit++;
        }
        return String.format("%.2f %s", value, units[unit]);
    }

    /**
     * 注销全部接收器并恢复默认配置。供测试与进程退出使用。
     */
    public static void reset() {
        buffer = null;
        extraSink = null;
        level = LogLevel.INFO;
        clearOnNewOperation = true;
        sessionName = null;
    }

    /**
     * 设置记录阈值。低于该级别的事件不会进入任何接收器。
     *
     * @param newLevel 新阈值；null 视为 {@link LogLevel#INFO}
     */
    public static void setLevel(LogLevel newLevel) {
        LogLevel next = newLevel == null ? LogLevel.INFO : newLevel;
        level = next;
        MemoryLogBuffer current = buffer;
        if (current != null) {
            current.applyLevel(next);
        }
    }

    /**
     * 当前记录阈值。
     *
     * @return 级别
     */
    public static LogLevel getLevel() {
        return level;
    }

    /**
     * 诊断级别是否开启。热路径应先调用本方法再做字符串拼接。
     *
     * @return 当前阈值为 {@link LogLevel#TRACE} 时返回 {@code true}
     */
    public static boolean isTraceEnabled() {
        return level.includes(LogLevel.TRACE);
    }

    /**
     * 设置新操作开始时是否清空内存日志。
     *
     * @param clear true 表示每次 {@link #beginSession} 时清空
     */
    public static void setClearOnNewOperation(boolean clear) {
        clearOnNewOperation = clear;
    }

    /**
     * 新操作开始时是否清空内存日志。
     *
     * @return true 表示刷新
     */
    public static boolean isClearOnNewOperation() {
        return clearOnNewOperation;
    }

    /**
     * 开始一次操作会话。
     *
     * <p>若开启「每次刷新」，会先清空内存缓冲（文件日志不受影响），再写入一条 INFO 会话头。
     *
     * @param opName   操作名称（如 {@code GENERIC_ENCRYPT}）
     * @param fileName 相关文件名，可为 null
     */
    public static void beginSession(String opName, String fileName) {
        sessionName = opName == null ? "?" : opName;
        if (clearOnNewOperation) {
            MemoryLogBuffer current = buffer;
            if (current != null) {
                current.clear();
            }
        }
        String target = (fileName == null || fileName.isBlank()) ? "" : (": " + fileName);
        info("Session", "开始 " + sessionName + target);
    }

    /**
     * 结束当前操作会话。
     *
     * @param success     是否成功
     * @param elapsedMillis 耗时毫秒
     */
    public static void endSession(boolean success, long elapsedMillis) {
        String name = sessionName == null ? "?" : sessionName;
        String result = success ? "完成" : "失败";
        info("Session", result + " " + name, elapsedMillis);
        sessionName = null;
    }

    /**
     * 以「已取消」结束当前操作会话。
     *
     * @param elapsedMillis 耗时毫秒
     */
    public static void endSessionCancelled(long elapsedMillis) {
        String name = sessionName == null ? "?" : sessionName;
        info("Session", "取消 " + name, elapsedMillis);
        sessionName = null;
    }

    /**
     * 记录 INFO 事件。
     *
     * @param category 分类
     * @param message  消息
     */
    public static void info(String category, String message) {
        emit(LogLevel.INFO, category, message, null, null);
    }

    /**
     * 记录带耗时的 INFO 事件。
     *
     * @param category      分类
     * @param message       消息
     * @param elapsedMillis 耗时毫秒
     */
    public static void info(String category, String message, long elapsedMillis) {
        emit(LogLevel.INFO, category, message, elapsedMillis, null);
    }

    /**
     * 记录 WARN 事件。
     *
     * @param category 分类
     * @param message  消息
     */
    public static void warn(String category, String message) {
        emit(LogLevel.WARN, category, message, null, null);
    }

    /**
     * 记录 ERROR 事件。
     *
     * @param category 分类
     * @param message  消息
     */
    public static void error(String category, String message) {
        emit(LogLevel.ERROR, category, message, null, null);
    }

    /**
     * 记录带异常的 ERROR 事件。
     *
     * @param category  分类
     * @param message   消息
     * @param throwable 异常，可为 null
     */
    public static void error(String category, String message, Throwable throwable) {
        emit(LogLevel.ERROR, category, message, null, throwable);
    }

    /**
     * 记录 TRACE 事件。
     *
     * @param category 分类
     * @param message  消息
     */
    public static void trace(String category, String message) {
        emit(LogLevel.TRACE, category, message, null, null);
    }

    /**
     * 记录带耗时的 TRACE 事件。
     *
     * @param category      分类
     * @param message       消息
     * @param elapsedMillis 耗时毫秒
     */
    public static void trace(String category, String message, long elapsedMillis) {
        emit(LogLevel.TRACE, category, message, elapsedMillis, null);
    }

    /**
     * 清空内存缓冲。文件日志不受影响。
     */
    public static void clear() {
        MemoryLogBuffer current = buffer;
        if (current != null) {
            current.clear();
        }
    }

    /**
     * 返回内存缓冲快照（最旧在前）。未注册时返回空列表。
     *
     * @return 事件列表
     */
    public static List<LogEvent> snapshot() {
        MemoryLogBuffer current = buffer;
        return current == null ? List.of() : current.snapshot();
    }

    /**
     * 订阅内存缓冲变更。未注册缓冲时忽略。
     *
     * @param listener 监听器
     */
    public static void addListener(LogListener listener) {
        MemoryLogBuffer current = buffer;
        if (current != null) {
            current.addListener(listener);
        }
    }

    /**
     * 取消订阅。
     *
     * @param listener 监听器
     */
    public static void removeListener(LogListener listener) {
        MemoryLogBuffer current = buffer;
        if (current != null) {
            current.removeListener(listener);
        }
    }

    /**
     * 将内存日志格式化为多行文本，供导出。
     *
     * @return 导出文本；无记录时为空字符串
     */
    public static String exportText() {
        List<LogEvent> events = snapshot();
        if (events.isEmpty()) {
            return "";
        }
        StringBuilder sb = new StringBuilder(events.size() * 80);
        for (LogEvent event : events) {
            sb.append(event.formatLine()).append('\n');
        }
        return sb.toString();
    }

    /**
     * 按级别过滤后分发给已注册接收器。
     *
     * @param eventLevel    事件级别
     * @param category      分类
     * @param message       消息
     * @param elapsedMillis 可选耗时
     * @param throwable     可选异常
     */
    private static void emit(LogLevel eventLevel, String category, String message,
                             Long elapsedMillis, Throwable throwable) {
        if (!level.includes(eventLevel)) {
            return;
        }
        LogEvent event = new LogEvent(
                System.currentTimeMillis(),
                eventLevel,
                category == null ? "?" : category,
                message == null ? "" : message,
                elapsedMillis,
                LogEvent.summarize(throwable));
        MemoryLogBuffer current = buffer;
        if (current != null) {
            current.accept(event);
        }
        LogSink extra = extraSink;
        if (extra != null) {
            extra.accept(event);
        }
    }
}
