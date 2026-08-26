package hbnu.project.ergoutreecrypt.log;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * 线程安全的内存环形日志缓冲。
 *
 * <p>超出容量时丢弃最旧事件。容量随当前日志级别调整：标准（INFO）约
 * {@value #INFO_CAPACITY} 条，诊断（TRACE）约 {@value #TRACE_CAPACITY} 条。
 *
 * @author ErgouTree
 * @since 2026/8/26
 */
public final class MemoryLogBuffer implements LogSink {

    /** 标准级别下的缓冲上限。 */
    public static final int INFO_CAPACITY = 2000;

    /** 诊断级别下的缓冲上限。 */
    public static final int TRACE_CAPACITY = 20_000;

    /** 按时间顺序保存的事件（最旧在前）。 */
    private final ArrayDeque<LogEvent> events = new ArrayDeque<>();

    /** 监听器列表，写多读少，用 COW 避免持锁回调。 */
    private final CopyOnWriteArrayList<LogListener> listeners = new CopyOnWriteArrayList<>();

    /** 当前容量上限。 */
    private int capacity;

    /**
     * 以指定容量创建缓冲。
     *
     * @param capacity 容量上限，至少为 1
     */
    public MemoryLogBuffer(int capacity) {
        this.capacity = Math.max(1, capacity);
    }

    /**
     * 按标准级别默认容量创建缓冲。
     */
    public MemoryLogBuffer() {
        this(INFO_CAPACITY);
    }

    /**
     * 按当前日志级别调整容量，并在缩容时丢弃最旧事件。
     *
     * @param level 当前阈值
     */
    public synchronized void applyLevel(LogLevel level) {
        int next = level == LogLevel.TRACE ? TRACE_CAPACITY : INFO_CAPACITY;
        this.capacity = next;
        trimToCapacity();
    }

    /**
     * 注册监听器。已注册的实例不会重复添加。
     *
     * @param listener 监听器，null 被忽略
     */
    public void addListener(LogListener listener) {
        if (listener != null && !listeners.contains(listener)) {
            listeners.add(listener);
        }
    }

    /**
     * 移除监听器。
     *
     * @param listener 监听器，null 被忽略
     */
    public void removeListener(LogListener listener) {
        if (listener != null) {
            listeners.remove(listener);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void accept(LogEvent event) {
        if (event == null) {
            return;
        }
        synchronized (this) {
            events.addLast(event);
            trimToCapacity();
        }
        for (LogListener listener : listeners) {
            listener.onEvent(event);
        }
    }

    /**
     * 清空缓冲并通知监听器。
     */
    public void clear() {
        synchronized (this) {
            events.clear();
        }
        for (LogListener listener : listeners) {
            listener.onCleared();
        }
    }

    /**
     * 按时间顺序（最旧在前）返回当前缓冲快照。
     *
     * @return 不可变快照
     */
    public synchronized List<LogEvent> snapshot() {
        return List.copyOf(new ArrayList<>(events));
    }

    /**
     * 当前缓冲条数。
     *
     * @return 条数
     */
    public synchronized int size() {
        return events.size();
    }

    /**
     * 当前容量上限。
     *
     * @return 容量
     */
    public synchronized int capacity() {
        return capacity;
    }

    /**
     * 丢弃超出容量的最旧事件。调用方须已持有本实例锁。
     */
    private void trimToCapacity() {
        while (events.size() > capacity) {
            events.removeFirst();
        }
    }
}
