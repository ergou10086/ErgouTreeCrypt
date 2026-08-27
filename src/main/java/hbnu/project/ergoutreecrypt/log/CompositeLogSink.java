package hbnu.project.ergoutreecrypt.log;

/**
 * 将同一事件转发给多个接收器。
 *
 * <p>单个接收器失败会被吞掉，不影响其余接收器与主流程。
 *
 * @author ErgouTree
 * @since 2026/8/27
 */
public final class CompositeLogSink implements LogSink {

    /** 下游接收器，构造后不再修改。 */
    private final LogSink[] sinks;

    /**
     * 组合若干接收器。{@code null} 项会被忽略。
     *
     * @param sinks 下游接收器
     */
    public CompositeLogSink(LogSink... sinks) {
        this.sinks = sinks == null ? new LogSink[0] : sinks.clone();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void accept(LogEvent event) {
        if (event == null) {
            return;
        }
        for (LogSink sink : sinks) {
            if (sink == null) {
                continue;
            }
            try {
                sink.accept(event);
            } catch (Throwable ignored) {
                // 单个接收器失败不影响其他
            }
        }
    }
}
