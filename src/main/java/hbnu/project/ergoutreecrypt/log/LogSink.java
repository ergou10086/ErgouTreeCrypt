package hbnu.project.ergoutreecrypt.log;

/**
 * 日志事件接收器。
 *
 * <p>实现必须线程安全；写入失败应自行消化，不得向上抛出，以免干扰主流程。
 *
 * @author ErgouTree
 * @since 2026/8/26
 */
public interface LogSink {

    /**
     * 接收一条已通过级别过滤的日志事件。
     *
     * @param event 事件，不允许为 null
     */
    void accept(LogEvent event);
}
