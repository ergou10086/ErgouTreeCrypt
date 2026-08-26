package hbnu.project.ergoutreecrypt.log;

/**
 * 内存日志缓冲的变更监听器，供 UI 实时刷新。
 *
 * <p>回调可能来自任意线程（含加解密后台线程），UI 实现须自行切到 FX 线程。
 *
 * @author ErgouTree
 * @since 2026/8/26
 */
public interface LogListener {

    /**
     * 缓冲中新增一条事件。
     *
     * @param event 新事件，不允许为 null
     */
    void onEvent(LogEvent event);

    /**
     * 缓冲被清空（用户点击清空，或新操作会话按设置刷新）。
     */
    default void onCleared() {
    }
}
