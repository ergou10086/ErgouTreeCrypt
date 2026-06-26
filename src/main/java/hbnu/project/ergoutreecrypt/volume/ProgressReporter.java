package hbnu.project.ergoutreecrypt.volume;

/**
 * 进度回调接口。
 *
 * <p>由 UI 层实现，加解密过程中在后台线程回调进度与状态。
 * 所有实现须线程安全，特别是 {@link #isCancelled()} 可能被 UI 线程设置后被后台线程读取。
 *
 * @author ErgouTree
 * @since 2026/6/17
 */
public interface ProgressReporter {

    /**
     * 更新当前状态文本（如 "Deriving key..."）。
     */
    void setStatus(String text);

    /**
     * 更新进度。
     *
     * @param fraction 完成比例（0.0~1.0）
     * @param info     附加信息（如速度、字节数等）
     */
    void setProgress(float fraction, String info);

    /**
     * 设置是否允许取消。
     */
    void setCanCancel(boolean can);

    /**
     * UI 刷新钩子，默认空实现。
     */
    default void update() {
    }

    /**
     * 是否已请求取消操作。
     *
     * @return true 表示应尽快中止当前操作
     */
    boolean isCancelled();
}
