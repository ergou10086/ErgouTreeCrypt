package hbnu.project.ergoutreecrypt.volume;

/**
 * 进度回调接口。
 *
 * <p>由 UI 层实现，加解密过程中在后台线程回调进度与状态。
 * 所有实现须线程安全，特别是 {@link #isCancelled()} 可能被 UI 线程设置后被后台线程读取。
 *
 * <p>支持 {@link ProgressPhase} 区分加解密与压缩/解压进度：UI 可据此驱动独立进度条与配色。
 *
 * @author ErgouTree
 * @since 2026/6/17
 */
public interface ProgressReporter {

    /**
     * 更新当前状态文本（如本地化后的「正在派生密钥…」）。
     *
     * @param text 状态文案
     */
    void setStatus(String text);

    /**
     * 更新状态文本并指定进度阶段。
     *
     * <p>默认实现忽略阶段，仅调用 {@link #setStatus(String)}；
     * UI 实现应覆盖以切换独立进度条。
     *
     * @param text  状态文案
     * @param phase 进度阶段
     */
    default void setStatus(String text, ProgressPhase phase) {
        setStatus(text);
    }

    /**
     * 更新进度（默认视为 {@link ProgressPhase#CRYPTO}）。
     *
     * @param fraction 完成比例（0.0~1.0）
     * @param info     附加信息（如速度、字节数等）
     */
    void setProgress(float fraction, String info);

    /**
     * 更新进度并指定阶段。
     *
     * <p>默认实现忽略阶段，仅调用 {@link #setProgress(float, String)}。
     *
     * @param fraction 完成比例（0.0~1.0）
     * @param info     附加信息
     * @param phase    进度阶段
     */
    default void setProgress(float fraction, String info, ProgressPhase phase) {
        setProgress(fraction, info);
    }

    /**
     * 设置是否允许取消。
     *
     * @param can 是否可取消
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
