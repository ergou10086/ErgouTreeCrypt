package hbnu.project.ergoutreecrypt.ui.support;

import hbnu.project.ergoutreecrypt.log.LogService;
import hbnu.project.ergoutreecrypt.volume.ProgressPhase;
import hbnu.project.ergoutreecrypt.volume.ProgressReporter;

/**
 * 将 {@link ProgressReporter} 的状态与进度镜像到 {@link LogService}。
 *
 * <p>状态文案以 INFO 记录；进度分数仅在 TRACE 下节流输出（约每 10% 或 500ms）。
 * 本装饰器不改变委托对象的取消语义。
 *
 * @author ErgouTree
 * @since 2026/8/26
 */
public final class LoggingProgressReporter implements ProgressReporter {

    /** TRACE 进度最小间隔。 */
    private static final long TRACE_INTERVAL_NS = 500_000_000L;

    /** TRACE 进度最小步进。 */
    private static final float TRACE_STEP = 0.10f;

    private final ProgressReporter delegate;
    private final String category;

    private volatile String lastStatus;
    private volatile float lastLoggedFraction = -1f;
    private volatile long lastTraceNs;

    /**
     * 包装已有进度回调。
     *
     * @param delegate 实际 UI 回调，不允许为 null
     * @param category 日志分类
     */
    public LoggingProgressReporter(ProgressReporter delegate, String category) {
        this.delegate = delegate;
        this.category = category == null ? "Progress" : category;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setStatus(String text) {
        delegate.setStatus(text);
        logStatus(text);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setStatus(String text, ProgressPhase phase) {
        delegate.setStatus(text, phase);
        logStatus(text);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setProgress(float fraction, String info) {
        delegate.setProgress(fraction, info);
        logProgress(fraction, info, null);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setProgress(float fraction, String info, ProgressPhase phase) {
        delegate.setProgress(fraction, info, phase);
        logProgress(fraction, info, phase);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setCanCancel(boolean can) {
        delegate.setCanCancel(can);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void update() {
        delegate.update();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isCancelled() {
        return delegate.isCancelled();
    }

    /**
     * 状态变化时写一条 INFO。
     *
     * @param text 状态文案
     */
    private void logStatus(String text) {
        if (text == null || text.equals(lastStatus)) {
            return;
        }
        lastStatus = text;
        LogService.info(category, text);
    }

    /**
     * TRACE 下节流记录进度。
     *
     * @param fraction 完成比例
     * @param info     附加信息
     * @param phase    阶段，可为 null
     */
    private void logProgress(float fraction, String info, ProgressPhase phase) {
        if (!LogService.isTraceEnabled()) {
            return;
        }
        long now = System.nanoTime();
        boolean boundary = fraction <= 0f || fraction >= 1f;
        boolean step = Math.abs(fraction - lastLoggedFraction) >= TRACE_STEP;
        boolean enoughTime = now - lastTraceNs >= TRACE_INTERVAL_NS;
        if (!boundary && !step && !enoughTime) {
            return;
        }
        lastLoggedFraction = fraction;
        lastTraceNs = now;
        StringBuilder sb = new StringBuilder(48);
        sb.append("进度 ");
        if (phase != null) {
            sb.append(phase.name()).append(' ');
        }
        sb.append(String.format("%.0f%%", fraction * 100f));
        if (info != null && !info.isBlank()) {
            sb.append(' ').append(info);
        }
        LogService.trace(category, sb.toString());
    }
}
