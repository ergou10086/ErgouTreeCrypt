package hbnu.project.ergoutreecrypt.ui.support;

import hbnu.project.ergoutreecrypt.log.LogService;
import hbnu.project.ergoutreecrypt.mediacrypt.MediaProgress;

/**
 * 将 {@link MediaProgress} 进度镜像到诊断日志。
 *
 * @author ErgouTree
 * @since 2026/8/26
 */
public final class LoggingMediaProgress implements MediaProgress {

    private static final long TRACE_INTERVAL_NS = 500_000_000L;

    private final MediaProgress delegate;
    private final String category;
    private volatile long lastTraceNs;
    private volatile int lastPercent = -1;

    /**
     * 包装已有媒体进度回调。
     *
     * @param delegate 实际回调，不允许为 null
     * @param category 日志分类
     */
    public LoggingMediaProgress(MediaProgress delegate, String category) {
        this.delegate = delegate;
        this.category = category == null ? "MediaCrypt" : category;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void onProgress(long processed, long total) {
        delegate.onProgress(processed, total);
        if (!LogService.isTraceEnabled()) {
            return;
        }
        int pct = total <= 0 ? 0 : (int) Math.min(100, (processed * 100) / total);
        long now = System.nanoTime();
        boolean boundary = processed <= 0 || (total > 0 && processed >= total);
        if (!boundary && pct / 10 == lastPercent / 10 && now - lastTraceNs < TRACE_INTERVAL_NS) {
            return;
        }
        lastPercent = pct;
        lastTraceNs = now;
        LogService.trace(category, "进度 " + pct + "% ("
                + LogService.humanSize(processed) + " / " + LogService.humanSize(total) + ")");
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isCancelled() {
        return delegate.isCancelled();
    }
}
