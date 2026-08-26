package hbnu.project.ergoutreecrypt.ui.support;

import hbnu.project.ergoutreecrypt.filestego.api.ProgressListener;
import hbnu.project.ergoutreecrypt.log.LogService;

/**
 * 将文件隐写 {@link ProgressListener} 进度镜像到诊断日志。
 *
 * @author ErgouTree
 * @since 2026/8/26
 */
public final class LoggingProgressListener implements ProgressListener {

    private static final long TRACE_INTERVAL_NS = 500_000_000L;

    private final ProgressListener delegate;
    private final String category;
    private volatile double lastLogged = -1;
    private volatile long lastTraceNs;

    /**
     * 包装已有监听器；{@code delegate} 可为 null（仅记日志）。
     *
     * @param delegate 实际监听器，可为 null
     * @param category 日志分类
     */
    public LoggingProgressListener(ProgressListener delegate, String category) {
        this.delegate = delegate;
        this.category = category == null ? "FileStego" : category;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void onProgress(double fraction) {
        if (delegate != null) {
            delegate.onProgress(fraction);
        }
        if (!LogService.isTraceEnabled()) {
            return;
        }
        long now = System.nanoTime();
        boolean boundary = fraction <= 0 || fraction >= 1;
        boolean step = Math.abs(fraction - lastLogged) >= 0.10;
        if (!boundary && !step && now - lastTraceNs < TRACE_INTERVAL_NS) {
            return;
        }
        lastLogged = fraction;
        lastTraceNs = now;
        LogService.trace(category, "进度 " + String.format("%.0f%%", fraction * 100));
    }
}
