package hbnu.project.ergoutreecrypt.ui.support;

import hbnu.project.ergoutreecrypt.volume.ProgressReporter;
import javafx.application.Platform;

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.BiConsumer;
import java.util.function.Consumer;

/**
 * {@link ProgressReporter} 的 JavaFX 线程实现。
 *
 * <p>后台加解密线程通过本类回调进度与状态；所有 UI 更新都经 {@link Platform#runLater} 投递到 FX 应用线程。
 * 为避免在大文件场景下淹没 FX 事件队列，进度更新做了 ~40ms 的节流，仅在进度变化达到阈值或时间间隔足够时才真正投递。
 *
 * @author ErgouTree
 */
public final class FxProgressReporter implements ProgressReporter {

    private static final long MIN_INTERVAL_NS = 40_000_000L; // 40ms

    private final Consumer<String> statusSink;
    private final BiConsumer<Float, String> progressSink;
    private final Consumer<Boolean> canCancelSink;

    private final AtomicBoolean cancelled = new AtomicBoolean(false);

    private volatile long lastEmitNs = 0L;
    private volatile float lastFraction = -1f;

    public FxProgressReporter(Consumer<String> statusSink,
                              BiConsumer<Float, String> progressSink,
                              Consumer<Boolean> canCancelSink) {
        this.statusSink = statusSink;
        this.progressSink = progressSink;
        this.canCancelSink = canCancelSink;
    }

    @Override
    public void setStatus(String text) {
        Platform.runLater(() -> statusSink.accept(text));
    }

    @Override
    public void setProgress(float fraction, String info) {
        long now = System.nanoTime();
        boolean boundary = fraction <= 0f || fraction >= 1f;
        boolean enoughTime = now - lastEmitNs >= MIN_INTERVAL_NS;
        boolean enoughDelta = Math.abs(fraction - lastFraction) >= 0.005f;
        if (!boundary && !(enoughTime && enoughDelta)) {
            return;
        }
        lastEmitNs = now;
        lastFraction = fraction;
        Platform.runLater(() -> progressSink.accept(fraction, info));
    }

    @Override
    public void setCanCancel(boolean can) {
        Platform.runLater(() -> canCancelSink.accept(can));
    }

    @Override
    public boolean isCancelled() {
        return cancelled.get();
    }

    /** 由 UI 取消按钮调用，置取消标志（后台循环每块检查）。 */
    public void cancel() {
        cancelled.set(true);
    }
}
