package hbnu.project.ergoutreecrypt.ui.support;

import hbnu.project.ergoutreecrypt.volume.ProgressPhase;
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
 * <p>支持双轨进度：{@link ProgressPhase#CRYPTO} 与 {@link ProgressPhase#ARCHIVE} 分别回调，
 * 便于 UI 用独立进度条与不同颜色展示压缩/解压阶段。
 *
 * @author ErgouTree
 */
public final class FxProgressReporter implements ProgressReporter {

    private static final long MIN_INTERVAL_NS = 40_000_000L;

    private final Consumer<String> statusSink;
    private final BiConsumer<Float, String> cryptoProgressSink;
    private final BiConsumer<Float, String> archiveProgressSink;
    private final Consumer<Boolean> archiveVisibleSink;
    private final Consumer<Boolean> canCancelSink;

    private final AtomicBoolean cancelled = new AtomicBoolean(false);

    private volatile long lastEmitNs = 0L;
    private volatile float lastFraction = -1f;
    private volatile ProgressPhase lastPhase = ProgressPhase.CRYPTO;

    /**
     * 单进度条构造（归档进度回落到主进度条，兼容旧调用）。
     *
     * @param statusSink     状态文案接收器
     * @param progressSink   进度接收器（fraction, info）
     * @param canCancelSink  取消按钮可见性接收器
     */
    public FxProgressReporter(Consumer<String> statusSink,
                              BiConsumer<Float, String> progressSink,
                              Consumer<Boolean> canCancelSink) {
        this(statusSink, progressSink, progressSink, visible -> {
        }, canCancelSink);
    }

    /**
     * 双轨进度构造。
     *
     * @param statusSink          状态文案接收器
     * @param cryptoProgressSink  加解密进度接收器
     * @param archiveProgressSink 压缩/解压进度接收器
     * @param archiveVisibleSink  归档进度条可见性接收器
     * @param canCancelSink       取消按钮可见性接收器
     */
    public FxProgressReporter(Consumer<String> statusSink,
                              BiConsumer<Float, String> cryptoProgressSink,
                              BiConsumer<Float, String> archiveProgressSink,
                              Consumer<Boolean> archiveVisibleSink,
                              Consumer<Boolean> canCancelSink) {
        this.statusSink = statusSink;
        this.cryptoProgressSink = cryptoProgressSink;
        this.archiveProgressSink = archiveProgressSink;
        this.archiveVisibleSink = archiveVisibleSink;
        this.canCancelSink = canCancelSink;
    }

    @Override
    public void setStatus(String text) {
        setStatus(text, lastPhase);
    }

    @Override
    public void setStatus(String text, ProgressPhase phase) {
        lastPhase = phase == null ? ProgressPhase.CRYPTO : phase;
        ProgressPhase p = lastPhase;
        Platform.runLater(() -> {
            if (p == ProgressPhase.ARCHIVE) {
                archiveVisibleSink.accept(true);
            }
            statusSink.accept(text);
        });
    }

    @Override
    public void setProgress(float fraction, String info) {
        setProgress(fraction, info, lastPhase);
    }

    @Override
    public void setProgress(float fraction, String info, ProgressPhase phase) {
        ProgressPhase p = phase == null ? ProgressPhase.CRYPTO : phase;
        lastPhase = p;
        long now = System.nanoTime();
        boolean boundary = fraction <= 0f || fraction >= 1f;
        boolean enoughTime = now - lastEmitNs >= MIN_INTERVAL_NS;
        boolean enoughDelta = Math.abs(fraction - lastFraction) >= 0.005f;
        if (!boundary && !(enoughTime && enoughDelta)) {
            return;
        }
        lastEmitNs = now;
        lastFraction = fraction;
        Platform.runLater(() -> {
            if (p == ProgressPhase.ARCHIVE) {
                archiveVisibleSink.accept(true);
                archiveProgressSink.accept(fraction, info);
            } else {
                cryptoProgressSink.accept(fraction, info);
            }
        });
    }

    @Override
    public void setCanCancel(boolean can) {
        Platform.runLater(() -> canCancelSink.accept(can));
    }

    @Override
    public boolean isCancelled() {
        return cancelled.get();
    }

    /**
     * 由 UI 取消按钮调用，置取消标志（后台循环每块检查）。
     */
    public void cancel() {
        cancelled.set(true);
    }
}
