package hbnu.project.ergoutreecrypt.ui.support;

import javafx.application.Platform;

import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 后台任务执行器：在守护线程池中运行加解密任务，避免阻塞 JavaFX UI 线程。
 *
 * <p>任务完成 / 失败的回调统一切回 FX 线程，便于 UI 安全更新。
 *
 * @author ErgouTree
 */
public final class TaskRunner {

    private static final ThreadFactory FACTORY = new ThreadFactory() {
        private final AtomicInteger seq = new AtomicInteger(1);

        @Override
        public Thread newThread(Runnable r) {
            Thread t = new Thread(r, "ergou-crypto-" + seq.getAndIncrement());
            t.setDaemon(true);
            t.setUncaughtExceptionHandler((th, ex) ->
                    System.err.println("[TaskRunner] uncaught in " + th.getName() + ": " + ex));
            return t;
        }
    };

    /**
     * 单工作线程 + 有界队列（容量 1）的执行器。
     * <ul>
     *   <li>core = max = 1：加解密是 CPU/IO 密集型操作，串行执行避免资源争抢</li>
     *   <li>有界队列（1）：拒绝堆积——UI 已通过 {@code setRunning} 禁用按钮，
     *       正常情况下不会并发提交；若意外堆积则快速失败而非静默排队</li>
     *   <li>{@code allowCoreThreadTimeOut = true}：空闲 60s 后线程可回收</li>
     *   <li>{@code AbortPolicy}：队列满时抛出 {@link java.util.concurrent.RejectedExecutionException}，
     *       避免静默丢弃任务</li>
     * </ul>
     */
    private final ThreadPoolExecutor executor = new ThreadPoolExecutor(
            1, 1,
            60L, TimeUnit.SECONDS,
            new LinkedBlockingQueue<>(1),
            FACTORY,
            new ThreadPoolExecutor.AbortPolicy()
    );

    {
        executor.allowCoreThreadTimeOut(true);
    }

    /**
     * 提交后台任务。
     *
     * @param work      后台执行的工作（不在 FX 线程）
     * @param onSuccess 成功回调（FX 线程）
     * @param onError   失败回调（FX 线程）
     */
    public void submit(CheckedRunnable work, Runnable onSuccess, java.util.function.Consumer<Throwable> onError) {
        executor.submit(() -> {
            try {
                work.run();
                Platform.runLater(onSuccess);
            } catch (Throwable t) {
                Platform.runLater(() -> onError.accept(t));
            }
        });
    }

    /**
     * 关闭线程池（应用退出时调用）。
     */
    public void shutdown() {
        executor.shutdownNow();
    }

    /**
     * 可抛出受检异常的任务体。
     */
    @FunctionalInterface
    public interface CheckedRunnable {
        void run() throws Exception;
    }
}
