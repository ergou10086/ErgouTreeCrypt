package hbnu.project.ergoutreecrypt.volume;

import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 加密/解密专用的线程池工厂。
 *
 * <p>使用手动配置的 {@link ThreadPoolExecutor} 而非 {@code Executors.newFixedThreadPool}，
 * 以获得对线程命名、守护状态、队列策略的完全控制：
 * <ul>
 *   <li>线程池大小固定（core = max = 指定线程数），空闲线程立即回收（keepAlive=0）。</li>
 *   <li>工作线程为守护线程，不阻止 JVM 退出。</li>
 *   <li>线程命名格式为 {@code ergou-<prefix>-<n>}，便于调试与监控。</li>
 *   <li>使用无界 {@link LinkedBlockingQueue} 配合 {@link ThreadPoolExecutor.CallerRunsPolicy} 作为饱和策略：
 *       当队列满时由调用线程直接执行任务，提供自然背压。</li>
 * </ul>
 *
 * @author ErgouTree
 */
public final class CryptoThreadPool {

    /** 线程名前缀 */
    private final String prefix;

    /** 线程数 */
    private final int threadCount;

    /** 线程编号计数器 */
    private final AtomicInteger counter = new AtomicInteger(1);

    /**
     * 创建一个新的线程池构建器。
     *
     * @param prefix      线程名前缀（如 "encrypt" 或 "decrypt"）
     * @param threadCount 线程数，必须 &ge; 1
     */
    private CryptoThreadPool(String prefix, int threadCount) {
        this.prefix = prefix;
        this.threadCount = threadCount;
    }

    /**
     * 创建一个用于加密场景的线程池。
     *
     * @param threadCount 线程数，必须 &ge; 1
     * @return 配置好的 {@link ThreadPoolExecutor}，调用方负责在 finally 块中 shutdown
     */
    public static ThreadPoolExecutor forEncrypt(int threadCount) {
        return new CryptoThreadPool("encrypt", threadCount).build();
    }

    /**
     * 创建一个用于解密场景的线程池。
     *
     * @param threadCount 线程数，必须 &ge; 1
     * @return 配置好的 {@link ThreadPoolExecutor}，调用方负责在 finally 块中 shutdown
     */
    public static ThreadPoolExecutor forDecrypt(int threadCount) {
        return new CryptoThreadPool("decrypt", threadCount).build();
    }

    /**
     * 构建并返回手动配置的线程池。
     */
    private ThreadPoolExecutor build() {
        ThreadPoolExecutor pool = new ThreadPoolExecutor(
                threadCount,               // corePoolSize
                threadCount,               // maximumPoolSize（固定大小）
                0L,                        // keepAliveTime（无超出核心的线程需要回收）
                TimeUnit.MILLISECONDS,
                new LinkedBlockingQueue<>(),
                threadFactory(),
                new ThreadPoolExecutor.CallerRunsPolicy()  // 饱和时由调用线程执行，提供自然背压
        );
        pool.allowCoreThreadTimeOut(false);  // 核心线程不超时回收
        return pool;
    }

    /**
     * 创建自定义线程工厂：守护线程 + 可辨识的名称。
     */
    private ThreadFactory threadFactory() {
        return r -> {
            Thread t = new Thread(r);
            t.setName("ergou-" + prefix + "-" + counter.getAndIncrement());
            t.setDaemon(true);
            t.setPriority(Thread.NORM_PRIORITY);
            return t;
        };
    }
}
