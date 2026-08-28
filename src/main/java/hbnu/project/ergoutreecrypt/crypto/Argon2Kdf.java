package hbnu.project.ergoutreecrypt.crypto;

import java.util.Arrays;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicInteger;

import hbnu.project.ergoutreecrypt.log.LogService;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

/**
 * Argon2id 密钥派生函数（KDF）。
 *
 * <p>根据安全模式选择迭代次数与并行度，从密码与 salt 派生 32 字节加密密钥。
 * 内存量固定为 1 GiB。派生结果为全零时视为 Argon2 故障并抛出异常。
 *
 * <p>参数对照：
 * <ul>
 *   <li>普通模式：4 passes / 1 GiB / 4 threads</li>
 *   <li>偏执模式：8 passes / 1 GiB / 8 threads</li>
 * </ul>
 *
 * <p>任意时刻只允许一路派生持有全局许可：默认参数每路约 1 GiB（堆内或离堆），
 * 并行文件处理若同时进入 KDF 会叠加内存并在 native {@code Unsafe} 路径上闪退。
 * 文件 I/O 仍可并行，仅密钥派生串行化。
 *
 * @author ErgouTree
 */
public final class Argon2Kdf {

    /**
     * Argon2 内存分配的安全系数：BouncyCastle 的实现以 {@code Block} 对象数组
     * 全量分配内存（每块 1 KiB 数据 + 数组/对象头），叠加派生过程的临时缓冲与
     * GC 峰值，实际堆占用约为内存参数的 1.25 倍。
     */
    private static final double MEMORY_OVERHEAD_FACTOR = 1.25;

    /**
     * 堆预检的固定安全余量（字节）：为应用其余部分与分配碎片保留。
     */
    private static final long MEMORY_CHECK_MARGIN_BYTES = 32L << 20;

    /**
     * 全局 KDF 许可：同时只允许一路 1 GiB 级 Argon2 分配。
     */
    private static final Semaphore KDF_LOCK = new Semaphore(1, true);

    /**
     * 当前持有 KDF 许可的线程数（0 或 1）。供单测断言互斥。
     */
    static final AtomicInteger kdfInFlight = new AtomicInteger();

    /**
     * 观测到的最大并发持有数。供单测断言互斥。
     */
    static final AtomicInteger kdfMaxInFlight = new AtomicInteger();

    private Argon2Kdf() {
    }

    /**
     * 重置互斥观测计数。仅供测试使用。
     */
    static void resetKdfStats() {
        kdfInFlight.set(0);
        kdfMaxInFlight.set(0);
    }

    /**
     * 估算给定 Argon2 内存参数所需的堆字节数。
     *
     * <p>BouncyCastle 的 {@code Argon2BytesGenerator} 会一次性分配约
     * {@code memoryKiB} KiB 的 Block 对象数组，叠加对象头与派生临时缓冲后，
     * 实际峰值约为参数内存的 {@link #MEMORY_OVERHEAD_FACTOR} 倍。
     *
     * @param memoryKiB Argon2 内存参数（KiB）
     * @return 估算的所需堆字节数
     */
    public static long estimateRequiredHeapBytes(final int memoryKiB) {
        return (long) Math.ceil(memoryKiB * 1024.0 * MEMORY_OVERHEAD_FACTOR);
    }

    /**
     * 估算当前 JVM 可用的堆字节数。
     *
     * <p>计算方式为 {@code maxMemory - (totalMemory - freeMemory)}：堆上限减去
     * 已占用部分，即不触发 GC 的前提下还能分配的最大字节数。Android ART 上
     * {@code maxMemory} 为应用堆上限（受 largeHeap 影响）。
     *
     * @return 当前可用的堆字节数
     */
    public static long availableHeapBytes() {
        Runtime rt = Runtime.getRuntime();
        return rt.maxMemory() - (rt.totalMemory() - rt.freeMemory());
    }

    /**
     * 判断当前堆内存是否足以完成给定参数的 Argon2 派生。
     *
     * <p>需求为 {@link #estimateRequiredHeapBytes(int)} 加
     * {@link #MEMORY_CHECK_MARGIN_BYTES} 固定余量。不足不代表派生无法完成：
     * {@link #deriveKey} 会回退到 {@link Argon2OffHeap}（离堆 native 内存）。
     *
     * @param memoryKiB Argon2 内存参数（KiB）
     * @return true 表示堆内派生可行
     */
    public static boolean isHeapFeasible(final int memoryKiB) {
        long required = estimateRequiredHeapBytes(memoryKiB) + MEMORY_CHECK_MARGIN_BYTES;
        return required <= availableHeapBytes();
    }

    /**
     * 校验当前堆内存是否足以完成给定参数的 Argon2 派生。
     *
     * <p>在真正分配之前调用，以友好失败取代 {@link OutOfMemoryError}：
     * 不足时抛出带所需/可用字节信息的 {@link IllegalStateException}。
     *
     * @param memoryKiB Argon2 内存参数（KiB）
     * @throws IllegalStateException 可用堆不足
     */
    public static void assertMemoryAvailable(final int memoryKiB) {
        if (!isHeapFeasible(memoryKiB)) {
            long required = estimateRequiredHeapBytes(memoryKiB) + MEMORY_CHECK_MARGIN_BYTES;
            long available = availableHeapBytes();
            throw new IllegalStateException(String.format(
                    "Argon2 需要约 %d MiB 堆内存（参数 %d KiB），当前可用仅 %d MiB",
                    required >> 20, memoryKiB, available >> 20));
        }
    }

    /**
     * 从密码与 salt 派生 32 字节加密密钥。
     *
     * @param password 已归一化（NFC）的密码 UTF-8 字节
     * @param salt     16 字节 Argon2 salt
     * @param paranoid 是否使用偏执模式参数（更多迭代与线程）
     * @return 32 字节派生密钥
     * @throws IllegalStateException 若派生结果为全零，视为 Argon2 故障
     */
    public static byte[] deriveKey(byte[] password, byte[] salt, boolean paranoid) {
        return deriveKey(password, salt, paranoid, null, null, null);
    }

    /**
     * 从密码与 salt 派生 32 字节加密密钥（支持参数覆写）。
     *
     * <p>当 override 参数为非 null 时使用覆写值，否则根据 paranoid 标志选择默认值。
     * Android 移动端通过此方法使用更低的内存参数以适配移动设备。
     *
     * <p>任意时刻只允许一路派生持有全局许可，避免并行文件处理叠加 1 GiB 内存。
     * 堆内不足时回退到 {@link Argon2OffHeap}。
     *
     * @param password           已归一化（NFC）的密码 UTF-8 字节
     * @param salt               16 字节 Argon2 salt
     * @param paranoid           是否使用偏执模式参数（更多迭代与线程）
     * @param overrideMemoryKib  覆写的内存参数（KiB），null 表示使用默认值
     * @param overridePasses     覆写的迭代次数，null 表示使用默认值
     * @param overrideParallelism 覆写的并行线程数，null 表示使用默认值
     * @return 32 字节派生密钥
     * @throws IllegalStateException 若派生结果为全零，或等待许可时被中断
     */
    public static byte[] deriveKey(byte[] password, byte[] salt, boolean paranoid,
                                   Integer overrideMemoryKib, Integer overridePasses,
                                   Integer overrideParallelism) {
        return deriveKey(password, salt, paranoid, overrideMemoryKib, overridePasses,
                overrideParallelism, null);
    }

    /**
     * 从密码与 salt 派生 32 字节加密密钥（支持参数覆写与进度/取消回调）。
     *
     * <p>当 override 参数为非 null 时使用覆写值，否则根据 paranoid 标志选择默认值。
     * {@code progress} 为 null 时行为与 6 参重载完全一致（桌面端）。
     *
     * @param password            已归一化（NFC）的密码 UTF-8 字节
     * @param salt                16 字节 Argon2 salt
     * @param paranoid            是否使用偏执模式参数（更多迭代与线程）
     * @param overrideMemoryKib   覆写的内存参数（KiB），null 表示使用默认值
     * @param overridePasses      覆写的迭代次数，null 表示使用默认值
     * @param overrideParallelism 覆写的并行线程数，null 表示使用默认值
     * @param progress            进度/取消回调，可为 null
     * @return 32 字节派生密钥
     * @throws IllegalStateException 若派生结果为全零，或等待许可时被中断/取消
     */
    public static byte[] deriveKey(byte[] password, byte[] salt, boolean paranoid,
                                   Integer overrideMemoryKib, Integer overridePasses,
                                   Integer overrideParallelism, KdfProgress progress) {
        int passes = overridePasses != null ? overridePasses
                : (paranoid ? CryptoConstants.ARGON2_PARANOID_PASSES : CryptoConstants.ARGON2_NORMAL_PASSES);
        int memoryKiB = overrideMemoryKib != null ? overrideMemoryKib
                : (paranoid ? CryptoConstants.ARGON2_PARANOID_MEMORY_KIB : CryptoConstants.ARGON2_NORMAL_MEMORY_KIB);
        int threads = overrideParallelism != null ? overrideParallelism
                : (paranoid ? CryptoConstants.ARGON2_PARANOID_THREADS : CryptoConstants.ARGON2_NORMAL_THREADS);

        long waitStart = System.nanoTime();
        try {
            KDF_LOCK.acquire();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Argon2 密钥派生等待许可时被取消", e);
        }
        long waitMs = (System.nanoTime() - waitStart) / 1_000_000L;
        int inflight = kdfInFlight.incrementAndGet();
        kdfMaxInFlight.accumulateAndGet(inflight, Math::max);
        try {
            return deriveKeyUnlocked(password, salt, memoryKiB, passes, threads, waitMs, progress);
        } finally {
            kdfInFlight.decrementAndGet();
            KDF_LOCK.release();
        }
    }

    /**
     * 已持有全局许可后的实际派生。
     *
     * @param password  密码字节
     * @param salt      Argon2 盐
     * @param memoryKiB 内存参数（KiB）
     * @param passes    迭代次数
     * @param threads   lane 并行度
     * @param waitMs    获取许可等待的毫秒数
     * @param progress  进度/取消回调，可为 null
     * @return 32 字节派生密钥
     */
    private static byte[] deriveKeyUnlocked(byte[] password, byte[] salt,
                                            int memoryKiB, int passes, int threads,
                                            long waitMs, KdfProgress progress) {
        long t0 = System.nanoTime();
        boolean offHeap = !isHeapFeasible(memoryKiB);
        if (LogService.isTraceEnabled()) {
            LogService.trace("Argon2Kdf", "派生开始 passes=" + passes
                    + ", memKiB=" + memoryKiB
                    + ", threads=" + threads
                    + ", offHeap=" + offHeap
                    + ", waitMs=" + waitMs);
        } else if (waitMs >= 50L) {
            LogService.info("Argon2Kdf", "等待全局许可 " + waitMs + " ms 后开始派生 offHeap=" + offHeap);
        }

        byte[] key;
        if (offHeap) {
            key = Argon2OffHeap.deriveKey(password, salt, memoryKiB, passes,
                    threads, CryptoConstants.ARGON2_KEY_SIZE, progress);
        } else {
            Argon2Parameters params = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                    .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                    .withIterations(passes)
                    .withMemoryAsKB(memoryKiB)
                    .withParallelism(threads)
                    .withSalt(salt)
                    .build();

            Argon2BytesGenerator generator = new Argon2BytesGenerator();
            generator.init(params);

            key = new byte[CryptoConstants.ARGON2_KEY_SIZE];
            generator.generateBytes(password, key);
        }

        if (Arrays.equals(key, new byte[CryptoConstants.ARGON2_KEY_SIZE])) {
            throw new IllegalStateException("fatal Argon2 error: produced zero key");
        }
        if (LogService.isTraceEnabled()) {
            LogService.trace("Argon2Kdf", "派生完成 offHeap=" + offHeap,
                    (System.nanoTime() - t0) / 1_000_000L);
        }
        return key;
    }
}
