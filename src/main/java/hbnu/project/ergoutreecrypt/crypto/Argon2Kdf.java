package hbnu.project.ergoutreecrypt.crypto;

import java.util.Arrays;

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

    private Argon2Kdf() {
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
     * <p>实现选择：先按 {@link #isHeapFeasible(int)} 判断堆内派生是否可行；
     * 不足时回退到 {@link Argon2OffHeap}（离堆 native 内存），使桌面端
     * 1 GiB 参数的文件也能在 16 GB 级设备上派生密钥，避免误报内存不足。
     *
     * @param password           已归一化（NFC）的密码 UTF-8 字节
     * @param salt               16 字节 Argon2 salt
     * @param paranoid           是否使用偏执模式参数（更多迭代与线程）
     * @param overrideMemoryKib  覆写的内存参数（KiB），null 表示使用默认值
     * @param overridePasses     覆写的迭代次数，null 表示使用默认值
     * @param overrideParallelism 覆写的并行线程数，null 表示使用默认值
     * @return 32 字节派生密钥
     * @throws IllegalStateException 若派生结果为全零，视为 Argon2 故障
     */
    public static byte[] deriveKey(byte[] password, byte[] salt, boolean paranoid,
                                   Integer overrideMemoryKib, Integer overridePasses,
                                   Integer overrideParallelism) {
        int passes = overridePasses != null ? overridePasses
                : (paranoid ? CryptoConstants.ARGON2_PARANOID_PASSES : CryptoConstants.ARGON2_NORMAL_PASSES);
        int memoryKiB = overrideMemoryKib != null ? overrideMemoryKib
                : (paranoid ? CryptoConstants.ARGON2_PARANOID_MEMORY_KIB : CryptoConstants.ARGON2_NORMAL_MEMORY_KIB);
        int threads = overrideParallelism != null ? overrideParallelism
                : (paranoid ? CryptoConstants.ARGON2_PARANOID_THREADS : CryptoConstants.ARGON2_NORMAL_THREADS);

        byte[] key;
        if (!isHeapFeasible(memoryKiB)) {
            // 堆内放不下 → 离堆实现（native 内存不受 Java 堆上限约束）
            key = Argon2OffHeap.deriveKey(password, salt, memoryKiB, passes,
                    threads, CryptoConstants.ARGON2_KEY_SIZE);
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

        // 全零结果视为 Argon2 致命故障
        if (Arrays.equals(key, new byte[CryptoConstants.ARGON2_KEY_SIZE])) {
            throw new IllegalStateException("fatal Argon2 error: produced zero key");
        }
        return key;
    }
}
