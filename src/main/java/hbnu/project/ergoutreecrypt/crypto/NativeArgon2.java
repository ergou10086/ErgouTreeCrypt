package hbnu.project.ergoutreecrypt.crypto;

/**
 * 原生（JNI）Argon2id 派生桥接。
 *
 * <p>通过 JNI 调用随 Android 打包的 libargon2（参考 C 实现），在 native 堆分配内存、
 * 用 SIMD 优化，使移动端派生 1 GiB 参数时从「数分钟」降到秒级。桌面端未打包
 * {@code ergou_argon2} 动态库，{@link #isAvailable()} 恒为 {@code false}，调用方
 * 回退到纯 Java 的 {@link Argon2OffHeap}，行为不变。
 *
 * <p>输出与 BouncyCastle {@code Argon2BytesGenerator}、{@link Argon2OffHeap} 逐字节
 * 一致（三者均实现 Argon2id v1.3，RFC 9106 确定性），由 {@code NativeArgon2Test}
 * 交叉验证。
 *
 * <p>本类在桌面端（无 native 库）与 Android 端（有 native 库）共用同一份源码；桌面
 * 端仅 {@code loadLibrary} 失败一次后缓存为不可用，无其他开销。
 *
 * @author ErgouTree
 * @since 2026/8/30
 */
public final class NativeArgon2 {

    /**
     * 原生库是否成功加载。加载失败（桌面端 / 不支持 ABI）后恒为 false。
     */
    private static final boolean AVAILABLE = loadLibrary();

    private NativeArgon2() {
    }

    /**
     * 尝试加载原生库 {@code ergou_argon2}。任何失败都视为不可用。
     *
     * @return true 表示原生库已加载
     */
    private static boolean loadLibrary() {
        try {
            System.loadLibrary("ergou_argon2");
            return true;
        } catch (Throwable t) {
            return false;
        }
    }

    /**
     * 原生 Argon2 是否可用。
     *
     * @return true 表示可用（Android 打包了 native 库）
     */
    public static boolean isAvailable() {
        return AVAILABLE;
    }

    /**
     * 用原生 libargon2 派生 Argon2id 密钥。
     *
     * @param password    密码字节（非空）
     * @param salt        Argon2 盐（至少 8 字节）
     * @param memoryKiB   内存参数（KiB），须 ≥ 2×parallelism
     * @param passes      迭代次数，须 ≥ 1
     * @param parallelism 并行 lane 数，须 ≥ 1
     * @param outputLen   输出字节数（≥ 4，本项目恒为 32）
     * @return 派生密钥
     * @throws IllegalArgumentException 参数非法
     * @throws IllegalStateException    native 派生失败（如内存不足）
     */
    public static byte[] deriveKey(final byte[] password, final byte[] salt,
                                   final int memoryKiB, final int passes,
                                   final int parallelism, final int outputLen) {
        if (password == null || salt == null) {
            throw new IllegalArgumentException("password and salt must not be null");
        }
        if (parallelism < 1) {
            throw new IllegalArgumentException("parallelism must be at least 1");
        }
        if (memoryKiB < 2 * parallelism) {
            throw new IllegalArgumentException("memoryKiB must be at least 2×parallelism");
        }
        if (passes < 1) {
            throw new IllegalArgumentException("passes must be at least 1");
        }
        if (outputLen < 4) {
            throw new IllegalArgumentException("outputLen must be at least 4");
        }
        return argon2idHashRaw(password, salt, passes, memoryKiB, parallelism, outputLen);
    }

    /**
     * 原生方法：调用 libargon2 的 {@code argon2id_hash_raw}。
     *
     * @param password    密码字节
     * @param salt        Argon2 盐
     * @param tCost       迭代次数（passes）
     * @param mCost       内存参数（KiB）
     * @param parallelism 并行 lane 数
     * @param outputLen   输出字节数
     * @return 派生密钥字节
     */
    private static native byte[] argon2idHashRaw(byte[] password, byte[] salt,
                                                 int tCost, int mCost,
                                                 int parallelism, int outputLen);
}
