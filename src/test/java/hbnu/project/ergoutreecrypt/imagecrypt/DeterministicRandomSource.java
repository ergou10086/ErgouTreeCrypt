package hbnu.project.ergoutreecrypt.imagecrypt;

/**
 * 测试专用的确定性随机源。
 *
 * <p>生产路径只能使用 {@link ImageCryptRandomSource#secure()}；本实现让协议字段与密钥中间值
 * 可复现，从而把黄金向量冻结成断言。它在包内可见，不经过 {@code ImageCryptCodec} 的公开 API，
 * 因此不会暴露给 UI。
 *
 * <p>字节序列由一个线性同余发生器产生，不会出现全零窗口，满足 {@code RandomBytes} 的健全性检查。
 *
 * @author ErgouTree
 * @since 2026/9/15
 */
final class DeterministicRandomSource implements ImageCryptRandomSource {

    /**
     * 线性同余发生器的乘数。
     */
    private static final long MULTIPLIER = 6364136223846793005L;

    /**
     * 线性同余发生器的增量。
     */
    private static final long INCREMENT = 1442695040888963407L;

    /**
     * 当前发生器状态。
     */
    private long state;

    /**
     * 构造确定性随机源。
     *
     * @param seed 初始种子
     */
    DeterministicRandomSource(final long seed) {
        this.state = seed;
    }

    @Override
    public byte[] nextBytes(final int length) {
        byte[] out = new byte[length];
        for (int i = 0; i < length; i++) {
            state = state * MULTIPLIER + INCREMENT;
            out[i] = (byte) (state >>> 33);
        }
        return out;
    }
}
