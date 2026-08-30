package hbnu.project.ergoutreecrypt.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 离堆 Argon2 取消响应性与进度粒度测试（Phase A1）。
 *
 * <p>验证 {@link Argon2OffHeap} 在取消信号到来时于 slice/块粒度即可中止派生，
 * 而非等到整轮（pass）结束；同时验证 {@code onSliceProgress} 以 slice 粒度回调，
 * 以及正常派生结果与 BouncyCastle 仍逐字节一致（改动不破坏正确性）。
 *
 * @author ErgouTree
 */
class Argon2OffHeapCancelTest {

    private static final byte[] PWD = "ergou-password".getBytes(StandardCharsets.UTF_8);
    private static final byte[] SALT = Hex.decode("000102030405060708090a0b0c0d0e0f");

    /**
     * 派生开始前即已请求取消：应立即抛出取消异常，而非完成派生。
     */
    @Test
    void cancelBeforeStart_abortsImmediately() {
        KdfProgress progress = new KdfProgress() {
            @Override
            public void onProgress(final int pass, final int totalPasses) {
            }

            @Override
            public boolean isCancelled() {
                return true;
            }
        };
        assertThrows(IllegalStateException.class,
                () -> Argon2OffHeap.deriveKey(PWD, SALT, 65536, 2, 4, 32, progress),
                "取消请求应立即中止派生");
    }

    /**
     * 首个 slice 之后请求取消：应中止，且不会推进到第二个 pass。
     *
     * <p>取消在 {@code onSliceProgress} 首次回调（slice 1 边界）置位。若取消检查
     * 仍是旧的整轮粒度，则派生会继续填完整个 pass 0 才在 pass 1 边界中止，届时
     * {@code onProgress} 会被回调到 pass 2；本用例断言其停留在 pass 1，证明取消
     * 已细化到 slice 以内。
     */
    @Test
    void cancelAfterFirstSlice_abortsWithinFirstPass() {
        AtomicInteger maxPass = new AtomicInteger();
        AtomicBoolean cancel = new AtomicBoolean(false);
        KdfProgress progress = new KdfProgress() {
            @Override
            public void onProgress(final int pass, final int totalPasses) {
                maxPass.set(Math.max(maxPass.get(), pass));
            }

            @Override
            public void onSliceProgress(final int doneSlices, final int totalSlices) {
                if (doneSlices >= 2) {
                    cancel.set(true);
                }
            }

            @Override
            public boolean isCancelled() {
                return cancel.get();
            }
        };
        assertThrows(IllegalStateException.class,
                () -> Argon2OffHeap.deriveKey(PWD, SALT, 65536, 3, 4, 32, progress));
        assertTrue(maxPass.get() < 2,
                "应在首个 pass 内中止，实际报告到 pass=" + maxPass.get());
    }

    /**
     * 正常派生结果不因取消/进度改动而变化（与 BouncyCastle 逐字节一致）。
     */
    @Test
    void resultUnchanged_matchesBouncyCastle() {
        int memoryKiB = 65536;
        int passes = 2;
        int parallelism = 4;
        byte[] bc = deriveWithBouncyCastle(memoryKiB, passes, parallelism);
        byte[] offHeap = Argon2OffHeap.deriveKey(PWD, SALT, memoryKiB, passes, parallelism, 32);
        assertArrayEquals(bc, offHeap);
    }

    /**
     * 用 BouncyCastle 派生参考输出。
     *
     * @param memoryKiB  内存参数（KiB）
     * @param passes     迭代次数
     * @param parallelism 并行 lane 数
     * @return 32 字节派生密钥
     */
    private static byte[] deriveWithBouncyCastle(final int memoryKiB, final int passes,
                                                 final int parallelism) {
        Argon2Parameters params = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                .withIterations(passes)
                .withMemoryAsKB(memoryKiB)
                .withParallelism(parallelism)
                .withSalt(SALT)
                .build();
        Argon2BytesGenerator generator = new Argon2BytesGenerator();
        generator.init(params);
        byte[] out = new byte[32];
        generator.generateBytes(PWD, out);
        return out;
    }
}
