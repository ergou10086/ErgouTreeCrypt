package hbnu.project.ergoutreecrypt.crypto;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

/**
 * KDF 派生耗时基线测量（Phase 0.2）。
 *
 * <p>在同一台 JVM 上分别测量「堆内 BouncyCastle」与「离堆纯 Java」两条路径在
 * 桌面端常见档位下的派生耗时，作为 A2（native 加速）的对照基线。结果仅打印，
 * 不做断言（计时易受环境抖动影响）。
 *
 * @author ErgouTree
 */
class KdfTimingBaselineTest {

    private static final byte[] PWD = "ergou-password".getBytes(StandardCharsets.UTF_8);
    private static final byte[] SALT = Hex.decode("000102030405060708090a0b0c0d0e0f");

    /**
     * 打印各档位在堆内与离堆两条路径下的派生耗时。
     */
    @Test
    void printTimingBaseline() {
        int[][] cases = {
                {65536, 2, 2},       // 移动端 LIGHT：64 MiB / 2 轮 / 2 线程
                {256 << 10, 3, 4},   // 移动端 BALANCED：256 MiB / 3 轮 / 4 线程
                {1048576, 1, 4},     // 桌面端普通档（仅 1 轮，便于测量单轮成本）
        };
        for (int[] c : cases) {
            long inHeapMs = timeBouncyCastle(c[0], c[1], c[2]);
            long offHeapMs = timeOffHeap(c[0], c[1], c[2]);
            System.out.printf("KDF baseline m=%d KiB t=%d p=%d | inHeap=%d ms | offHeap=%d ms%n",
                    c[0], c[1], c[2], inHeapMs, offHeapMs);
        }
    }

    /**
     * 测量堆内 BouncyCastle 派生耗时。
     */
    private static long timeBouncyCastle(final int memoryKiB, final int passes,
                                         final int parallelism) {
        long t0 = System.nanoTime();
        Argon2Parameters params = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                .withIterations(passes)
                .withMemoryAsKB(memoryKiB)
                .withParallelism(parallelism)
                .withSalt(SALT)
                .build();
        Argon2BytesGenerator generator = new Argon2BytesGenerator();
        generator.init(params);
        generator.generateBytes(PWD, new byte[32]);
        return (System.nanoTime() - t0) / 1_000_000L;
    }

    /**
     * 测量离堆纯 Java 派生耗时。
     */
    private static long timeOffHeap(final int memoryKiB, final int passes,
                                    final int parallelism) {
        long t0 = System.nanoTime();
        Argon2OffHeap.deriveKey(PWD, SALT, memoryKiB, passes, parallelism, 32);
        return (System.nanoTime() - t0) / 1_000_000L;
    }
}
