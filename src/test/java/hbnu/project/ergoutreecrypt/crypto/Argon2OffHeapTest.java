package hbnu.project.ergoutreecrypt.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

/**
 * 离堆 Argon2id 实现的正确性测试。
 *
 * <p>与 BouncyCastle 的 {@code Argon2BytesGenerator} 逐字节交叉验证：
 * 多组内存/迭代/并行参数下两者输出必须完全一致；另以 Go x/crypto 的
 * 官方测试向量作为独立基准（Argon2id v1.3，m=256 KiB，t=3，p=2）。
 *
 * @author ErgouTree
 * @since 2026/8/15
 */
class Argon2OffHeapTest {

    private static final byte[] PWD = "ergou-password".getBytes(java.nio.charset.StandardCharsets.UTF_8);
    private static final byte[] SALT = Hex.decode("000102030405060708090a0b0c0d0e0f");

    /**
     * 多组参数下离堆实现应与 BouncyCastle 输出完全一致（含 64 MiB 档位规模）。
     */
    @Test
    void matchesBouncyCastleAcrossParams() {
        // {memoryKiB, passes, parallelism}
        int[][] cases = {
                {8, 2, 1},
                {32, 3, 2},
                {64, 2, 1},
                {256, 3, 2},
                {1024, 2, 4},
                {8192, 1, 4},
                {65536, 1, 2},
        };
        for (int[] c : cases) {
            byte[] bc = deriveWithBouncyCastle(c[0], c[1], c[2]);
            byte[] offHeap = Argon2OffHeap.deriveKey(PWD, SALT, c[0], c[1], c[2], 32);
            assertArrayEquals(bc, offHeap,
                    "m=" + c[0] + " t=" + c[1] + " p=" + c[2] + " 与 BouncyCastle 不一致");
        }
    }

    /**
     * Go x/crypto 官方测试向量：password/somesalt，t=3，m=256 KiB，p=2，
     * Argon2id v1.3，24 字节输出。
     */
    @Test
    void matchesGoCryptoVector() {
        byte[] out = Argon2OffHeap.deriveKey(
                "password".getBytes(java.nio.charset.StandardCharsets.UTF_8),
                "somesalt".getBytes(java.nio.charset.StandardCharsets.UTF_8),
                256, 3, 2, 24);
        byte[] expected = Hex.decode("4668d30ac4187e6878eedeacf0fd83c5a0a30db2cc16ef0b");
        assertArrayEquals(expected, out);
    }

    /**
     * 1 GiB 内存参数 + 8 lanes（桌面端偏执档）应能完成派生且与 BC 一致——
     * 这是移动端离堆路径的目标场景。仅比较小内存下的等价性太弱，此处用
     * 1 GiB 参数验证离堆分配真实可用（单 pass 控制耗时）。
     */
    @Test
    void oneGiBParam_derivesOnOffHeap() {
        byte[] bc = deriveWithBouncyCastle(1048576, 1, 4);
        byte[] offHeap = Argon2OffHeap.deriveKey(PWD, SALT, 1048576, 1, 4, 32);
        assertArrayEquals(bc, offHeap);
    }

    /**
     * 用 BouncyCastle 派生参考输出。
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
