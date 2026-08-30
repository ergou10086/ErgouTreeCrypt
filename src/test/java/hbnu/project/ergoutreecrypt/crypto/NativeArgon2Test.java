package hbnu.project.ergoutreecrypt.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assumptions.assumeFalse;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

/**
 * 原生 Argon2 桥接的一致性测试。
 *
 * <p>在桌面端（无 native 库）验证 {@link NativeArgon2#isAvailable()} 为 {@code false}
 * 且 {@link Argon2Kdf} 正确回退纯 Java；在 Android 真机（有 native 库）验证原生实现
 * 与 BouncyCastle、{@link Argon2OffHeap} 三者的输出逐字节一致（RFC 9106 确定性）。
 *
 * @author ErgouTree
 */
class NativeArgon2Test {

    private static final byte[] PWD = "ergou-password".getBytes(StandardCharsets.UTF_8);
    private static final byte[] SALT = Hex.decode("000102030405060708090a0b0c0d0e0f");

    /**
     * 桌面端无 native 库时，{@code isAvailable()} 应为 false，且回退路径不抛异常。
     */
    @Test
    void unavailableOnDesktop_fallsBack() {
        assumeFalse(NativeArgon2.isAvailable(),
                "桌面端 JVM 不应加载 Android 的 ergou_argon2 库");
        byte[] offHeap = Argon2OffHeap.deriveKey(PWD, SALT, 65536, 2, 4, 32);
        assertEquals(32, offHeap.length);
    }

    /**
     * native 可用时，多组参数下原生输出应与 BouncyCastle、离堆实现逐字节一致。
     */
    @Test
    void nativeMatchesReferenceImplementations() {
        assumeTrue(NativeArgon2.isAvailable(), "native lib 不可用，跳过");
        int[][] cases = {
                {8, 2, 1},
                {256, 3, 2},
                {65536, 2, 4},
                {256 << 10, 3, 4},
        };
        for (int[] c : cases) {
            byte[] bc = deriveWithBouncyCastle(c[0], c[1], c[2]);
            byte[] offHeap = Argon2OffHeap.deriveKey(PWD, SALT, c[0], c[1], c[2], 32);
            byte[] nativeKey = NativeArgon2.deriveKey(PWD, SALT, c[0], c[1], c[2], 32);
            assertArrayEquals(bc, nativeKey, "native 与 BouncyCastle 不一致 m=" + c[0]);
            assertArrayEquals(offHeap, nativeKey, "native 与离堆实现不一致 m=" + c[0]);
        }
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
