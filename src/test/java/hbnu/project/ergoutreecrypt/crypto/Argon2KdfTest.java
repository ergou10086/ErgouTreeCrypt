package hbnu.project.ergoutreecrypt.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.security.Security;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * 验证 {@link Argon2Kdf} 的 Argon2id 实现正确性。
 *
 * <p>{@link #referenceVector()} 使用 phc-winner-argon2 参考实现的标准测试向量
 * （Argon2id v1.3，低内存参数），证明 BouncyCastle 的 Argon2id 与规范一致。
 * Go 的 {@code golang.org/x/crypto/argon2} 同样遵循该规范，因此参数相同则输出相同
 * ——这是能解密既有 .pcv 卷的前提（仅参数不同：Picocrypt 用 m=1GiB）。
 */
class Argon2KdfTest {

    @BeforeAll
    static void setup() {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }
    }

    /**
     * Go x/crypto argon2 官方测试向量（argon2_test.go 的 TestVectors）：
     * password = "password", salt = "somesalt", 模式 Argon2id,
     * t=3, m=256 KiB, p=2, 输出 24 字节 → 4668d30ac4187e6878eedeacf0fd83c5a0a30db2cc16ef0b。
     *
     * <p>通过此向量即证明 BouncyCastle 的 Argon2id 与 Go x/crypto 字节一致——这是
     * 解密既有 .pcv 卷的根本前提（Picocrypt 仅参数不同：m=1GiB、固定 32 字节输出）。
     */
    @Test
    void goCryptoVector() {
        byte[] pwd = "password".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] salt = "somesalt".getBytes(java.nio.charset.StandardCharsets.UTF_8);

        Argon2Parameters params = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                .withIterations(3)
                .withMemoryAsKB(256)
                .withParallelism(2)
                .withSalt(salt)
                .build();
        Argon2BytesGenerator gen = new Argon2BytesGenerator();
        gen.init(params);
        byte[] out = new byte[24];
        gen.generateBytes(pwd, out);

        byte[] expected = Hex.decode("4668d30ac4187e6878eedeacf0fd83c5a0a30db2cc16ef0b");
        assertArrayEquals(expected, out,
                "Argon2id 与 Go x/crypto 向量不一致：实际 " + Hex.toHexString(out));
    }

    /** 验证 {@link Argon2Kdf} 普通模式确定性与长度（不依赖 1GiB 内存）。 */
    @Test
    void deriveKeyDeterministic() {
        byte[] pwd = "ergou".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] salt = Hex.decode("000102030405060708090a0b0c0d0e0f");
        byte[] k1 = Argon2Kdf.deriveKey(pwd, salt, false);
        byte[] k2 = Argon2Kdf.deriveKey(pwd, salt, false);
        assertEquals(32, k1.length);
        assertArrayEquals(k1, k2);
    }
}
