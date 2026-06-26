package hbnu.project.ergoutreecrypt.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.security.Security;

import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * 验证 {@link XChaCha20} 的核心正确性。
 *
 * <p>关键测试 {@link #hChaCha20Vector()} 使用 IETF 草案
 * draft-irtf-cfrg-xchacha-03 §2.2.1 的官方 HChaCha20 测试向量。HChaCha20 是
 * XChaCha20 的子密钥派生核心，也是 Java 实现最容易与 Go x/crypto 产生分歧之处。
 * 该向量通过即证明子密钥派生与规范（及 Go）一致。
 */
class XChaCha20Test {

    @BeforeAll
    static void setup() {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }
    }

    /**
     * 官方 HChaCha20 测试向量（draft-irtf-cfrg-xchacha-03 §2.2.1）：
     * <pre>
     * key   = 00:01:...:1f
     * nonce = 00:00:00:09:00:00:00:4a:00:00:00:00:31:41:59:27
     * out   = 82413b4227b27bfed30e42508a877d73
     *         a0f9e4d0b7d9d6f96a3da6f6e2f7a3c... (见下)
     * </pre>
     * 期望输出（32 字节子密钥，规范 §2.2.1）：
     * 82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc
     */
    @Test
    void hChaCha20Vector() throws Exception {
        byte[] key = Hex.decode(
                "000102030405060708090a0b0c0d0e0f"
                        + "101112131415161718191a1b1c1d1e1f");
        byte[] nonce16 = Hex.decode("000000090000004a0000000031415927");

        byte[] expected = Hex.decode(
                "82413b4227b27bfed30e42508a877d73"
                        + "a0f9e4d58a74a853c12ec41326d3ecdc");

        // 通过反射调用私有 hChaCha20，专项验证子密钥派生这一最易出错的环节。
        Method m = XChaCha20.class.getDeclaredMethod("hChaCha20", byte[].class, byte[].class);
        m.setAccessible(true);
        byte[] subkey = (byte[]) m.invoke(null, key, nonce16);

        assertArrayEquals(expected, subkey,
                "HChaCha20 子密钥与 RFC 草案向量不一致：\n期望 " + Hex.toHexString(expected)
                        + "\n实际 " + Hex.toHexString(subkey));
    }

    /** 流密码自反性：用相同 key/nonce 加密两次应还原明文。 */
    @Test
    void involution() {
        byte[] key = new byte[32];
        byte[] nonce = new byte[24];
        for (int i = 0; i < 32; i++) {
            key[i] = (byte) i;
        }
        for (int i = 0; i < 24; i++) {
            nonce[i] = (byte) (i + 1);
        }
        byte[] plain = "ErgouTreeCrypt 迁移自 Picocrypt-NG".getBytes(StandardCharsets.UTF_8);

        byte[] ct = new byte[plain.length];
        new XChaCha20(key, nonce).process(ct, plain, plain.length);

        byte[] back = new byte[plain.length];
        new XChaCha20(key, nonce).process(back, ct, ct.length);

        assertArrayEquals(plain, back);
    }
}
