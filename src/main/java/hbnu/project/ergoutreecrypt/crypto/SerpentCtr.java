package hbnu.project.ergoutreecrypt.crypto;

import org.bouncycastle.crypto.engines.SerpentEngine;
import org.bouncycastle.crypto.modes.SICBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

/**
 * Serpent-CTR 流密码（偏执模式），对应原项目中 {@code internal/crypto/cipher.go} 中 {@code cipher.NewCTR(serpent.NewCipher(key), iv)}。
 * <p>
 * 使用 BouncyCastle 的标准 {@link SerpentEngine} 配 CTR 模式（{@link SICBlockCipher}）。
 *
 * @author ErgouTree
 */
public final class SerpentCtr {

    private final SICBlockCipher cipher;

    /**
     * @param key 32 字节 Serpent 密钥
     * @param iv  16 字节初始计数器（IV）
     */
    public SerpentCtr(byte[] key, byte[] iv) {
        if (iv.length != 16) {
            throw new IllegalArgumentException("Serpent IV must be 16 bytes, got " + iv.length);
        }
        cipher = new SICBlockCipher(new SerpentEngine());
        cipher.init(true, new ParametersWithIV(new KeyParameter(key), iv));
    }

    /**
     * 流加解密（XOR keystream）。CTR 模式下加解密为同一操作。
     */
    public void process(byte[] out, byte[] in, int len) {
        cipher.processBytes(in, 0, len, out, 0);
    }
}
