package hbnu.project.ergoutreecrypt.crypto;

import org.bouncycastle.crypto.engines.SerpentEngine;
import org.bouncycastle.crypto.modes.SICBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

/**
 * Serpent-CTR 流密码（偏执模式叠加层）。
 *
 * <p>使用 BouncyCastle 的 {@link SerpentEngine} 配合 CTR 模式（{@link SICBlockCipher}），
 * 提供与 XChaCha20 正交的额外加密层。CTR 模式下加解密为同一操作。
 *
 * @author ErgouTree
 */
public final class SerpentCtr {

    /**
     * Serpent-CTR 密码引擎。
     */
    private final SICBlockCipher cipher;

    /**
     * 初始化 Serpent-CTR 流密码。
     *
     * @param key 32 字节 Serpent 密钥
     * @param iv  16 字节初始计数器（IV）
     * @throws IllegalArgumentException 若 IV 长度不是 16 字节
     */
    public SerpentCtr(byte[] key, byte[] iv) {
        if (iv.length != 16) {
            throw new IllegalArgumentException("Serpent IV must be 16 bytes, got " + iv.length);
        }
        cipher = new SICBlockCipher(new SerpentEngine());
        cipher.init(true, new ParametersWithIV(new KeyParameter(key), iv));
    }

    /**
     * 流加解密处理（XOR keystream）。CTR 模式下加解密为同一操作。
     *
     * @param out 输出缓冲区
     * @param in  输入数据
     * @param len 处理字节数
     */
    public void process(byte[] out, byte[] in, int len) {
        cipher.processBytes(in, 0, len, out, 0);
    }
}
