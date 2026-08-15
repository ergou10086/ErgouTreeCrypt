package hbnu.project.ergoutreecrypt.classical.modern;

import org.bouncycastle.crypto.engines.ChaCha7539Engine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

/**
 * ChaCha20 字符串密码。
 *
 * <p>采用 256 位密钥与 96 位随机 nonce 的流密码，加密与解密为同一异或操作。
 * 无完整性校验——密码错误会静默产出乱码而非报错，仅作教学演示。
 *
 * @author ErgouTree
 */
public final class ChaCha20Cipher extends AbstractModernCipher {

    /**
     * 构造 ChaCha20 密码实例。
     */
    public ChaCha20Cipher() {
        super("chacha20", "cc.chacha20.name", "cc.chacha20.desc");
    }

    @Override
    protected int keySize() {
        return 32;
    }

    @Override
    protected int ivSize() {
        return 12;
    }

    @Override
    protected int tagSize() {
        return 0;
    }

    @Override
    protected int blockSize() {
        return 0;
    }

    @Override
    protected byte algorithmId() {
        return 0x02;
    }

    @Override
    protected byte[] encryptBytes(final byte[] plain, final byte[] key, final byte[] iv) {
        ChaCha7539Engine engine = new ChaCha7539Engine();
        engine.init(true, new ParametersWithIV(new KeyParameter(key), iv));
        byte[] out = new byte[plain.length];
        engine.processBytes(plain, 0, plain.length, out, 0);
        return out;
    }

    @Override
    protected byte[] decryptBytes(final byte[] cipher, final byte[] key, final byte[] iv) {
        return encryptBytes(cipher, key, iv);
    }
}
