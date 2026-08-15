package hbnu.project.ergoutreecrypt.classical.modern;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;

import java.util.Arrays;

/**
 * AES-256-GCM 字符串密码。
 *
 * <p>采用 256 位密钥与 GCM 认证加密模式，密文携带 128 位认证标签，
 * 任何篡改或密码错误都会在解密时被检测出来。
 *
 * @author ErgouTree
 */
public final class AesCipher extends AbstractModernCipher {

    /**
     * 认证标签字节数（128 位）。
     */
    private static final int TAG_BYTES = 16;

    /**
     * 构造 AES-256-GCM 密码实例。
     */
    public AesCipher() {
        super("aes", "cc.aes.name", "cc.aes.desc");
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
        return TAG_BYTES;
    }

    @Override
    protected int blockSize() {
        return 0;
    }

    @Override
    protected byte algorithmId() {
        return 0x01;
    }

    @Override
    protected byte[] encryptBytes(final byte[] plain, final byte[] key, final byte[] iv) {
        GCMBlockCipher gcm = new GCMBlockCipher(new AESEngine());
        gcm.init(true, new AEADParameters(new KeyParameter(key), 128, iv, null));
        byte[] out = new byte[gcm.getOutputSize(plain.length)];
        int len = gcm.processBytes(plain, 0, plain.length, out, 0);
        try {
            len += gcm.doFinal(out, len);
        } catch (InvalidCipherTextException e) {
            throw new IllegalStateException("GCM encrypt failed", e);
        }
        byte[] tag = gcm.getMac();
        byte[] result = Arrays.copyOf(out, len + tag.length);
        System.arraycopy(tag, 0, result, len, tag.length);
        return result;
    }

    @Override
    protected byte[] decryptBytes(final byte[] cipher, final byte[] key, final byte[] iv)
            throws InvalidCipherTextException {
        int cipherLen = cipher.length - TAG_BYTES;
        GCMBlockCipher gcm = new GCMBlockCipher(new AESEngine());
        gcm.init(false, new AEADParameters(new KeyParameter(key), 128, iv, null));
        byte[] out = new byte[gcm.getOutputSize(cipherLen)];
        int len = gcm.processBytes(cipher, 0, cipherLen, out, 0);
        len += gcm.doFinal(out, len);
        return Arrays.copyOf(out, len);
    }
}
