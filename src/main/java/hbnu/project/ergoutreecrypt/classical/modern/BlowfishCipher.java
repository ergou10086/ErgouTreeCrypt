package hbnu.project.ergoutreecrypt.classical.modern;

import org.bouncycastle.crypto.engines.BlowfishEngine;

/**
 * Blowfish 字符串密码。
 *
 * <p>Bruce Schneier 设计的 64 位分组密码，采用 256 位密钥、CBC 模式与 PKCS7 填充。
 *
 * @author ErgouTree
 */
public final class BlowfishCipher extends AbstractModernCipher {

    /**
     * 构造 Blowfish 密码实例。
     */
    public BlowfishCipher() {
        super("blowfish", "cc.blowfish.name", "cc.blowfish.desc");
    }

    @Override
    protected int keySize() {
        return 32;
    }

    @Override
    protected int ivSize() {
        return 8;
    }

    @Override
    protected int tagSize() {
        return 0;
    }

    @Override
    protected int blockSize() {
        return 8;
    }

    @Override
    protected byte algorithmId() {
        return 0x04;
    }

    @Override
    protected byte[] encryptBytes(final byte[] plain, final byte[] key, final byte[] iv) {
        return cbcProcess(true, plain, new BlowfishEngine(), key, iv);
    }

    @Override
    protected byte[] decryptBytes(final byte[] cipher, final byte[] key, final byte[] iv) {
        return cbcProcess(false, cipher, new BlowfishEngine(), key, iv);
    }
}
