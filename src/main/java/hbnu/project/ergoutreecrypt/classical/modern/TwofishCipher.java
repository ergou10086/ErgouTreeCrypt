package hbnu.project.ergoutreecrypt.classical.modern;

import org.bouncycastle.crypto.engines.TwofishEngine;

/**
 * Twofish 字符串密码。
 *
 * <p>Blowfish 的后继者、AES 竞赛决赛算法，采用 256 位密钥、CBC 模式与 PKCS7 填充。
 *
 * @author ErgouTree
 */
public final class TwofishCipher extends AbstractModernCipher {

    /**
     * 构造 Twofish 密码实例。
     */
    public TwofishCipher() {
        super("twofish", "cc.twofish.name", "cc.twofish.desc");
    }

    @Override
    protected int keySize() {
        return 32;
    }

    @Override
    protected int ivSize() {
        return 16;
    }

    @Override
    protected int tagSize() {
        return 0;
    }

    @Override
    protected int blockSize() {
        return 16;
    }

    @Override
    protected byte algorithmId() {
        return 0x05;
    }

    @Override
    protected byte[] encryptBytes(final byte[] plain, final byte[] key, final byte[] iv) {
        return cbcProcess(true, plain, new TwofishEngine(), key, iv);
    }

    @Override
    protected byte[] decryptBytes(final byte[] cipher, final byte[] key, final byte[] iv) {
        return cbcProcess(false, cipher, new TwofishEngine(), key, iv);
    }
}
