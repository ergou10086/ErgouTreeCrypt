package hbnu.project.ergoutreecrypt.classical.modern;

import org.bouncycastle.crypto.engines.SM4Engine;

/**
 * SM4 字符串密码。
 *
 * <p>中国国家密码管理局发布的分组密码标准（GM/T 0002），
 * 采用 128 位密钥、CBC 模式与 PKCS7 填充。
 *
 * @author ErgouTree
 */
public final class Sm4Cipher extends AbstractModernCipher {

    /**
     * 构造 SM4 密码实例。
     */
    public Sm4Cipher() {
        super("sm4", "cc.sm4.name", "cc.sm4.desc");
    }

    @Override
    protected int keySize() {
        return 16;
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
        return 0x03;
    }

    @Override
    protected byte[] encryptBytes(final byte[] plain, final byte[] key, final byte[] iv) {
        return cbcProcess(true, plain, new SM4Engine(), key, iv);
    }

    @Override
    protected byte[] decryptBytes(final byte[] cipher, final byte[] key, final byte[] iv) {
        return cbcProcess(false, cipher, new SM4Engine(), key, iv);
    }
}
