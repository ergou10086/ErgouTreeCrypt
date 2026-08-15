package hbnu.project.ergoutreecrypt.classical.modern;

import org.bouncycastle.crypto.engines.DESedeEngine;

/**
 * 3DES（Triple DES）字符串密码。
 *
 * <p>对 DES 进行三重加密的变体，168 位密钥（有效强度约 112 位），
 * 采用 CBC 模式与 PKCS7 填充。已逐步退役，仅用于教学演示。
 *
 * @author ErgouTree
 */
public final class TripleDesCipher extends AbstractModernCipher {

    /**
     * 构造 3DES 密码实例。
     */
    public TripleDesCipher() {
        super("triple-des", "cc.triple-des.name", "cc.triple-des.desc");
    }

    @Override
    protected int keySize() {
        return 24;
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
        return 0x07;
    }

    @Override
    protected byte[] encryptBytes(final byte[] plain, final byte[] key, final byte[] iv) {
        return cbcProcess(true, plain, new DESedeEngine(), key, iv);
    }

    @Override
    protected byte[] decryptBytes(final byte[] cipher, final byte[] key, final byte[] iv) {
        return cbcProcess(false, cipher, new DESedeEngine(), key, iv);
    }
}
