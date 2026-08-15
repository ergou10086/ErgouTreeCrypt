package hbnu.project.ergoutreecrypt.classical.modern;

import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.params.DESParameters;

/**
 * DES 字符串密码。
 *
 * <p>1977 年的经典分组密码，56 位有效密钥，采用 CBC 模式与 PKCS7 填充。
 * 密钥已可被暴力破解，仅用于教学演示。派生密钥若恰好为弱密钥会翻转一位规避。
 *
 * @author ErgouTree
 */
public final class DesCipher extends AbstractModernCipher {

    /**
     * 构造 DES 密码实例。
     */
    public DesCipher() {
        super("des", "cc.des.name", "cc.des.desc");
    }

    @Override
    protected int keySize() {
        return 8;
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
        return 0x06;
    }

    @Override
    protected byte[] adjustKey(final byte[] key) {
        if (DESParameters.isWeakKey(key, 0)) {
            key[7] ^= 0x01;
        }
        return key;
    }

    @Override
    protected byte[] encryptBytes(final byte[] plain, final byte[] key, final byte[] iv) {
        return cbcProcess(true, plain, new DESEngine(), key, iv);
    }

    @Override
    protected byte[] decryptBytes(final byte[] cipher, final byte[] key, final byte[] iv) {
        return cbcProcess(false, cipher, new DESEngine(), key, iv);
    }
}
