package hbnu.project.ergoutreecrypt.classical;

import java.util.Collections;
import java.util.Map;

/**
 * ROT13 密码。
 *
 * <p>凯撒密码的特例，固定位移量为 13。加密与解密为同一操作（自反），
 * 两次 ROT13 操作还原原文。支持所有 Unicode 字符。
 *
 * <p>无参数。
 *
 * @author ErgouTree
 */
public final class Rot13Cipher implements ClassicalCipher {

    private static final int SHIFT = 13;

    private static final CipherInfo INFO = new CipherInfo(
            "rot13",
            "cc.rot13.name",
            "cc.rot13.desc",
            Collections.emptyList()
    );

    @Override
    public String encrypt(final String plaintext, final Map<String, String> params) {
        return CaesarCipher.shiftCodePoints(plaintext, SHIFT);
    }

    @Override
    public String decrypt(final String ciphertext, final Map<String, String> params) {
        // ROT13 为自反操作
        return CaesarCipher.shiftCodePoints(ciphertext, SHIFT);
    }

    @Override
    public CipherInfo getInfo() {
        return INFO;
    }
}
