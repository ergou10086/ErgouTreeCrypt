package hbnu.project.ergoutreecrypt.classical;

import java.util.Collections;
import java.util.Map;

/**
 * 反转密码（Reverse Cipher）。
 *
 * <p>最简单的换位密码，将文本中的字符（按码点）或字节序列完全反转。
 * 加密与解密为同一操作（自反），支持所有 Unicode 字符。
 *
 * <p>无参数。
 *
 * @author ErgouTree
 */
public final class ReverseCipher implements ClassicalCipher {

    private static final CipherInfo INFO = new CipherInfo(
            "reverse",
            "cc.reverse.name",
            "cc.reverse.desc",
            Collections.emptyList()
    );

    @Override
    public String encrypt(final String plaintext, final Map<String, String> params) {
        return reverse(plaintext);
    }

    @Override
    public String decrypt(final String ciphertext, final Map<String, String> params) {
        // 反转为自反操作
        return reverse(ciphertext);
    }

    @Override
    public CipherInfo getInfo() {
        return INFO;
    }

    /**
     * 按 Unicode 码点反转字符串。
     *
     * @param text 输入字符串
     * @return 反转后的字符串
     */
    private String reverse(final String text) {
        if (text == null || text.isEmpty()) {
            return "";
        }
        int[] codePoints = text.codePoints().toArray();
        StringBuilder sb = new StringBuilder(text.length() + 16);
        for (int i = codePoints.length - 1; i >= 0; i--) {
            sb.appendCodePoint(codePoints[i]);
        }
        return sb.toString();
    }
}
