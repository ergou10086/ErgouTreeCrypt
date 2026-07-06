package hbnu.project.ergoutreecrypt.classical;

import java.util.Collections;
import java.util.Map;

/**
 * 埃特巴什码（Atbash Cipher）。
 *
 * <p>一种替换密码，将字符映射到 Unicode 码点空间的对称位置。
 * 加密与解密为同一操作（自反），支持所有 Unicode 字符。
 *
 * <p>无参数。
 *
 * @author ErgouTree
 */
public final class AtbashCipher implements ClassicalCipher {

    private static final int SAFE_RANGE = CodePointUtil.SAFE_RANGE;

    private static final CipherInfo INFO = new CipherInfo(
            "atbash",
            "cc.atbash.name",
            "cc.atbash.desc",
            Collections.emptyList()
    );

    @Override
    public String encrypt(final String plaintext, final Map<String, String> params) {
        return transform(plaintext);
    }

    @Override
    public String decrypt(final String ciphertext, final Map<String, String> params) {
        // Atbash 为自反操作
        return transform(ciphertext);
    }

    @Override
    public CipherInfo getInfo() {
        return INFO;
    }

    /**
     * 将每个 Unicode 码点映射到码点空间中的对称位置。
     *
     * @param text 输入字符串
     * @return 变换后的字符串
     */
    private String transform(final String text) {
        if (text == null || text.isEmpty()) {
            return "";
        }
        int[] codePoints = text.codePoints().toArray();
        StringBuilder sb = new StringBuilder(text.length() + 16);
        for (int cp : codePoints) {
            int pos = CodePointUtil.toSafePosition(cp);
            int reversed = SAFE_RANGE - 1 - pos;
            sb.appendCodePoint(CodePointUtil.fromSafePosition(reversed));
        }
        return sb.toString();
    }
}
