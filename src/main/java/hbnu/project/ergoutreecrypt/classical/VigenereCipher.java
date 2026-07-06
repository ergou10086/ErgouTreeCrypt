package hbnu.project.ergoutreecrypt.classical;

import java.util.List;
import java.util.Map;

/**
 * 维吉尼亚密码（Vigenère Cipher）。
 *
 * <p>一种多表替换密码，使用关键词的每个字符的码点作为位移量，
 * 对明文中对应位置的字符进行凯撒位移。关键词循环使用。
 * 支持所有 Unicode 字符。
 *
 * <p>参数：
 * <ul>
 *   <li>{@code keyword} — 关键词字符串，默认为空</li>
 * </ul>
 *
 * @author ErgouTree
 */
public final class VigenereCipher implements ClassicalCipher {

    private static final int SAFE_RANGE = CodePointUtil.SAFE_RANGE;

    private static final CipherInfo INFO = new CipherInfo(
            "vigenere",
            "cc.vigenere.name",
            "cc.vigenere.desc",
            List.of(new CipherInfo.ParamDef("keyword", "cc.param.keyword", "text", ""))
    );

    @Override
    public String encrypt(final String plaintext, final Map<String, String> params) {
        String keyword = getKeyword(params);
        return transform(plaintext, keyword, true);
    }

    @Override
    public String decrypt(final String ciphertext, final Map<String, String> params) {
        String keyword = getKeyword(params);
        return transform(ciphertext, keyword, false);
    }

    @Override
    public CipherInfo getInfo() {
        return INFO;
    }

    /**
     * 从参数中获取关键词。
     *
     * @param params 算法参数
     * @return 关键词字符串
     */
    private static String getKeyword(final Map<String, String> params) {
        if (params != null && params.containsKey("keyword")) {
            return params.get("keyword");
        }
        return "";
    }

    /**
     * 执行维吉尼亚变换。
     *
     * @param text    输入文本
     * @param keyword 关键词
     * @param encrypt true 为加密（加法），false 为解密（减法）
     * @return 变换后的文本
     */
    static String transform(final String text, final String keyword, final boolean encrypt) {
        if (text == null || text.isEmpty()) {
            return "";
        }
        int[] keyCodePoints = (keyword != null && !keyword.isEmpty())
                ? keyword.codePoints().toArray()
                : new int[]{0};
        if (keyCodePoints.length == 0) {
            keyCodePoints = new int[]{0};
        }

        int[] textCodePoints = text.codePoints().toArray();
        StringBuilder sb = new StringBuilder(text.length() + 16);
        for (int i = 0; i < textCodePoints.length; i++) {
            int cp = textCodePoints[i];
            int keyCp = keyCodePoints[i % keyCodePoints.length];
            int keyShift = CodePointUtil.toSafePosition(keyCp);
            int pos = CodePointUtil.toSafePosition(cp);
            int result;
            if (encrypt) {
                result = Math.floorMod(pos + keyShift, SAFE_RANGE);
            } else {
                result = Math.floorMod(pos - keyShift, SAFE_RANGE);
            }
            sb.appendCodePoint(CodePointUtil.fromSafePosition(result));
        }
        return sb.toString();
    }
}
