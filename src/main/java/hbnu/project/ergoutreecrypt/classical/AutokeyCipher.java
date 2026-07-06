package hbnu.project.ergoutreecrypt.classical;

import java.util.List;
import java.util.Map;

/**
 * 自动密钥密码（Autokey Cipher）。
 *
 * <p>维吉尼亚密码的变体，密钥由初始关键词后接明文自身构成，
 * 避免了维吉尼亚密码中因短关键词循环使用带来的周期性规律。
 * 支持所有 Unicode 字符。
 *
 * <p>参数：
 * <ul>
 *   <li>{@code keyword} — 初始关键词字符串，默认为空</li>
 * </ul>
 *
 * @author ErgouTree
 */
public final class AutokeyCipher implements ClassicalCipher {

    private static final int SAFE_RANGE = CodePointUtil.SAFE_RANGE;

    private static final CipherInfo INFO = new CipherInfo(
            "autokey",
            "cc.autokey.name",
            "cc.autokey.desc",
            List.of(new CipherInfo.ParamDef("keyword", "cc.param.keyword", "text", ""))
    );

    @Override
    public String encrypt(final String plaintext, final Map<String, String> params) {
        String keyword = getKeyword(params);
        return encryptTransform(plaintext, keyword);
    }

    @Override
    public String decrypt(final String ciphertext, final Map<String, String> params) {
        String keyword = getKeyword(params);
        return decryptTransform(ciphertext, keyword);
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
     * Autokey 加密：密钥 = 初始关键词 + 明文自身。
     *
     * @param text    明文
     * @param keyword 初始关键词
     * @return 密文
     */
    private String encryptTransform(final String text, final String keyword) {
        if (text == null || text.isEmpty()) {
            return "";
        }
        int[] keyInit = (keyword != null && !keyword.isEmpty())
                ? keyword.codePoints().toArray()
                : new int[0];
        int[] textCps = text.codePoints().toArray();
        // 构建完整密钥流：关键词 + 明文自身
        int[] fullKey = new int[keyInit.length + textCps.length];
        System.arraycopy(keyInit, 0, fullKey, 0, keyInit.length);
        System.arraycopy(textCps, 0, fullKey, keyInit.length, textCps.length);

        StringBuilder sb = new StringBuilder(text.length() + 16);
        for (int i = 0; i < textCps.length; i++) {
            int pos = CodePointUtil.toSafePosition(textCps[i]);
            int keyShift = CodePointUtil.toSafePosition(fullKey[i]);
            int result = Math.floorMod(pos + keyShift, SAFE_RANGE);
            sb.appendCodePoint(CodePointUtil.fromSafePosition(result));
        }
        return sb.toString();
    }

    /**
     * Autokey 解密：密钥 = 初始关键词 + 解密过程中逐步恢复的明文。
     *
     * @param text    密文
     * @param keyword 初始关键词
     * @return 明文
     */
    private String decryptTransform(final String text, final String keyword) {
        if (text == null || text.isEmpty()) {
            return "";
        }
        int[] keyInit = (keyword != null && !keyword.isEmpty())
                ? keyword.codePoints().toArray()
                : new int[0];
        int[] textCps = text.codePoints().toArray();

        StringBuilder sb = new StringBuilder(text.length() + 16);
        // 解密时逐步构建密钥流
        int[] decrypted = new int[textCps.length];
        for (int i = 0; i < textCps.length; i++) {
            // 当前密钥码点：如果 i 在关键词范围内则用关键词，否则用已解密的明文
            int keyCp;
            if (i < keyInit.length) {
                keyCp = keyInit[i];
            } else {
                keyCp = decrypted[i - keyInit.length];
            }
            int pos = CodePointUtil.toSafePosition(textCps[i]);
            int keyShift = CodePointUtil.toSafePosition(keyCp);
            int result = Math.floorMod(pos - keyShift, SAFE_RANGE);
            decrypted[i] = CodePointUtil.fromSafePosition(result);
            sb.appendCodePoint(CodePointUtil.fromSafePosition(result));
        }
        return sb.toString();
    }
}
