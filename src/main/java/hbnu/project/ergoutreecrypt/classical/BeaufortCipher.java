package hbnu.project.ergoutreecrypt.classical;

import java.util.List;
import java.util.Map;

/**
 * 博福特密码（Beaufort Cipher）。
 *
 * <p>一种自反多表替换密码：加密操作与解密操作完全相同。
 * 变换公式为 {@code cipherPos = (keyPos - plainPos) mod SAFE_RANGE}，
 * 两次变换还原原文。支持所有 Unicode 字符。
 *
 * <p>参数：
 * <ul>
 *   <li>{@code keyword} — 关键词字符串，默认为空</li>
 * </ul>
 *
 * @author ErgouTree
 */
public final class BeaufortCipher implements ClassicalCipher {

    private static final int SAFE_RANGE = CodePointUtil.SAFE_RANGE;

    private static final CipherInfo INFO = new CipherInfo(
            "beaufort",
            "cc.beaufort.name",
            "cc.beaufort.desc",
            List.of(new CipherInfo.ParamDef("keyword", "cc.param.keyword", "text", ""))
    );

    @Override
    public String encrypt(final String plaintext, final Map<String, String> params) {
        return transform(plaintext, params);
    }

    @Override
    public String decrypt(final String ciphertext, final Map<String, String> params) {
        // Beaufort 为自反操作
        return transform(ciphertext, params);
    }

    @Override
    public CipherInfo getInfo() {
        return INFO;
    }

    /**
     * 执行博福特变换（自反）。
     *
     * <p>对每个字符：resultPos = (keyPos - textPos) mod SAFE_RANGE
     *
     * @param text   输入文本
     * @param params 参数（含 keyword）
     * @return 变换后的文本
     */
    private String transform(final String text, final Map<String, String> params) {
        if (text == null || text.isEmpty()) {
            return "";
        }
        String keyword = "";
        if (params != null && params.containsKey("keyword")) {
            keyword = params.get("keyword");
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
            int keyPos = CodePointUtil.toSafePosition(keyCp);
            int pos = CodePointUtil.toSafePosition(cp);
            int result = Math.floorMod(keyPos - pos, SAFE_RANGE);
            sb.appendCodePoint(CodePointUtil.fromSafePosition(result));
        }
        return sb.toString();
    }
}
