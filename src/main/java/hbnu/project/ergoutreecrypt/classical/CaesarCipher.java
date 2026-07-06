package hbnu.project.ergoutreecrypt.classical;

import java.util.List;
import java.util.Map;

/**
 * 凯撒密码（Caesar Cipher）。
 *
 * <p>一种替换密码，通过将每个字符的 Unicode 码点按固定偏移量位移来实现加密。
 * 支持所有 Unicode 字符（自动跳过代理对范围），加密与解密互为逆操作。
 *
 * <p>参数：
 * <ul>
 *   <li>{@code shift} — 位移量（整数），默认为 3</li>
 * </ul>
 *
 * @author ErgouTree
 */
public final class CaesarCipher implements ClassicalCipher {

    /**
     * Unicode 安全范围内码点总数，引用自 {@link CodePointUtil#SAFE_RANGE}。
     */
    static final int SAFE_RANGE = CodePointUtil.SAFE_RANGE;

    private static final CipherInfo INFO = new CipherInfo(
            "caesar",
            "cc.caesar.name",
            "cc.caesar.desc",
            List.of(new CipherInfo.ParamDef("shift", "cc.param.shift", "number", "3"))
    );

    @Override
    public String encrypt(final String plaintext, final Map<String, String> params) {
        int shift = parseShift(params);
        return shiftCodePoints(plaintext, shift);
    }

    @Override
    public String decrypt(final String ciphertext, final Map<String, String> params) {
        int shift = parseShift(params);
        return shiftCodePoints(ciphertext, -shift);
    }

    @Override
    public CipherInfo getInfo() {
        return INFO;
    }

    /**
     * 从参数 Map 中解析位移量。
     *
     * @param params 算法参数
     * @return 位移量整数值
     */
    private static int parseShift(final Map<String, String> params) {
        if (params != null && params.containsKey("shift")) {
            try {
                return Integer.parseInt(params.get("shift"));
            } catch (NumberFormatException ignored) {
                // 解析失败使用默认值
            }
        }
        return 3;
    }

    /**
     * 对字符串中的每个 Unicode 码点进行位移变换。
     *
     * <p>码点先映射到安全连续区间（跳过代理对），位移后取模映射回原始码点空间。
     *
     * @param text  输入字符串
     * @param shift 位移量
     * @return 变换后的字符串
     */
    static String shiftCodePoints(final String text, final int shift) {
        if (text == null || text.isEmpty()) {
            return "";
        }
        int[] codePoints = text.codePoints().toArray();
        StringBuilder sb = new StringBuilder(text.length() + 16);
        for (int cp : codePoints) {
            int pos = CodePointUtil.toSafePosition(cp);
            int shifted = Math.floorMod(pos + shift, SAFE_RANGE);
            sb.appendCodePoint(CodePointUtil.fromSafePosition(shifted));
        }
        return sb.toString();
    }

}
