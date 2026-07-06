package hbnu.project.ergoutreecrypt.classical;

import java.util.List;
import java.util.Map;

/**
 * 栅栏密码（Rail Fence Cipher）。
 *
 * <p>一种换位密码，将明文以锯齿形写入 N 行"栅栏"，再逐行读取得到密文。
 * 换位操作与字符内容无关，天然支持所有语言和 Unicode 字符。
 *
 * <p>参数：
 * <ul>
 *   <li>{@code rails} — 栅栏层数（正整数），默认为 3</li>
 * </ul>
 *
 * @author ErgouTree
 */
public final class RailFenceCipher implements ClassicalCipher {

    private static final CipherInfo INFO = new CipherInfo(
            "railfence",
            "cc.railfence.name",
            "cc.railfence.desc",
            List.of(new CipherInfo.ParamDef("rails", "cc.param.rails", "number", "3"))
    );

    @Override
    public String encrypt(final String plaintext, final Map<String, String> params) {
        int rails = parseRails(params);
        return encode(plaintext, rails);
    }

    @Override
    public String decrypt(final String ciphertext, final Map<String, String> params) {
        int rails = parseRails(params);
        return decode(ciphertext, rails);
    }

    @Override
    public CipherInfo getInfo() {
        return INFO;
    }

    /**
     * 从参数中解析栅栏层数。
     *
     * @param params 算法参数
     * @return 栅栏层数，至少为 2
     */
    private static int parseRails(final Map<String, String> params) {
        if (params != null && params.containsKey("rails")) {
            try {
                int r = Integer.parseInt(params.get("rails"));
                return Math.max(2, r);
            } catch (NumberFormatException ignored) {
                // 解析失败使用默认值
            }
        }
        return 3;
    }

    /**
     * 栅栏加密：锯齿形写入，逐行读取。
     *
     * @param text  明文
     * @param rails 栅栏层数
     * @return 密文
     */
    private String encode(final String text, final int rails) {
        if (text == null || text.isEmpty()) {
            return "";
        }
        if (rails <= 1 || rails >= text.length()) {
            return text;
        }
        int[] codePoints = text.codePoints().toArray();
        int n = codePoints.length;
        StringBuilder[] fence = new StringBuilder[rails];
        for (int i = 0; i < rails; i++) {
            fence[i] = new StringBuilder((n / rails) + 1);
        }
        int row = 0;
        int delta = 1;
        for (int cp : codePoints) {
            fence[row].appendCodePoint(cp);
            if (row == 0) {
                delta = 1;
            } else if (row == rails - 1) {
                delta = -1;
            }
            row += delta;
        }
        StringBuilder result = new StringBuilder(n + 16);
        for (StringBuilder sb : fence) {
            result.append(sb);
        }
        return result.toString();
    }

    /**
     * 栅栏解密：按栅栏布局标记位置，再按锯齿形填入字符。
     *
     * @param text  密文
     * @param rails 栅栏层数
     * @return 明文
     */
    private String decode(final String text, final int rails) {
        if (text == null || text.isEmpty()) {
            return "";
        }
        if (rails <= 1 || rails >= text.length()) {
            return text;
        }
        int[] codePoints = text.codePoints().toArray();
        int n = codePoints.length;
        // 先标记每个位置属于哪一行
        int[] rowAssignment = new int[n];
        int row = 0;
        int delta = 1;
        for (int i = 0; i < n; i++) {
            rowAssignment[i] = row;
            if (row == 0) {
                delta = 1;
            } else if (row == rails - 1) {
                delta = -1;
            }
            row += delta;
        }
        // 计算每行的字符数并按行填充
        int[] rowCounts = new int[rails];
        for (int r : rowAssignment) {
            rowCounts[r]++;
        }
        int[][] rowChars = new int[rails][];
        int idx = 0;
        for (int r = 0; r < rails; r++) {
            rowChars[r] = new int[rowCounts[r]];
            for (int j = 0; j < rowCounts[r]; j++) {
                rowChars[r][j] = codePoints[idx++];
            }
        }
        // 按锯齿顺序读取还原
        int[] rowPos = new int[rails];
        StringBuilder result = new StringBuilder(n + 16);
        for (int i = 0; i < n; i++) {
            int r = rowAssignment[i];
            result.appendCodePoint(rowChars[r][rowPos[r]++]);
        }
        return result.toString();
    }
}
