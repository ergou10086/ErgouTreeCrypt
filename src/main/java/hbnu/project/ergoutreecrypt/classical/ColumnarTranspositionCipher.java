package hbnu.project.ergoutreecrypt.classical;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;

/**
 * 列移位密码（Columnar Transposition Cipher）。
 *
 * <p>一种换位密码，将明文按行填入固定列宽的矩阵，然后按关键词各字符的排序顺序
 * 重新排列各列读出密文。换位操作与字符内容无关，天然支持所有语言和 Unicode 字符。
 *
 * <p>参数：
 * <ul>
 *   <li>{@code keyword} — 列排序关键词字符串，默认为空</li>
 * </ul>
 *
 * @author ErgouTree
 */
public final class ColumnarTranspositionCipher implements ClassicalCipher {

    private static final CipherInfo INFO = new CipherInfo(
            "coltrans",
            "cc.coltrans.name",
            "cc.coltrans.desc",
            List.of(new CipherInfo.ParamDef("keyword", "cc.param.keyword", "text", ""))
    );

    @Override
    public String encrypt(final String plaintext, final Map<String, String> params) {
        String keyword = getKeyword(params);
        return encode(plaintext, keyword);
    }

    @Override
    public String decrypt(final String ciphertext, final Map<String, String> params) {
        String keyword = getKeyword(params);
        return decode(ciphertext, keyword);
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
     * 列移位加密。
     *
     * <p>将文本按行写入 width × ceil(n/width) 的矩阵，按关键词排序后的列顺序逐列读取。
     *
     * @param text    明文
     * @param keyword 列排序关键词
     * @return 密文
     */
    private String encode(final String text, final String keyword) {
        if (text == null || text.isEmpty()) {
            return "";
        }
        int width = resolveWidth(keyword);
        if (width <= 1) {
            return text;
        }
        int[] cps = text.codePoints().toArray();
        int n = cps.length;
        int height = (n + width - 1) / width;
        // 填充矩阵
        int[][] matrix = new int[height][width];
        int idx = 0;
        for (int r = 0; r < height; r++) {
            for (int c = 0; c < width; c++) {
                matrix[r][c] = (idx < n) ? cps[idx++] : 0;
            }
        }
        // 获取列排序
        int[] colOrder = columnOrder(keyword, width);
        StringBuilder result = new StringBuilder(n + 16);
        for (int c : colOrder) {
            for (int r = 0; r < height; r++) {
                if (matrix[r][c] != 0 || (r * width + c < n)) {
                    result.appendCodePoint(matrix[r][c]);
                }
            }
        }
        return result.toString();
    }

    /**
     * 列移位解密。
     *
     * @param text    密文
     * @param keyword 列排序关键词
     * @return 明文
     */
    private String decode(final String text, final String keyword) {
        if (text == null || text.isEmpty()) {
            return "";
        }
        int width = resolveWidth(keyword);
        if (width <= 1) {
            return text;
        }
        int[] cps = text.codePoints().toArray();
        int n = cps.length;
        int height = (n + width - 1) / width;
        int fullCols = n % width;
        if (fullCols == 0) {
            fullCols = width;
        }
        // 获取列顺序
        int[] colOrder = columnOrder(keyword, width);
        // 计算每列的行数
        int[] colHeights = new int[width];
        for (int c = 0; c < width; c++) {
            colHeights[c] = (c < fullCols) ? height : height - 1;
        }
        // 按列顺序读取并填入矩阵
        int[][] matrix = new int[height][width];
        int idx = 0;
        for (int orderedCol : colOrder) {
            for (int r = 0; r < colHeights[orderedCol]; r++) {
                matrix[r][orderedCol] = cps[idx++];
            }
        }
        // 按行读取还原
        StringBuilder result = new StringBuilder(n + 16);
        for (int r = 0; r < height; r++) {
            for (int c = 0; c < width; c++) {
                if (matrix[r][c] != 0) {
                    result.appendCodePoint(matrix[r][c]);
                }
            }
        }
        return result.toString();
    }

    /**
     * 解析列宽：取关键词长度，若为空则返回 0。
     */
    private static int resolveWidth(final String keyword) {
        if (keyword == null || keyword.isEmpty()) {
            return 0;
        }
        return Math.max(1, keyword.codePointCount(0, keyword.length()));
    }

    /**
     * 根据关键词字符的自然排序生成列读取顺序。
     *
     * @param keyword 关键词
     * @param width   列数
     * @return 排序后的列索引数组
     */
    private int[] columnOrder(final String keyword, final int width) {
        int[] keyCps = keyword.codePoints().toArray();
        // 创建带原始索引的列信息
        List<ColEntry> entries = new ArrayList<>(width);
        for (int i = 0; i < width; i++) {
            int cp = (i < keyCps.length) ? keyCps[i] : i;
            entries.add(new ColEntry(i, cp));
        }
        // 按码点排序，码点相同保持原始顺序（稳定排序）
        entries.sort(Comparator.comparingInt(ColEntry::keyCp));
        int[] order = new int[width];
        for (int i = 0; i < width; i++) {
            order[i] = entries.get(i).index;
        }
        return order;
    }

    /**
     * 列条目：原始索引与对应关键词码点。
     */
    private record ColEntry(int index, int keyCp) {
    }
}
