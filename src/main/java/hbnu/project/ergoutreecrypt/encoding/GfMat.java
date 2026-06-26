package hbnu.project.ergoutreecrypt.encoding;

/**
 * GF(2^8) 矩阵，行主序存储在 {@code int[]} 中（每元素 0..255）。
 *
 * <p>提供高斯消元求逆、标准化为 [I | P] 及从标准型生成校验矩阵等操作，供 Berlekamp-Welch 纠错与
 * 校验矩阵（syndrome）构造使用。
 *
 * @author ErgouTree
 */
final class GfMat {

    /**
     * 行主序矩阵数据。
     */
    final int[] d;

    /**
     * 行数。
     */
    final int r;

    /**
     * 列数。
     */
    final int c;

    /**
     * 创建 rows×cols 的零矩阵。
     *
     * @param rows 行数
     * @param cols 列数
     */
    GfMat(int rows, int cols) {
        this.d = new int[rows * cols];
        this.r = rows;
        this.c = cols;
    }

    /**
     * 计算 (i, j) 在行主序数组中的线性索引。
     */
    private int index(int i, int j) {
        return c * i + j;
    }

    /**
     * 获取第 i 行第 j 列的元素。
     */
    int get(int i, int j) {
        return d[index(i, j)];
    }

    /**
     * 设置第 i 行第 j 列的元素为 val（自动截断至 0..255）。
     */
    void set(int i, int j, int val) {
        d[index(i, j)] = val & 0xff;
    }

    /**
     * 返回第 i 行的副本（长度 c），避免调用方直接修改矩阵内部数据。
     */
    int[] rowCopy(int i) {
        int[] out = new int[c];
        System.arraycopy(d, index(i, 0), out, 0, c);
        return out;
    }

    /**
     * 交换第 i 行与第 j 行。
     */
    private void swapRow(int i, int j) {
        for (int col = 0; col < c; col++) {
            int tmp = d[index(i, col)];
            d[index(i, col)] = d[index(j, col)];
            d[index(j, col)] = tmp;
        }
    }

    /**
     * 对第 i 行进行标量乘法：row_i *= val（GF 域）。
     */
    private void scaleRow(int i, int val) {
        int base = index(i, 0);
        for (int col = 0; col < c; col++) {
            d[base + col] = GfAlg.mul(d[base + col], val);
        }
    }

    /**
     * 行叠加：{@code row_j += val * row_i}（GF 域）。
     */
    private void addmulRow(int i, int j, int val) {
        int baseI = index(i, 0);
        int baseJ = index(j, 0);
        int[] mulV = GaloisField.GF_MUL_TABLE[val & 0xff];
        for (int col = 0; col < c; col++) {
            d[baseJ + col] ^= mulV[d[baseI + col] & 0xff];
        }
    }

    /**
     * 原地求逆：当前矩阵变为单位阵，逆矩阵写入参数 a（a 须初始化为单位阵）。
     * 使用 Gauss-Jordan 消元，含部分主元搜索。
     *
     * @param a 初始为单位阵的同尺寸矩阵，接收逆矩阵结果
     */
    void invertWith(GfMat a) {
        // 正向消元：化为上三角
        for (int i = 0; i < r; i++) {
            int pRow = i;
            int pVal = get(i, i);
            for (int j = i + 1; j < r && GfAlg.isZero(pVal); j++) {
                pRow = j;
                pVal = get(j, i);
            }
            if (GfAlg.isZero(pVal)) {
                continue;
            }
            if (pRow != i) {
                swapRow(i, pRow);
                a.swapRow(i, pRow);
            }
            int inv = GfAlg.inv(pVal);
            scaleRow(i, inv);
            a.scaleRow(i, inv);

            for (int j = i + 1; j < r; j++) {
                int leading = get(j, i);
                addmulRow(i, j, leading);
                a.addmulRow(i, j, leading);
            }
        }

        // 反向消元：消去上三角部分
        for (int i = r - 1; i > 0; i--) {
            for (int j = i - 1; j >= 0; j--) {
                int trailing = get(j, i);
                addmulRow(i, j, trailing);
                a.addmulRow(i, j, trailing);
            }
        }
    }

    /**
     * 原地标准化为 [I | P] 形式（Gauss-Jordan 消元但不维护伴随矩阵）。
     */
    void standardize() {
        // 正向消元
        for (int i = 0; i < r; i++) {
            int pRow = i;
            int pVal = get(i, i);
            for (int j = i + 1; j < r && GfAlg.isZero(pVal); j++) {
                pRow = j;
                pVal = get(j, i);
            }
            if (GfAlg.isZero(pVal)) {
                continue;
            }
            if (pRow != i) {
                swapRow(i, pRow);
            }
            int inv = GfAlg.inv(pVal);
            scaleRow(i, inv);
            for (int j = i + 1; j < r; j++) {
                int leading = get(j, i);
                addmulRow(i, j, leading);
            }
        }

        // 反向消元
        for (int i = r - 1; i > 0; i--) {
            for (int j = i - 1; j >= 0; j--) {
                int trailing = get(j, i);
                addmulRow(i, j, trailing);
            }
        }
    }

    /**
     * 由标准型 [I_r | P] 生成校验矩阵 [P^T | I_{c-r}]。
     * GF(2) 特征下无需取负，转置即等于校验矩阵的 P 部分。
     *
     * @return 尺寸为 (c-r)×c 的校验矩阵
     */
    GfMat parity() {
        GfMat out = new GfMat(c - r, c);
        for (int i = 0; i < c - r; i++) {
            out.set(i, i + r, 1);
        }
        for (int i = 0; i < c - r; i++) {
            for (int j = 0; j < r; j++) {
                out.set(i, j, get(j, i + r));
            }
        }
        return out;
    }
}
