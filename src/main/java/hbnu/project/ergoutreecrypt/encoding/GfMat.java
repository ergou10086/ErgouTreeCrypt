package hbnu.project.ergoutreecrypt.encoding;

/**
 * GF(2^8) 矩阵
 *
 * <p>行主序存储于 {@code int[]}（每元素 0..255），供 Berlekamp-Welch 纠错与
 * 校验矩阵（syndrome）构造使用。
 *
 * @author ErgouTree
 */
final class GfMat {

    final int[] d;
    final int r;
    final int c;

    GfMat(int rows, int cols) {
        this.d = new int[rows * cols];
        this.r = rows;
        this.c = cols;
    }

    private int index(int i, int j) {
        return c * i + j;
    }

    int get(int i, int j) {
        return d[index(i, j)];
    }

    void set(int i, int j, int val) {
        d[index(i, j)] = val & 0xff;
    }

    /**
     * 返回第 i 行的视图副本（长度 c）。
     */
    int[] rowCopy(int i) {
        int[] out = new int[c];
        System.arraycopy(d, index(i, 0), out, 0, c);
        return out;
    }

    private void swapRow(int i, int j) {
        for (int col = 0; col < c; col++) {
            int tmp = d[index(i, col)];
            d[index(i, col)] = d[index(j, col)];
            d[index(j, col)] = tmp;
        }
    }

    private void scaleRow(int i, int val) {
        int base = index(i, 0);
        for (int col = 0; col < c; col++) {
            d[base + col] = GfAlg.mul(d[base + col], val);
        }
    }

    /**
     * rj += val * ri（GF），对应 addmulRow。
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
     * 原地求逆：m 变为单位阵，结果写入 a（a 须初始为单位阵）。
     * 对应 {@code gfMat.invertWith}。
     */
    void invertWith(GfMat a) {
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
        for (int i = r - 1; i > 0; i--) {
            for (int j = i - 1; j >= 0; j--) {
                int trailing = get(j, i);
                addmulRow(i, j, trailing);
                a.addmulRow(i, j, trailing);
            }
        }
    }

    /**
     * 原地标准化（化为 [I | P]），对应 {@code gfMat.standardize}。
     */
    void standardize() {
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
        for (int i = r - 1; i > 0; i--) {
            for (int j = i - 1; j >= 0; j--) {
                int trailing = get(j, i);
                addmulRow(i, j, trailing);
            }
        }
    }

    /**
     * 由标准型 [I_r | P] 生成校验矩阵 [P^T | I_(c-r)]（GF(2) 特征下无需取负）。
     * 对应 {@code gfMat.parity}。
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
