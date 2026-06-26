package hbnu.project.ergoutreecrypt.encoding;

import java.util.Arrays;

/**
 * FEC 矩阵运算工具。
 *
 * <p>提供 {@code invertMatrix}（高斯消元求逆）与 {@code createInvertedVdm}（构造逆 Vandermonde 矩阵），
 * 供 {@link Fec#newFec} 编码矩阵构造与 {@link Fec#rebuild} 重建解码使用。
 *
 * @author ErgouTree
 */
final class FecMath {

    private FecMath() {
    }

    /**
     * 交换数组 a 中索引 i 与 j 处的字节。
     */
    private static void swap(byte[] a, int i, int j) {
        byte t = a[i];
        a[i] = a[j];
        a[j] = t;
    }

    /**
     * 原地求逆 K×K 矩阵（行主序），使用 Gauss-Jordan 消元。
     * 包含部分主元搜索，在 GF(2^8) 上完成所有算术运算。
     *
     * @param matrix K×K 矩阵（行主序），计算完成后即变为逆矩阵
     * @param k      矩阵维度
     * @throws ArithmeticException 若矩阵奇异无法求逆
     */
    static void invertMatrix(byte[] matrix, int k) {
        PivotSearcher pivotSearcher = new PivotSearcher(k);
        int[] indxc = new int[k];
        int[] indxr = new int[k];
        byte[] idRow = new byte[k];

        for (int col = 0; col < k; col++) {
            int[] ir = pivotSearcher.search(col, matrix);
            int icol = ir[0];
            int irow = ir[1];

            // 必要时交换行
            if (irow != icol) {
                for (int i = 0; i < k; i++) {
                    swap(matrix, irow * k + i, icol * k + i);
                }
            }

            indxr[col] = irow;
            indxc[col] = icol;

            // 将主元归一化
            int pivotBase = icol * k;
            int c = matrix[pivotBase + icol] & 0xff;
            if (c == 0) {
                throw new ArithmeticException("singular matrix");
            }

            if (c != 1) {
                c = GaloisField.GF_INVERSE[c];
                matrix[pivotBase + icol] = 1;
                int[] mulC = GaloisField.GF_MUL_TABLE[c];
                for (int i = 0; i < k; i++) {
                    matrix[pivotBase + i] = (byte) mulC[matrix[pivotBase + i] & 0xff];
                }
            }

            // 若 pivot 行不是单位行，则对其余行消元
            idRow[icol] = 1;
            if (!pivotRowEqualsIdRow(matrix, pivotBase, idRow, k)) {
                for (int rowBase = 0, rowIdx = 0; rowIdx < k; rowIdx++, rowBase += k) {
                    if (rowIdx != icol) {
                        int cc = matrix[rowBase + icol] & 0xff;
                        matrix[rowBase + icol] = 0;
                        GaloisField.addmul(matrix, rowBase, matrix, pivotBase, cc, k);
                    }
                }
            }
            idRow[icol] = 0;
        }

        // 还原列交换
        for (int i = 0; i < k; i++) {
            if (indxr[i] != indxc[i]) {
                for (int row = 0; row < k; row++) {
                    swap(matrix, row * k + indxr[i], row * k + indxc[i]);
                }
            }
        }
    }

    /**
     * 判断 pivot 行是否等于单位行（idRow），用于消元分支判断。
     */
    private static boolean pivotRowEqualsIdRow(byte[] matrix, int pivotBase, byte[] idRow, int k) {
        for (int i = 0; i < k; i++) {
            if (matrix[pivotBase + i] != idRow[i]) {
                return false;
            }
        }
        return true;
    }

    /**
     * 构造逆 Vandermonde 矩阵（K×K，行主序结果写入 vdm）。
     * 矩阵第 (i,j) 元素为 1/(α_i - α_j) 的展开式，α_i = 2^i 为生成元的幂。
     *
     * @param vdm 输出矩阵（K×K 行主序）
     * @param k   矩阵维度
     */
    static void createInvertedVdm(byte[] vdm, int k) {
        if (k == 1) {
            vdm[0] = 1;
            return;
        }

        byte[] b = new byte[k];
        byte[] c = new byte[k];

        // 计算辅助多项式的系数 c
        c[k - 1] = 0;
        for (int i = 1; i < k; i++) {
            int[] mulPi = GaloisField.GF_MUL_TABLE[GaloisField.GF_EXP[i]];
            for (int j = k - 1 - (i - 1); j < k - 1; j++) {
                c[j] ^= (byte) mulPi[c[j + 1] & 0xff];
            }
            c[k - 1] ^= (byte) GaloisField.GF_EXP[i];
        }

        // 逐行填充逆 Vandermonde 矩阵
        for (int row = 0; row < k; row++) {
            int index = 0;
            if (row != 0) {
                index = GaloisField.GF_EXP[row];
            }
            int[] mulPRow = GaloisField.GF_MUL_TABLE[index];

            int t = 1;
            b[k - 1] = 1;
            for (int i = k - 2; i >= 0; i--) {
                b[i] = (byte) ((c[i + 1] & 0xff) ^ mulPRow[b[i + 1] & 0xff]);
                t = (b[i] & 0xff) ^ mulPRow[t];
            }

            int[] mulTInv = GaloisField.GF_MUL_TABLE[GaloisField.GF_INVERSE[t]];
            for (int col = 0; col < k; col++) {
                vdm[col * k + row] = (byte) mulTInv[b[col] & 0xff];
            }
        }
    }

    /**
     * 拷贝矩阵（调试用），避免原地修改影响调用方。
     */
    static byte[] copy(byte[] m) {
        return Arrays.copyOf(m, m.length);
    }

    /**
     * pivot 搜索器，在 Gauss-Jordan 消元中按序查找可用主元。
     * 每次找到的主元位置会被标记为已使用，保证同一行/列不重复选取。
     */
    private static final class PivotSearcher {

        /**
         * 矩阵维度。
         */
        private final int k;

        /**
         * 标记某行/列是否已被选为主元。
         */
        private final boolean[] ipiv;

        /**
         * @param k 矩阵维度
         */
        PivotSearcher(int k) {
            this.k = k;
            this.ipiv = new boolean[k];
        }

        /**
         * 搜索第 col 列可用的主元。
         * 优先使用对角线元素；若不可用则扫描未使用的行找到第一个非零元素。
         *
         * @param col    当前消元列
         * @param matrix K×K 矩阵（行主序）
         * @return {@code [icol, irow]}，即主元的列号和行号
         * @throws ArithmeticException 若找不到任何可用主元
         */
        int[] search(int col, byte[] matrix) {
            if (!ipiv[col] && matrix[col * k + col] != 0) {
                ipiv[col] = true;
                return new int[]{col, col};
            }
            for (int row = 0; row < k; row++) {
                if (ipiv[row]) {
                    continue;
                }
                for (int i = 0; i < k; i++) {
                    if (!ipiv[i] && matrix[row * k + i] != 0) {
                        ipiv[i] = true;
                        return new int[]{i, row};
                    }
                }
            }
            throw new ArithmeticException("pivot not found");
        }
    }
}
