package hbnu.project.ergoutreecrypt.encoding;

import java.util.Arrays;

/**
 * FEC 矩阵运算，精确移植自 infectious 的 {@code math.go}。
 *
 * <p>包含 {@code invertMatrix}（高斯消元求逆）与 {@code createInvertedVdm}（构造逆 Vandermonde 矩阵），供 {@link Fec#newFec} 与 {@link Fec#rebuild} 使用。
 *
 * <p>构造方式（行主序、pivot 搜索、约简顺序）必须与 infectious 一致，否则编码矩阵不同 → 校验字节不同 → 无法解码既有卷。
 *
 * @author ErgouTree
 */
final class FecMath {

    private FecMath() {
    }

    private static void swap(byte[] a, int i, int j) {
        byte t = a[i];
        a[i] = a[j];
        a[j] = t;
    }

    /**
     * 原地求逆 K*K 矩阵（行主序），对应 infectious 的 {@code invertMatrix}。
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

            if (irow != icol) {
                for (int i = 0; i < k; i++) {
                    swap(matrix, irow * k + i, icol * k + i);
                }
            }

            indxr[col] = irow;
            indxc[col] = icol;

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

            idRow[icol] = 1;
            // 若 pivot 行不是单位行，则对其余行消元。
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

        // 还原列交换。
        for (int i = 0; i < k; i++) {
            if (indxr[i] != indxc[i]) {
                for (int row = 0; row < k; row++) {
                    swap(matrix, row * k + indxr[i], row * k + indxc[i]);
                }
            }
        }
    }

    private static boolean pivotRowEqualsIdRow(byte[] matrix, int pivotBase, byte[] idRow, int k) {
        for (int i = 0; i < k; i++) {
            if (matrix[pivotBase + i] != idRow[i]) {
                return false;
            }
        }
        return true;
    }

    /**
     * 构造逆 Vandermonde 矩阵，对应 infectious 的 {@code createInvertedVdm}。
     */
    static void createInvertedVdm(byte[] vdm, int k) {
        if (k == 1) {
            vdm[0] = 1;
            return;
        }

        byte[] b = new byte[k];
        byte[] c = new byte[k];

        c[k - 1] = 0;
        for (int i = 1; i < k; i++) {
            int[] mulPi = GaloisField.GF_MUL_TABLE[GaloisField.GF_EXP[i]];
            for (int j = k - 1 - (i - 1); j < k - 1; j++) {
                c[j] ^= (byte) mulPi[c[j + 1] & 0xff];
            }
            c[k - 1] ^= (byte) GaloisField.GF_EXP[i];
        }

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
     * 调试用：拷贝矩阵（避免原地修改影响调用方）。
     */
    static byte[] copy(byte[] m) {
        return Arrays.copyOf(m, m.length);
    }

    /**
     * pivot 搜索器，对应 infectious 的 {@code pivotSearcher}。
     */
    private static final class PivotSearcher {
        private final int k;
        private final boolean[] ipiv;

        PivotSearcher(int k) {
            this.k = k;
            this.ipiv = new boolean[k];
        }

        /**
         * @return {@code [icol, irow]}；找不到则抛出异常。
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
