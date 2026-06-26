package hbnu.project.ergoutreecrypt.encoding;

/**
 * GF(2^8) 上的多项式与矩阵代数运算。
 *
 * <p>用 {@code int[]}（每元素取值 0..255）表示标量与多项式，仅供 Berlekamp-Welch 纠错内部使用。
 *
 * @author ErgouTree
 */
final class GfAlg {

    private GfAlg() {
    }

    // ==================== 标量运算 ====================

    /**
     * GF(2^8) 幂运算：{@code b^val mod poly}。
     *
     * @param b   底数
     * @param val 指数
     * @return 幂值
     */
    static int pow(int b, int val) {
        int out = 1;
        int[] mulBase = GaloisField.GF_MUL_TABLE[b & 0xff];
        for (int i = 0; i < val; i++) {
            out = mulBase[out & 0xff];
        }
        return out;
    }

    /**
     * GF(2^8) 乘法，委托 {@link GaloisField#mul}。
     */
    static int mul(int a, int b) {
        return GaloisField.GF_MUL_TABLE[a & 0xff][b & 0xff];
    }

    /**
     * GF(2^8) 除法：{@code a / b mod poly}。b 为零时抛出异常。
     *
     * @param a 被除数
     * @param b 除数
     * @return 商
     * @throws ArithmeticException 若除数为零
     */
    static int div(int a, int b) {
        if (b == 0) {
            throw new ArithmeticException("divide by zero");
        }
        if (a == 0) {
            return 0;
        }
        int idx = GaloisField.GF_LOG[a & 0xff] - GaloisField.GF_LOG[b & 0xff];
        idx %= 255;
        if (idx < 0) {
            idx += 255;
        }
        return GaloisField.GF_EXP[idx];
    }

    /**
     * GF(2^8) 加法（即 XOR）。
     */
    static int add(int a, int b) {
        return (a ^ b) & 0xff;
    }

    /**
     * 判断 GF 元素是否为零。
     */
    static boolean isZero(int a) {
        return (a & 0xff) == 0;
    }

    /**
     * GF(2^8) 乘法逆元：{@code a^{-1} mod poly}。a 为零时抛出异常。
     *
     * @throws ArithmeticException 若对零求逆
     */
    static int inv(int a) {
        if (a == 0) {
            throw new ArithmeticException("invert zero");
        }
        return GaloisField.GF_EXP[255 - GaloisField.GF_LOG[a & 0xff]];
    }

    /**
     * 向量点积：{@code Σ(a[i] * b[i]) mod poly}。
     */
    static int dot(int[] a, int[] b) {
        int out = 0;
        for (int i = 0; i < a.length; i++) {
            out = add(out, mul(a[i], b[i]));
        }
        return out;
    }

    // ==================== 多项式运算（高位在前） ====================

    /**
     * 创建零多项式，长度为 size。
     */
    static int[] polyZero(int size) {
        return new int[size];
    }

    /**
     * 判断多项式是否全为零。
     */
    static boolean polyIsZero(int[] p) {
        for (int coef : p) {
            if (!isZero(coef)) {
                return false;
            }
        }
        return true;
    }

    /**
     * 返回多项式的次数（长度减一）。
     */
    static int polyDeg(int[] p) {
        return p.length - 1;
    }

    /**
     * 按幂次获取多项式系数，power 越界时返回 0。
     *
     * @param p     多项式（高位在前）
     * @param power 幂次（0 为常数项）
     * @return 对应系数
     */
    static int polyIndex(int[] p, int power) {
        if (power < 0) {
            return 0;
        }
        int which = polyDeg(p) - power;
        if (which < 0) {
            return 0;
        }
        return p[which];
    }

    /**
     * 多项式标量乘法：{@code factor * p}。
     */
    static int[] polyScale(int[] p, int factor) {
        int[] out = new int[p.length];
        for (int i = 0; i < p.length; i++) {
            out[i] = mul(p[i], factor);
        }
        return out;
    }

    /**
     * 多项式加法（GF 系数加法即 XOR），返回长度较大者的新多项式。
     */
    static int[] polyAdd(int[] p, int[] b) {
        int size = Math.max(p.length, b.length);
        int[] out = new int[size];
        for (int i = 0; i < size; i++) {
            int pi = polyIndex(p, i);
            int bi = polyIndex(b, i);
            polySet(out, polyDeg(out), i, add(pi, bi));
        }
        return out;
    }

    /**
     * 按幂次设置多项式系数。若索引越界则忽略。
     *
     * @param poly 多项式（高位在前，长度即次数+1）
     * @param deg  多项式的次数
     * @param pow  目标幂次
     * @param coef 系数值
     */
    private static void polySet(int[] poly, int deg, int pow, int coef) {
        int which = deg - pow;
        if (which >= 0 && which < poly.length) {
            poly[which] = coef;
        }
    }

    /**
     * 多项式除法，返回 {@code [商, 余数]}（高位在前）。
     * 内部自动去除输入的前导零。
     *
     * @param pIn 被除数（高位在前）
     * @param bIn 除数（高位在前）
     * @return 长度为 2 的数组：{@code [0]=商, [1]=余数}
     * @throws ArithmeticException 若除数为零
     */
    static int[][] polyDiv(int[] pIn, int[] bIn) {
        // 去除除数前导零
        int bStart = 0;
        while (bStart < bIn.length && isZero(bIn[bStart])) {
            bStart++;
        }
        if (bStart == bIn.length) {
            throw new ArithmeticException("divide by zero");
        }
        int[] b = java.util.Arrays.copyOfRange(bIn, bStart, bIn.length);

        // 去除被除数前导零
        int pStart = 0;
        while (pStart < pIn.length && isZero(pIn[pStart])) {
            pStart++;
        }
        if (pStart == pIn.length) {
            return new int[][]{polyZero(1), polyZero(1)};
        }
        int[] p = java.util.Arrays.copyOfRange(pIn, pStart, pIn.length);

        java.util.List<Integer> q = new java.util.ArrayList<>();

        // 长除法主循环
        while (polyDeg(b) <= polyDeg(p)) {
            int leadingP = polyIndex(p, polyDeg(p));
            int leadingB = polyIndex(b, polyDeg(b));
            int coef = div(leadingP, leadingB);
            q.add(coef);

            int[] scaled = polyScale(b, coef);
            int[] padded = new int[polyDeg(p) + 1];
            System.arraycopy(scaled, 0, padded, 0, scaled.length);

            p = polyAdd(p, padded);
            if (!isZero(p[0])) {
                throw new ArithmeticException("alg error in poly div");
            }
            p = java.util.Arrays.copyOfRange(p, 1, p.length);
        }

        // 去除余数前导零（至少保留 1 个元素）
        int rStart = 0;
        while (rStart < p.length - 1 && isZero(p[rStart])) {
            rStart++;
        }
        int[] r = java.util.Arrays.copyOfRange(p, rStart, p.length);

        int[] qArr = new int[q.size()];
        for (int i = 0; i < q.size(); i++) {
            qArr[i] = q.get(i);
        }
        if (qArr.length == 0) {
            qArr = polyZero(1);
        }
        return new int[][]{qArr, r};
    }

    /**
     * 多项式求值：代入 x 计算 p(x)。
     *
     * @param p 多项式（高位在前）
     * @param x 代入值
     * @return p(x)
     */
    static int polyEval(int[] p, int x) {
        int out = 0;
        for (int i = 0; i <= polyDeg(p); i++) {
            int xi = pow(x, i);
            int pi = polyIndex(p, i);
            out = add(out, mul(pi, xi));
        }
        return out;
    }
}
