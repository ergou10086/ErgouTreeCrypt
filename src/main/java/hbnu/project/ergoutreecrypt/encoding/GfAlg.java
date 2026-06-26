package hbnu.project.ergoutreecrypt.encoding;

/**
 * GF(2^8) 上的多项式与矩阵代数，精确移植自 infectious 的 {@code gf_alg.go}。
 *
 * <p>仅供 {@link Fec} 的 Berlekamp-Welch 纠错使用。用 {@code int[]}（每元素取值 0..255）
 * 表示 {@code gfVals}/{@code gfPoly}，用 {@link GfMat} 表示矩阵
 *
 * @author ErgouTree
 */
final class GfAlg {

    private GfAlg() {
    }

    // ---- 标量运算（gfVal）----

    static int pow(int b, int val) {
        int out = 1;
        int[] mulBase = GaloisField.GF_MUL_TABLE[b & 0xff];
        for (int i = 0; i < val; i++) {
            out = mulBase[out & 0xff];
        }
        return out;
    }

    static int mul(int a, int b) {
        return GaloisField.GF_MUL_TABLE[a & 0xff][b & 0xff];
    }

    static int div(int a, int b) {
        if (b == 0) {
            throw new ArithmeticException("divide by zero");
        }
        if (a == 0) {
            return 0;
        }
        // gf_exp[gf_log[a]-gf_log[b]]，差值可能为负，gf_exp 长 510 不够负索引，
        // 故按 mod 255 规范化（与 Go 的 gf_exp[ (la-lb) ] 在表足够长时等价）。
        int idx = GaloisField.GF_LOG[a & 0xff] - GaloisField.GF_LOG[b & 0xff];
        idx %= 255;
        if (idx < 0) {
            idx += 255;
        }
        return GaloisField.GF_EXP[idx];
    }

    static int add(int a, int b) {
        return (a ^ b) & 0xff;
    }

    static boolean isZero(int a) {
        return (a & 0xff) == 0;
    }

    static int inv(int a) {
        if (a == 0) {
            throw new ArithmeticException("invert zero");
        }
        return GaloisField.GF_EXP[255 - GaloisField.GF_LOG[a & 0xff]];
    }

    static int dot(int[] a, int[] b) {
        int out = 0;
        for (int i = 0; i < a.length; i++) {
            out = add(out, mul(a[i], b[i]));
        }
        return out;
    }

    // ---- 多项式（gfPoly，高位在前）----

    static int[] polyZero(int size) {
        return new int[size];
    }

    static boolean polyIsZero(int[] p) {
        for (int coef : p) {
            if (!isZero(coef)) {
                return false;
            }
        }
        return true;
    }

    static int polyDeg(int[] p) {
        return p.length - 1;
    }

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

    static int[] polyScale(int[] p, int factor) {
        int[] out = new int[p.length];
        for (int i = 0; i < p.length; i++) {
            out[i] = mul(p[i], factor);
        }
        return out;
    }

    static int[] polyAdd(int[] p, int[] b) {
        int size = Math.max(p.length, b.length);
        int[] out = new int[size];
        // 与 Go 一致：out.set(i, p.index(i) ^ b.index(i))，i 为幂次，high-first 存储。
        for (int i = 0; i < size; i++) {
            int pi = polyIndex(p, i);
            int bi = polyIndex(b, i);
            polySet(out, polyDeg(out), i, add(pi, bi));
        }
        return out;
    }

    /**
     * 由于 Java 数组定长，polySet 仅在 which>=0 时写入（调用方保证 out 足够大）。
     */
    private static void polySet(int[] poly, int deg, int pow, int coef) {
        int which = deg - pow;
        if (which >= 0 && which < poly.length) {
            poly[which] = coef;
        }
    }

    /**
     * 多项式除法，返回 {@code [q, r]}，对应 Go 的 {@code gfPoly.div}。
     * 输入 p、b 高位在前；内部会去除前导零。
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

        while (polyDeg(b) <= polyDeg(p)) {
            int leadingP = polyIndex(p, polyDeg(p));
            int leadingB = polyIndex(b, polyDeg(b));
            int coef = div(leadingP, leadingB);
            q.add(coef);

            int[] scaled = polyScale(b, coef);
            int[] padded = new int[polyDeg(p) + 1];
            // padded = scaled 后补零至 p 的次数（high-first：scaled 放高位）。
            System.arraycopy(scaled, 0, padded, 0, scaled.length);

            p = polyAdd(p, padded);
            if (!isZero(p[0])) {
                throw new ArithmeticException("alg error in poly div");
            }
            // p = p[1:]
            p = java.util.Arrays.copyOfRange(p, 1, p.length);
        }

        // 去除余数前导零（保留至少 1 个）
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
