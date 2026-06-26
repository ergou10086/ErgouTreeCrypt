package hbnu.project.ergoutreecrypt.encoding;

import java.util.ArrayList;
import java.util.List;

/**
 * Reed-Solomon 前向纠错（FEC）
 *
 * <p>编码矩阵构造、Encode 输出、Rebuild/Decode（Berlekamp-Welch）必须与 infectious 字节一致，否则无法解码既有 .pcv 卷的 RS 字段。
 *
 * <p>用法对应 Picocrypt：{@code k} 个数据片、{@code n} 个总片（k 数据 + (n-k) 校验）。
 *
 * @author ErgouTree
 */
public final class Fec {

    private final int k;
    private final int n;
    private final byte[] encMatrix; // n*k，行主序
    private final byte[] vandMatrix; // k*n，行主序

    private Fec(int k, int n, byte[] encMatrix, byte[] vandMatrix) {
        this.k = k;
        this.n = n;
        this.encMatrix = encMatrix;
        this.vandMatrix = vandMatrix;
    }

    /**
     * 构造 FEC，对应 infectious 的 {@code NewFEC(k, n)}。
     */
    public static Fec newFec(int k, int n) {
        if (k <= 0 || n <= 0 || k > 256 || n > 256 || k > n) {
            throw new IllegalArgumentException("requires 1 <= k <= n <= 256");
        }

        byte[] encMatrix = new byte[n * k];
        byte[] tempMatrix = new byte[n * k];
        FecMath.createInvertedVdm(tempMatrix, k);

        for (int i = k * k; i < tempMatrix.length; i++) {
            tempMatrix[i] = (byte) GaloisField.GF_EXP[((i / k) * (i % k)) % 255];
        }

        for (int i = 0; i < k; i++) {
            encMatrix[i * (k + 1)] = 1;
        }

        for (int row = k * k; row < n * k; row += k) {
            for (int col = 0; col < k; col++) {
                int acc = 0;
                // pa = tempMatrix[row:], pb = tempMatrix[col:]，pb 步长 k。
                int paIdx = row;
                int pbIdx = col;
                for (int i = 0; i < k; i++) {
                    acc ^= GaloisField.GF_MUL_TABLE[tempMatrix[paIdx] & 0xff][tempMatrix[pbIdx] & 0xff];
                    paIdx += 1;
                    pbIdx += k;
                }
                encMatrix[row + col] = (byte) acc;
            }
        }

        // vand_matrix：k 行 n 列。
        byte[] vandMatrix = new byte[k * n];
        vandMatrix[0] = 1;
        int g = 1;
        for (int row = 0; row < k; row++) {
            int a = 1;
            for (int col = 1; col < n; col++) {
                vandMatrix[row * n + col] = (byte) a;
                a = GaloisField.GF_MUL_TABLE[g][a];
            }
            g = GaloisField.GF_MUL_TABLE[2][g];
        }

        return new Fec(k, n, encMatrix, vandMatrix);
    }

    private static int evalPoint(int interpBase, int num) {
        if (num == 0) {
            return 0;
        }
        return GfAlg.pow(interpBase, num - 1);
    }

    public int required() {
        return k;
    }

    public int total() {
        return n;
    }

    /**
     * 编码，对应 infectious 的 {@code Encode}。input 长度须为 k 的倍数。
     */
    public void encode(byte[] input, java.util.function.Consumer<Share> output) {
        int size = input.length;
        if (size % k != 0) {
            throw new IllegalArgumentException("input length must be a multiple of " + k);
        }
        int blockSize = size / k;

        for (int i = 0; i < k; i++) {
            byte[] piece = new byte[blockSize];
            System.arraycopy(input, i * blockSize, piece, 0, blockSize);
            output.accept(new Share(i, piece));
        }

        for (int i = k; i < n; i++) {
            byte[] fecBuf = new byte[blockSize];
            for (int j = 0; j < k; j++) {
                GaloisField.addmul(fecBuf, 0, input, j * blockSize, encMatrix[i * k + j] & 0xff, blockSize);
            }
            output.accept(new Share(i, fecBuf));
        }
    }

    /**
     * 重建原始 k 片数据（假设 shares 已纠错或无需纠错），对应 infectious 的 {@code Rebuild}。
     * output 会被回调 k 次（顺序不一定按片号）。
     */
    public void rebuild(List<Share> shares, java.util.function.Consumer<Share> output) {
        if (shares.size() < k) {
            throw new IllegalStateException("not enough shares");
        }

        int shareSize = shares.get(0).data.length;
        shares.sort((a, b) -> Integer.compare(a.number, b.number));

        byte[] mDec = new byte[k * k];
        int[] indexes = new int[k];
        byte[][] sharesv = new byte[k][];

        int bIter = 0;
        int eIter = shares.size() - 1;

        for (int i = 0; i < k; i++) {
            int shareId;
            byte[] shareData;
            Share head = shares.get(bIter);
            if (head.number == i) {
                shareId = head.number;
                shareData = head.data;
                bIter++;
            } else {
                Share tail = shares.get(eIter);
                shareId = tail.number;
                shareData = tail.data;
                eIter--;
            }

            if (shareId >= n) {
                throw new IllegalStateException("invalid share id: " + shareId);
            }

            if (shareId < k) {
                mDec[i * (k + 1)] = 1;
                if (output != null) {
                    output.accept(new Share(shareId, shareData));
                }
            } else {
                System.arraycopy(encMatrix, shareId * k, mDec, i * k, k);
            }

            sharesv[i] = shareData;
            indexes[i] = shareId;
        }

        FecMath.invertMatrix(mDec, k);

        for (int i = 0; i < indexes.length; i++) {
            if (indexes[i] >= k) {
                byte[] buf = new byte[shareSize];
                for (int col = 0; col < k; col++) {
                    GaloisField.addmul(buf, 0, sharesv[col], 0, mDec[i * k + col] & 0xff, shareSize);
                }
                if (output != null) {
                    output.accept(new Share(i, buf));
                }
            }
        }
    }

    /**
     * 解码：先纠错（{@link #correct}）再重建并拼接，对应 infectious 的 {@code Decode}。
     *
     * @return 长度 {@code k * pieceLen} 的原始数据
     */
    public byte[] decode(List<Share> shares) {
        correct(shares);
        if (shares.isEmpty()) {
            throw new IllegalStateException("must specify at least one share");
        }
        int pieceLen = shares.get(0).data.length;
        byte[] dst = new byte[pieceLen * k];
        rebuild(shares, s -> System.arraycopy(s.data, 0, dst, s.number * pieceLen, s.data.length));
        return dst;
    }

    // ---- Berlekamp-Welch 纠错（berlekamp_welch.go）----

    /**
     * 纠正 shares 中的错误（原地修改并排序），对应 infectious 的 {@code Correct}。
     */
    public void correct(List<Share> shares) {
        if (shares.size() < k) {
            throw new IllegalStateException("must specify at least the number of required shares");
        }
        shares.sort((a, b) -> Integer.compare(a.number, b.number));

        GfMat synd = syndromeMatrix(shares);
        byte[] buf = new byte[shares.get(0).data.length];

        for (int i = 0; i < synd.r; i++) {
            for (int j = 0; j < buf.length; j++) {
                buf[j] = 0;
            }
            for (int j = 0; j < synd.c; j++) {
                GaloisField.addmul(buf, 0, shares.get(j).data, 0, synd.get(i, j) & 0xff, buf.length);
            }
            for (int j = 0; j < buf.length; j++) {
                if (buf[j] == 0) {
                    continue;
                }
                byte[] data = berlekampWelch(shares, j);
                for (Share share : shares) {
                    share.data[j] = data[share.number];
                }
            }
        }
    }

    private byte[] berlekampWelch(List<Share> shares, int index) {
        int r = shares.size();
        int e = (r - k) / 2;
        int q = e + k;

        if (e <= 0) {
            throw new IllegalStateException("not enough shares");
        }

        final int interpBase = 2;

        int dim = q + e;
        GfMat s = new GfMat(dim, dim);
        GfMat a = new GfMat(dim, dim);
        int[] f = new int[dim];
        int[] u = new int[dim];

        for (int i = 0; i < dim; i++) {
            int xi = evalPoint(interpBase, shares.get(i).number);
            int ri = shares.get(i).data[index] & 0xff;

            f[i] = GfAlg.mul(GfAlg.pow(xi, e), ri);

            for (int j = 0; j < q; j++) {
                s.set(i, j, GfAlg.pow(xi, j));
                if (i == j) {
                    a.set(i, j, 1);
                }
            }
            for (int kk = 0; kk < e; kk++) {
                int j = kk + q;
                s.set(i, j, GfAlg.mul(GfAlg.pow(xi, kk), ri));
                if (i == j) {
                    a.set(i, j, 1);
                }
            }
        }

        s.invertWith(a);

        for (int i = 0; i < dim; i++) {
            u[i] = GfAlg.dot(a.rowCopy(i), f);
        }

        // 反转 u
        for (int i = 0; i < u.length / 2; i++) {
            int o = u.length - i - 1;
            int tmp = u[i];
            u[i] = u[o];
            u[o] = tmp;
        }

        int[] qPoly = java.util.Arrays.copyOfRange(u, e, u.length);
        int[] ePoly = new int[1 + e];
        ePoly[0] = 1;
        System.arraycopy(u, 0, ePoly, 1, e);

        int[][] divRes = GfAlg.polyDiv(qPoly, ePoly);
        int[] pPoly = divRes[0];
        int[] rem = divRes[1];

        if (!GfAlg.polyIsZero(rem)) {
            throw new IllegalStateException("too many errors to correct");
        }

        byte[] out = new byte[n];
        for (int i = 0; i < out.length; i++) {
            int pt = 0;
            if (i != 0) {
                pt = GfAlg.pow(interpBase, i - 1);
            }
            out[i] = (byte) GfAlg.polyEval(pPoly, pt);
        }
        return out;
    }

    private GfMat syndromeMatrix(List<Share> shares) {
        boolean[] keepers = new boolean[n];
        for (Share share : shares) {
            if (!keepers[share.number]) {
                keepers[share.number] = true;
            }
        }
        int shareCount = 0;
        for (boolean b : keepers) {
            if (b) {
                shareCount++;
            }
        }

        GfMat out = new GfMat(k, shareCount);
        for (int i = 0; i < k; i++) {
            int skipped = 0;
            for (int j = 0; j < n; j++) {
                if (!keepers[j]) {
                    skipped++;
                    continue;
                }
                out.set(i, j - skipped, vandMatrix[i * n + j] & 0xff);
            }
        }

        out.standardize();
        return out.parity();
    }

    /**
     * 便于测试：收集 encode 的所有 share。
     */
    public List<Share> encodeAll(byte[] input) {
        List<Share> shares = new ArrayList<>(n);
        encode(input, shares::add);
        return shares;
    }

    /**
     * 一个数据片，对应 infectious 的 {@code Share}。
     */
    public static final class Share {
        public int number;
        public byte[] data;

        public Share(int number, byte[] data) {
            this.number = number;
            this.data = data;
        }

        public Share deepCopy() {
            return new Share(number, data == null ? null : data.clone());
        }
    }
}
