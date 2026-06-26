package hbnu.project.ergoutreecrypt.encoding;

import java.util.ArrayList;
import java.util.List;

/**
 * Reed-Solomon 前向纠错（FEC）编解码器。
 *
 * <p>支持将 k 个数据片编码为 n 个总片（k 个数据片 + (n-k) 个校验片），
 * 并可对含错误的片集进行 Berlekamp-Welch 纠错后重建原始数据。编码与解码均以 Share 为单位。
 *
 * @author ErgouTree
 */
public final class Fec {

    /**
     * 数据片数量。
     */
    private final int k;

    /**
     * 总片数量（数据片 + 校验片）。
     */
    private final int n;

    /**
     * 编码矩阵（n×k，行主序），用于从 k 个数据片生成 n 个编码片。
     */
    private final byte[] encMatrix;

    /**
     * Vandermonde 矩阵（k×n，行主序），用于构造校验矩阵以检测和纠正错误。
     */
    private final byte[] vandMatrix;

    /**
     * 私有构造，通过 {@link #newFec} 工厂方法创建。
     */
    private Fec(int k, int n, byte[] encMatrix, byte[] vandMatrix) {
        this.k = k;
        this.n = n;
        this.encMatrix = encMatrix;
        this.vandMatrix = vandMatrix;
    }

    /**
     * 构造 FEC 编解码器。
     *
     * <p>内部构造编码矩阵与 Vandermonde 矩阵。编码矩阵的前 k 行为单位阵（直接输出数据片），
     * 后 (n-k) 行为校验行（由逆 Vandermonde 矩阵与 Vandermonde 扩展部分相乘得到）。
     *
     * @param k 数据片数量，须满足 1 ≤ k ≤ n ≤ 256
     * @param n 总片数量
     * @return FEC 实例
     * @throws IllegalArgumentException 若参数不满足约束
     */
    public static Fec newFec(int k, int n) {
        if (k <= 0 || n <= 0 || k > 256 || n > 256 || k > n) {
            throw new IllegalArgumentException("requires 1 <= k <= n <= 256");
        }

        byte[] encMatrix = new byte[n * k];
        byte[] tempMatrix = new byte[n * k];
        FecMath.createInvertedVdm(tempMatrix, k);

        // 填充 tempMatrix 的扩展部分（Vandermonde 矩阵元素）
        for (int i = k * k; i < tempMatrix.length; i++) {
            tempMatrix[i] = (byte) GaloisField.GF_EXP[((i / k) * (i % k)) % 255];
        }

        // 编码矩阵前 k 行为单位阵
        for (int i = 0; i < k; i++) {
            encMatrix[i * (k + 1)] = 1;
        }

        // 倒置 Vandermonde 矩阵 × Vandermonde 扩展部分 = 编码矩阵校验行
        for (int row = k * k; row < n * k; row += k) {
            for (int col = 0; col < k; col++) {
                int acc = 0;
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

        // 构造 Vandermonde 矩阵（k 行 n 列），用于校验矩阵
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

    /**
     * 计算插值基点 power 在给定编号片处的取值。
     * num==0 返回 0；否则返回 interpBase^(num-1)。
     */
    private static int evalPoint(int interpBase, int num) {
        if (num == 0) {
            return 0;
        }
        return GfAlg.pow(interpBase, num - 1);
    }

    /**
     * 返回解码所需的最少片数（即 k）。
     */
    public int required() {
        return k;
    }

    /**
     * 返回编码后的总片数（即 n）。
     */
    public int total() {
        return n;
    }

    /**
     * 将输入数据编码为 n 个 Share，逐个回调输出。
     *
     * <p>前 k 个 Share 为原始数据切片，后 (n-k) 个为校验片。
     * 输入长度须为 k 的整数倍，每片长度为 input.length/k。
     *
     * @param input  原始数据（长度须为 k 的倍数）
     * @param output 每个 Share 的回调
     * @throws IllegalArgumentException 若输入长度不是 k 的倍数
     */
    public void encode(byte[] input, java.util.function.Consumer<Share> output) {
        int size = input.length;
        if (size % k != 0) {
            throw new IllegalArgumentException("input length must be a multiple of " + k);
        }
        int blockSize = size / k;

        // 输出 k 个数据片
        for (int i = 0; i < k; i++) {
            byte[] piece = new byte[blockSize];
            System.arraycopy(input, i * blockSize, piece, 0, blockSize);
            output.accept(new Share(i, piece));
        }

        // 生成 (n-k) 个校验片：每片 = Σ data[j] * encMatrix[i][j]
        for (int i = k; i < n; i++) {
            byte[] fecBuf = new byte[blockSize];
            for (int j = 0; j < k; j++) {
                GaloisField.addmul(fecBuf, 0, input, j * blockSize, encMatrix[i * k + j] & 0xff, blockSize);
            }
            output.accept(new Share(i, fecBuf));
        }
    }

    /**
     * 从至少 k 个 Share 重建原始数据（假设已纠错或无需纠错）。
     *
     * <p>对输入的 shares 排序后优先使用编号靠前和靠后的片，处理完毕后通过 {@code output} 回调 k 次输出重建的数据片。
     *
     * @param shares 至少 k 个 Share
     * @param output 重建后的每个 Share 回调（顺序不一定按片号）
     * @throws IllegalStateException 若 shares 数量不足 k 或包含无效编号
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

        // 优先选取编号匹配的 Share：匹配到在前的数据片则直接输出，否则取尾部的校验片
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
                // 数据片：解码矩阵对应行为单位行
                mDec[i * (k + 1)] = 1;
                if (output != null) {
                    output.accept(new Share(shareId, shareData));
                }
            } else {
                // 校验片：从编码矩阵取对应行
                System.arraycopy(encMatrix, shareId * k, mDec, i * k, k);
            }

            sharesv[i] = shareData;
            indexes[i] = shareId;
        }

        // 对解码矩阵求逆
        FecMath.invertMatrix(mDec, k);

        // 恢复缺失的数据片：data[i] = Σ share[col] * mDec[i][col]
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
     * 解码：先对 shares 纠错（{@link #correct}），再重建并拼接为原始数据。
     *
     * @param shares 至少 1 个 Share（可能含错误）
     * @return 长度为 k × pieceLen 的原始数据
     * @throws IllegalStateException 若 shares 为空
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

    // ==================== Berlekamp-Welch 纠错 ====================

    /**
     * 对 shares 进行 Berlekamp-Welch 纠错，原地修改每个 Share 的数据。
     * 先排序，再构造校验矩阵（syndrome），对每个出错的字节位置执行 BW 恢复。
     *
     * @param shares 至少 k 个 Share
     * @throws IllegalStateException 若 shares 数量不足 k
     */
    public void correct(List<Share> shares) {
        if (shares.size() < k) {
            throw new IllegalStateException("must specify at least the number of required shares");
        }
        shares.sort((a, b) -> Integer.compare(a.number, b.number));

        GfMat synd = syndromeMatrix(shares);
        byte[] buf = new byte[shares.get(0).data.length];

        // 遍历校验矩阵的每一行，找出并修复错误字节
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

    /**
     * 对 shares 在指定字节索引 index 处执行 Berlekamp-Welch 解码，返回整个编码空间的恢复数据。
     *
     * <p>步骤：
     * <ol>
     *   <li>构造 S 矩阵（q+e 维）与伴随矩阵 a；</li>
     *   <li>对 S 求逆并解算出中间向量 u；</li>
     *   <li>从 u 分离出 Q 多项式和 E 多项式，做多项式除法得到 P 多项式；</li>
     *   <li>对 P 多项式求值恢复所有字节。</li>
     * </ol>
     *
     * @param shares 已排序的 Share 列表
     * @param index  需要纠错的字节索引
     * @return 长度为 n 的恢复数据（每片对应一个字节）
     * @throws IllegalStateException 若错误过多无法纠正
     */
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

        // 填充 S 矩阵与 a 矩阵（单位阵），并计算 f 向量
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

        // 对 S 求逆并解 u = a · f
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

        // 从 u 分离 Q 多项式与 E 多项式
        int[] qPoly = java.util.Arrays.copyOfRange(u, e, u.length);
        int[] ePoly = new int[1 + e];
        ePoly[0] = 1;
        System.arraycopy(u, 0, ePoly, 1, e);

        // 多项式除法：P = Q / E（余数须为零）
        int[][] divRes = GfAlg.polyDiv(qPoly, ePoly);
        int[] pPoly = divRes[0];
        int[] rem = divRes[1];

        if (!GfAlg.polyIsZero(rem)) {
            throw new IllegalStateException("too many errors to correct");
        }

        // 对 P 多项式求值恢复所有字节
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

    /**
     * 根据当前 shares 构造校验矩阵（syndrome matrix）。
     * 从 Vandermonde 矩阵中选取 shares 对应的列，标准化后提取校验部分。
     *
     * @param shares 当前持有的 Share 列表
     * @return 校验矩阵
     */
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
     * 便捷方法：编码并收集全部 Share。
     */
    public List<Share> encodeAll(byte[] input) {
        List<Share> shares = new ArrayList<>(n);
        encode(input, shares::add);
        return shares;
    }

    /**
     * 一个数据片，包含片编号与该片的数据负载。
     */
    public static final class Share {

        /**
         * 片编号（0 起始）。
         */
        public int number;

        /**
         * 片数据负载。
         */
        public byte[] data;

        /**
         * @param number 片编号
         * @param data   数据负载
         */
        public Share(int number, byte[] data) {
            this.number = number;
            this.data = data;
        }

        /**
         * 深拷贝当前 Share（包括数据副本）。
         */
        public Share deepCopy() {
            return new Share(number, data == null ? null : data.clone());
        }
    }
}
