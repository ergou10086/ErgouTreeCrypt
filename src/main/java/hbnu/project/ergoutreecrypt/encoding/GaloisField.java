package hbnu.project.ergoutreecrypt.encoding;

/**
 * GF(2^8) 伽罗瓦域算术表与基础运算。
 *
 * <p>使用本原多项式 {@code 0x11d}（x^8+x^4+x^3+x^2+1），生成元为 2，供 Reed-Solomon 编解码与 Berlekamp-Welch 纠错使用。
 * 所有表在类加载时通过算法计算生成，而非硬编码常量，以降低抄写错误风险。
 *
 * <p>关键表结构：
 * <ul>
 *   <li>{@code gfExp} 长度 510（两个 255 周期），便于 {@code (logI+logJ)} 不取模直接索引；</li>
 *   <li>{@code gfMulTable[0][i] == gfMulTable[i][0] == 0}，含零乘积强制为零；</li>
 *   <li>{@code gfLog[0] == 0xFF}，作为零无对数的占位值。</li>
 * </ul>
 *
 * @author ErgouTree
 */
public final class GaloisField {

    /**
     * 指数表（长度 510，两个 255 周期），{@code gfExp[i] = 2^i mod poly}。
     */
    public static final int[] GF_EXP = new int[510];

    /**
     * 对数表（长度 256），{@code gfLog[gfExp[i]] = i}，{@code gfLog[0] = 0xFF} 表示零无对数。
     */
    public static final int[] GF_LOG = new int[256];

    /**
     * 乘法逆元表（长度 256），{@code gfInverse[a] = a^{-1} mod poly}，{@code gfInverse[0] = 0}。
     */
    public static final int[] GF_INVERSE = new int[256];

    /**
     * GF(2^8) 完整乘法表（256×256），{@code gfMulTable[a][b] = a * b mod poly}。
     * 行列均以 0..255 索引，查表免去每次 log/exp 转换开销。
     */
    public static final int[][] GF_MUL_TABLE = new int[256][256];

    /**
     * 约简多项式：本原多项式 0x11d 的低 8 位，用于域元素约简。
     */
    private static final int PRIMITIVE_POLY = 0x1d;

    static {
        // 以生成元 2 反复乘并按本原多项式约简，生成 gfExp / gfLog
        int x = 1;
        for (int i = 0; i < 255; i++) {
            GF_EXP[i] = x;
            GF_LOG[x] = i;
            x <<= 1;
            if ((x & 0x100) != 0) {
                x ^= 0x100 | PRIMITIVE_POLY;
            }
            x &= 0xff;
        }
        GF_LOG[0] = 0xFF;

        // 第二个周期，使 (logI + logJ) 可直接索引而无需取模
        for (int i = 255; i < 510; i++) {
            GF_EXP[i] = GF_EXP[i - 255];
        }

        // 通过 exp/log 构建完整乘法表
        for (int i = 0; i < 256; i++) {
            for (int j = 0; j < 256; j++) {
                int logI = GF_LOG[i];
                int logJ = GF_LOG[j];
                GF_MUL_TABLE[i][j] = GF_EXP[(logI + logJ) % 255];
            }
        }

        // 含零乘积强制为零
        for (int i = 0; i < 256; i++) {
            GF_MUL_TABLE[0][i] = 0;
            GF_MUL_TABLE[i][0] = 0;
        }

        // 逆元表：gfInverse[a] = gfExp[255 - gfLog[a]]（a ≠ 0）
        GF_INVERSE[0] = 0;
        for (int a = 1; a < 256; a++) {
            GF_INVERSE[a] = GF_EXP[255 - GF_LOG[a]];
        }
    }

    private GaloisField() {
    }

    /**
     * GF(2^8) 乘法，通过查表直接返回 a*b mod poly。
     *
     * @param a 乘数一（0..255）
     * @param b 乘数二（0..255）
     * @return 乘积（0..255）
     */
    public static int mul(int a, int b) {
        return GF_MUL_TABLE[a & 0xff][b & 0xff];
    }

    /**
     * 向量化 GF(2^8) 乘加运算：{@code z[zOff..] ^= y * x[xOff..]}（长度为 len）。
     * 这是矩阵乘法与 RS 编码的核心热点，y==0 时提前返回以避免无效运算。
     *
     * @param z    目标数组
     * @param zOff 目标数组起始偏移
     * @param x    源数组
     * @param xOff 源数组起始偏移
     * @param y    GF 标量乘数（0..255）
     * @param len  处理字节数
     */
    public static void addmul(byte[] z, int zOff, byte[] x, int xOff, int y, int len) {
        if (len == 0 || (y & 0xff) == 0) {
            return;
        }
        int[] mulY = GF_MUL_TABLE[y & 0xff];
        for (int i = 0; i < len; i++) {
            z[zOff + i] ^= (byte) mulY[x[xOff + i] & 0xff];
        }
    }
}
