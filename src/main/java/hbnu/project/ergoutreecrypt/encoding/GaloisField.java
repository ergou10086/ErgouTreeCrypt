package hbnu.project.ergoutreecrypt.encoding;

/**
 * GF(2^8) 域算术表
 *
 * <p>表的取值必须与 infectious 完全一致，否则无法解码既有 .pcv 卷的 Reed-Solomon 字段。infectious 使用本原多项式 0x11d（x^8+x^4+x^3+x^2+1），生成元为 2。
 *
 * <p>这里在类加载时按与 infectious 相同的算法<strong>计算</strong>各表，而非硬编码 1000+ 字节常量，从而降低抄写错误风险；构造完成后用已知首项断言（见单测）锁定正确性。
 *
 * <p>与 infectious 一致的细节：
 * <ul>
 *   <li>{@code gfExp} 长度 510（重复两遍 255 周期，便于 {@code (logI+logJ)} 不取模直接索引）；</li>
 *   <li>{@code gfMulTable[0][i] == gfMulTable[i][0] == 0}（与 init() 末尾的清零一致）；</li>
 *   <li>{@code gfLog[0] == 0xFF}（占位，0 无对数）。</li>
 * </ul>
 *
 * @author ErgouTree
 */
public final class GaloisField {

    /**
     * 指数表，长度 510（两个 255 周期）。{@code gfExp[i] = 2^i mod poly}。
     */
    public static final int[] GF_EXP = new int[510];

    /**
     * 对数表，长度 256。{@code gfLog[gfExp[i]] = i}；{@code gfLog[0] = 0xFF}。
     */
    public static final int[] GF_LOG = new int[256];

    /**
     * 乘法逆元表，长度 256。{@code gfInverse[a] = a^{-1}}；{@code gfInverse[0] = 0}。
     */
    public static final int[] GF_INVERSE = new int[256];

    /**
     * 乘法表 256x256。{@code gfMulTable[a][b] = a*b}（GF 乘法）。
     */
    public static final int[][] GF_MUL_TABLE = new int[256][256];

    /**
     * 本原多项式 0x11d 的低 8 位（约简多项式）。
     */
    private static final int PRIMITIVE_POLY = 0x1d;

    static {
        // 生成 gfExp / gfLog：以生成元 2 反复乘并按 0x11d 约简。
        int x = 1;
        for (int i = 0; i < 255; i++) {
            GF_EXP[i] = x;
            GF_LOG[x] = i;
            // x = x * 2 in GF(2^8)
            x <<= 1;
            if ((x & 0x100) != 0) {
                x ^= 0x100 | PRIMITIVE_POLY; // 减去本原多项式（含最高位）
            }
            x &= 0xff;
        }
        GF_LOG[0] = 0xFF; // 与 infectious 一致的占位
        // 第二个周期，便于 (logI + logJ) 直接索引而无需取模。
        for (int i = 255; i < 510; i++) {
            GF_EXP[i] = GF_EXP[i - 255];
        }

        // 乘法表：gfMulTable[i][j] = gfExp[(logI + logJ) % 255]
        for (int i = 0; i < 256; i++) {
            for (int j = 0; j < 256; j++) {
                int logI = GF_LOG[i];
                int logJ = GF_LOG[j];
                GF_MUL_TABLE[i][j] = GF_EXP[(logI + logJ) % 255];
            }
        }
        // 与 infectious 的 init() 末尾一致：含 0 的乘积强制为 0。
        for (int i = 0; i < 256; i++) {
            GF_MUL_TABLE[0][i] = 0;
            GF_MUL_TABLE[i][0] = 0;
        }

        // 逆元表：gfInverse[a] = gfExp[255 - gfLog[a]]，a != 0。
        GF_INVERSE[0] = 0;
        for (int a = 1; a < 256; a++) {
            GF_INVERSE[a] = GF_EXP[255 - GF_LOG[a]];
        }
    }

    private GaloisField() {
    }

    /**
     * GF 乘法。
     */
    public static int mul(int a, int b) {
        return GF_MUL_TABLE[a & 0xff][b & 0xff];
    }

    /**
     * {@code z[i] ^= y * x[i]}（GF 域），精确移植自 infectious 的 {@code addmul}（纯 Go 回退路径）。
     * 这是矩阵乘与 RS 编码的核心热点。
     */
    public static void addmul(byte[] z, int zOff, byte[] x, int xOff, int y, int len) {
        // y==0 时 GF 乘积恒为 0，z ^= 0 无效果，可直接跳过（与 infectious 语义一致）。
        if (len == 0 || (y & 0xff) == 0) {
            return;
        }
        int[] mulY = GF_MUL_TABLE[y & 0xff];
        for (int i = 0; i < len; i++) {
            z[zOff + i] ^= (byte) mulY[x[xOff + i] & 0xff];
        }
    }
}
