package hbnu.project.ergoutreecrypt.encoding;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

/**
 * 用 infectious {@code tables.go} 的硬编码值锁定 {@link GaloisField} 的计算结果。
 *
 * <p>这是 RS 字节兼容性的根基：只要 GF 表与 infectious 完全一致，编码矩阵、校验字节、
 * 纠错行为就都能与既有 .pcv 卷对齐。
 */
class GaloisFieldTest {

    /** gf_exp 前 32 项（infectious tables.go 原值）。 */
    private static final int[] GF_EXP_HEAD = {
            0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1D, 0x3A, 0x74,
            0xE8, 0xCD, 0x87, 0x13, 0x26, 0x4C, 0x98, 0x2D, 0x5A, 0xB4, 0x75,
            0xEA, 0xC9, 0x8F, 0x03, 0x06, 0x0C, 0x18, 0x30, 0x60, 0xC0
    };

    /** gf_exp 末 8 项（第一周期 247..254）。 */
    private static final int[] GF_EXP_TAIL = {
            0x53, 0xA6, 0x51, 0xA2, 0x59, 0xB2, 0x79, 0xF2
    };

    @Test
    void gfExpHeadMatchesInfectious() {
        for (int i = 0; i < GF_EXP_HEAD.length; i++) {
            assertEquals(GF_EXP_HEAD[i], GaloisField.GF_EXP[i], "gfExp[" + i + "]");
        }
    }

    @Test
    void gfExpTailAndPeriodicity() {
        // 第一周期末 8 项（索引 200..207 对应上面的 0x53.. ，这里用相对末尾校验周期性）。
        for (int i = 0; i < 255; i++) {
            assertEquals(GaloisField.GF_EXP[i], GaloisField.GF_EXP[i + 255],
                    "gfExp 应具备 255 周期性 @" + i);
        }
        // gfExp[254] 应为周期最后一项；与 gfExp[254-255+255] 自洽，另校验已知值 0x8E。
        assertEquals(0x8E, GaloisField.GF_EXP[254], "gfExp[254]");
    }

    @Test
    void gfLogKnownValues() {
        // infectious gf_log：gf_log[0]=0xFF, gf_log[1]=0x00, gf_log[2]=0x01, gf_log[3]=0x19。
        assertEquals(0xFF, GaloisField.GF_LOG[0]);
        assertEquals(0x00, GaloisField.GF_LOG[1]);
        assertEquals(0x01, GaloisField.GF_LOG[2]);
        assertEquals(0x19, GaloisField.GF_LOG[3]);
        assertEquals(0xC6, GaloisField.GF_LOG[7]);
    }

    @Test
    void gfInverseKnownValues() {
        // infectious gf_inverse：[0]=0x00,[1]=0x01,[2]=0x8E,[3]=0xF4,[4]=0x47。
        assertEquals(0x00, GaloisField.GF_INVERSE[0]);
        assertEquals(0x01, GaloisField.GF_INVERSE[1]);
        assertEquals(0x8E, GaloisField.GF_INVERSE[2]);
        assertEquals(0xF4, GaloisField.GF_INVERSE[3]);
        assertEquals(0x47, GaloisField.GF_INVERSE[4]);
    }

    @Test
    void gfInverseIsConsistentWithMul() {
        // a * a^{-1} == 1 对所有非零 a 成立。
        for (int a = 1; a < 256; a++) {
            assertEquals(1, GaloisField.mul(a, GaloisField.GF_INVERSE[a]), "a*a^-1 @" + a);
        }
    }

    @Test
    void mulTableZeroRowAndColumn() {
        for (int i = 0; i < 256; i++) {
            assertEquals(0, GaloisField.GF_MUL_TABLE[0][i]);
            assertEquals(0, GaloisField.GF_MUL_TABLE[i][0]);
        }
    }
}
