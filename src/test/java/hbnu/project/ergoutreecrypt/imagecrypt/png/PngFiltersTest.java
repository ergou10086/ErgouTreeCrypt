package hbnu.project.ergoutreecrypt.imagecrypt.png;

import hbnu.project.ergoutreecrypt.exception.ErrorKind;
import hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptException;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * {@link PngFilters} 的 PNG filter 0–4 规范向量测试。
 *
 * @author ErgouTree
 * @since 2026/9/16
 */
final class PngFiltersTest {

    /**
     * filter 0 必须保持样本不变。
     *
     * @throws Exception 反滤波失败
     */
    @Test
    void noneLeavesSamplesUntouched() throws Exception {
        byte[] row = bytes(15, 25, 35, 55, 65, 75);
        byte[] expected = row.clone();
        PngFilters.unfilter(PngFilters.NONE, row, bytes(10, 20, 30, 40, 50, 60), 3);
        assertArrayEquals(expected, row);
    }

    /**
     * filter 1 必须使用当前行已恢复的左侧样本。
     *
     * @throws Exception 反滤波失败
     */
    @Test
    void subUsesReconstructedLeftSample() throws Exception {
        byte[] row = bytes(15, 25, 35, 40, 40, 40);
        PngFilters.unfilter(PngFilters.SUB, row, null, 3);
        assertArrayEquals(bytes(15, 25, 35, 55, 65, 75), row);
    }

    /**
     * filter 2 必须叠加上一条已恢复扫描线。
     *
     * @throws Exception 反滤波失败
     */
    @Test
    void upUsesPreviousRow() throws Exception {
        byte[] row = bytes(5, 5, 5, 15, 15, 15);
        PngFilters.unfilter(PngFilters.UP, row, bytes(10, 20, 30, 40, 50, 60), 3);
        assertArrayEquals(bytes(15, 25, 35, 55, 65, 75), row);
    }

    /**
     * filter 3 必须向下取整计算 left/up 平均值。
     *
     * @throws Exception 反滤波失败
     */
    @Test
    void averageUsesFloorOfLeftAndUp() throws Exception {
        byte[] row = bytes(10, 15, 20, 28, 28, 28);
        PngFilters.unfilter(PngFilters.AVERAGE, row, bytes(10, 20, 30, 40, 50, 60), 3);
        assertArrayEquals(bytes(15, 25, 35, 55, 65, 75), row);
    }

    /**
     * filter 4 必须按 Paeth 的最小距离与规范平局顺序选择预测值。
     *
     * @throws Exception 反滤波失败
     */
    @Test
    void paethUsesNormativePredictor() throws Exception {
        byte[] row = bytes(40, 206, 30, 231, 80, 206);
        PngFilters.unfilter(PngFilters.PAETH, row, bytes(10, 90, 30, 80, 20, 70), 3);
        assertArrayEquals(bytes(50, 40, 60, 55, 100, 20), row);
    }

    /**
     * 未知 filter 类型必须映射为稳定的 INVALID_HEADER，而不是数组越界。
     */
    @Test
    void unknownFilterIsRejected() {
        ImageCryptException thrown = assertThrows(ImageCryptException.class,
                () -> PngFilters.unfilter(5, new byte[3], null, 3));
        assertEquals(ErrorKind.INVALID_HEADER, thrown.kind());
    }

    /**
     * 把 0–255 的测试数值转换为字节数组。
     *
     * @param values 无符号测试值
     * @return 字节数组
     */
    private static byte[] bytes(final int... values) {
        byte[] result = new byte[values.length];
        for (int i = 0; i < values.length; i++) {
            result[i] = (byte) values[i];
        }
        return result;
    }
}
