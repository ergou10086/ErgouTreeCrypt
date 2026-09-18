package hbnu.project.ergoutreecrypt.imagecrypt.robust;

import java.util.Objects;

/**
 * 已解码图片的 8 位亮度平面。
 *
 * @param width 图片宽度
 * @param height 图片高度
 * @param luminance 按行存放的亮度样本
 * @author ErgouTree
 * @since 2026/9/17
 */
public record RobustRaster(int width, int height, byte[] luminance) {

    /**
     * 校验尺寸与样本数量。
     */
    public RobustRaster {
        Objects.requireNonNull(luminance, "luminance");
        if (width <= 0 || height <= 0 || (long) width * height != luminance.length) {
            throw new IllegalArgumentException("亮度平面尺寸与样本数量不一致");
        }
    }

    /**
     * 返回像素总数。
     *
     * @return 像素数量
     */
    public long pixelCount() {
        return (long) width * height;
    }

    /**
     * 返回指定线性位置的无符号亮度。
     *
     * @param index 线性像素位置
     * @return 0 至 255 的亮度值
     */
    public int luminanceAt(final long index) {
        return luminance[(int) index] & 0xff;
    }
}
