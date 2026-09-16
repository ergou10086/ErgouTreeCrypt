package hbnu.project.ergoutreecrypt.imagecrypt.png;

import hbnu.project.ergoutreecrypt.exception.ErrorKind;
import hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptException;

/**
 * PNG 扫描线过滤器 0–4 的反滤波实现。
 *
 * <p>方法按 PNG 规范使用模 256 字节运算，并原地把当前行从过滤值恢复为原始样本。
 * EGTC-IMG writer 固定写 filter 0，但 reader 必须接受 0–4，才能读取由标准无损 PNG 优化器重新选择过滤器后仍保持 RGB 样本不变的文件。
 *
 * @author ErgouTree
 * @since 2026/9/16
 */
public final class PngFilters {

    /**
     * PNG filter 类型 0：None。
     */
    public static final int NONE = 0;

    /**
     * PNG filter 类型 1：Sub。
     */
    public static final int SUB = 1;

    /**
     * PNG filter 类型 2：Up。
     */
    public static final int UP = 2;

    /**
     * PNG filter 类型 3：Average。
     */
    public static final int AVERAGE = 3;

    /**
     * PNG filter 类型 4：Paeth。
     */
    public static final int PAETH = 4;

    /**
     * 工具类不允许实例化。
     */
    private PngFilters() {
    }

    /**
     * 原地反滤波一条扫描线。
     *
     * @param filterType   PNG filter 类型 0–4
     * @param currentRow   当前行的过滤后字节；调用后变为原始样本
     * @param previousRow  上一行原始样本；首行可传 {@code null}
     * @param bytesPerPixel 每个像素的字节数；RGB8 为 3
     * @throws ImageCryptException filter 未知、行长度不一致或像素步长非法
     */
    public static void unfilter(final int filterType, final byte[] currentRow,
                                final byte[] previousRow, final int bytesPerPixel)
            throws ImageCryptException {
        if (currentRow == null) {
            throw invalid("PNG 当前扫描线不得为 null");
        }
        if (previousRow != null && previousRow.length != currentRow.length) {
            throw invalid("PNG 相邻扫描线长度不一致");
        }
        if (bytesPerPixel <= 0) {
            throw invalid("PNG bytesPerPixel 必须为正");
        }

        switch (filterType) {
            case NONE -> {
                return;
            }
            case SUB -> unfilterSub(currentRow, bytesPerPixel);
            case UP -> unfilterUp(currentRow, previousRow);
            case AVERAGE -> unfilterAverage(currentRow, previousRow, bytesPerPixel);
            case PAETH -> unfilterPaeth(currentRow, previousRow, bytesPerPixel);
            default -> throw invalid("不支持的 PNG filter 类型: " + filterType);
        }
    }

    /**
     * 反转 Sub 过滤器。
     *
     * @param row           当前行
     * @param bytesPerPixel 像素步长
     */
    private static void unfilterSub(final byte[] row, final int bytesPerPixel) {
        for (int i = bytesPerPixel; i < row.length; i++) {
            row[i] = (byte) ((row[i] & 0xff) + (row[i - bytesPerPixel] & 0xff));
        }
    }

    /**
     * 反转 Up 过滤器。
     *
     * @param row      当前行
     * @param previous 上一行；首行可为 {@code null}
     */
    private static void unfilterUp(final byte[] row, final byte[] previous) {
        if (previous == null) {
            return;
        }
        for (int i = 0; i < row.length; i++) {
            row[i] = (byte) ((row[i] & 0xff) + (previous[i] & 0xff));
        }
    }

    /**
     * 反转 Average 过滤器。
     *
     * @param row           当前行
     * @param previous      上一行；首行可为 {@code null}
     * @param bytesPerPixel 像素步长
     */
    private static void unfilterAverage(final byte[] row, final byte[] previous,
                                        final int bytesPerPixel) {
        for (int i = 0; i < row.length; i++) {
            int left = i >= bytesPerPixel ? row[i - bytesPerPixel] & 0xff : 0;
            int up = previous == null ? 0 : previous[i] & 0xff;
            row[i] = (byte) ((row[i] & 0xff) + ((left + up) >>> 1));
        }
    }

    /**
     * 反转 Paeth 过滤器。
     *
     * @param row           当前行
     * @param previous      上一行；首行可为 {@code null}
     * @param bytesPerPixel 像素步长
     */
    private static void unfilterPaeth(final byte[] row, final byte[] previous,
                                      final int bytesPerPixel) {
        for (int i = 0; i < row.length; i++) {
            int left = i >= bytesPerPixel ? row[i - bytesPerPixel] & 0xff : 0;
            int up = previous == null ? 0 : previous[i] & 0xff;
            int upperLeft = previous != null && i >= bytesPerPixel
                    ? previous[i - bytesPerPixel] & 0xff
                    : 0;
            row[i] = (byte) ((row[i] & 0xff) + paethPredictor(left, up, upperLeft));
        }
    }

    /**
     * 计算 PNG Paeth 预测值。
     *
     * @param left      左侧已恢复字节
     * @param up        上一行同列字节
     * @param upperLeft 左上字节
     * @return 三个候选中与线性预测最接近者
     */
    private static int paethPredictor(final int left, final int up, final int upperLeft) {
        int prediction = left + up - upperLeft;
        int leftDistance = Math.abs(prediction - left);
        int upDistance = Math.abs(prediction - up);
        int upperLeftDistance = Math.abs(prediction - upperLeft);
        if (leftDistance <= upDistance && leftDistance <= upperLeftDistance) {
            return left;
        }
        if (upDistance <= upperLeftDistance) {
            return up;
        }
        return upperLeft;
    }

    /**
     * 构造 PNG 过滤器错误。
     *
     * @param message 诊断消息
     * @return 分类为非法头的异常
     */
    private static ImageCryptException invalid(final String message) {
        return new ImageCryptException(ErrorKind.INVALID_HEADER, message);
    }
}
