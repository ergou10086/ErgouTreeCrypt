package hbnu.project.ergoutreecrypt.stego;

/**
 * 隐写容量计算工具。
 *
 * <p>根据图像尺寸、通道数、LSB 深度与元数据头大小计算可嵌入的最大字节数。
 *
 * @author ErgouTree
 */
public final class StegoCapacity {

    private StegoCapacity() {
    }

    /**
     * 计算给定图像的可嵌入容量。
     *
     * @param width       图像宽度（像素）
     * @param height      图像高度（像素）
     * @param channels    每像素有效通道数（RGB=3, RGBA=3 跳过 alpha）
     * @param lsbDepth    LSB 深度（1–4）
     * @param headerBytes 元数据头字节数
     * @return 可嵌入的数据字节数（不含元数据头）
     */
    public static long availableBytes(final int width, final int height,
                                       final int channels, final int lsbDepth,
                                       final int headerBytes) {
        long totalPixels = (long) width * height;
        long totalChannels = totalPixels * channels;
        long totalBits = totalChannels * lsbDepth;
        long headerBits = (long) headerBytes * 8;
        if (totalBits <= headerBits) {
            return 0;
        }
        return (totalBits - headerBits) / 8;
    }

    /**
     * 计算嵌入指定字节数据所需的最小像素数。
     *
     * @param dataBytes   要嵌入的数据字节数
     * @param headerBytes 元数据头字节数
     * @param channels    每像素有效通道数
     * @param lsbDepth    LSB 深度
     * @return 所需的最小像素数
     */
    public static long requiredPixels(final long dataBytes, final int headerBytes,
                                       final int channels, final int lsbDepth) {
        long totalBitsNeeded = (dataBytes + headerBytes) * 8L;
        long bitsPerPixel = (long) channels * lsbDepth;
        return (totalBitsNeeded + bitsPerPixel - 1) / bitsPerPixel;
    }
}
