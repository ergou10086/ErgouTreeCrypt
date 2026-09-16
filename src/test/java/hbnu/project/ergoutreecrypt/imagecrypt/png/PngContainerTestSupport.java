package hbnu.project.ergoutreecrypt.imagecrypt.png;

import hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptProtocol;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;

/**
 * Phase 2 PNG 容器测试的字节级构造工具。
 *
 * <p>测试通过本工具生成带任意 filter、IDAT 分块和块次序的标准 PNG，避免依赖 ImageIO
 * writer 对过滤策略与分块位置的实现选择。
 *
 * @author ErgouTree
 * @since 2026/9/16
 */
final class PngContainerTestSupport {

    /**
     * 测试工具类不允许实例化。
     */
    private PngContainerTestSupport() {
    }

    /**
     * 构造 RGB8 非交错 IHDR。
     *
     * @param width  宽度
     * @param height 高度
     * @return 13 字节 IHDR 数据
     */
    static byte[] rgbIhdr(final int width, final int height) {
        return ihdr(width, height, ImageCryptProtocol.PNG_BIT_DEPTH,
                ImageCryptProtocol.PNG_COLOR_TYPE_RGB, ImageCryptProtocol.PNG_INTERLACE_NONE);
    }

    /**
     * 构造指定关键字段的 IHDR。
     *
     * @param width     宽度
     * @param height    高度
     * @param bitDepth  位深
     * @param colorType 颜色类型
     * @param interlace 隔行方法
     * @return 13 字节 IHDR 数据
     */
    static byte[] ihdr(final int width, final int height, final int bitDepth,
                       final int colorType, final int interlace) {
        return ByteBuffer.allocate(ImageCryptProtocol.PNG_IHDR_LENGTH)
                .order(ByteOrder.BIG_ENDIAN)
                .putInt(width)
                .putInt(height)
                .put((byte) bitDepth)
                .put((byte) colorType)
                .put((byte) ImageCryptProtocol.PNG_COMPRESSION_METHOD)
                .put((byte) ImageCryptProtocol.PNG_FILTER_METHOD)
                .put((byte) interlace)
                .array();
    }

    /**
     * 使用 zlib 封装一段扫描线字节。
     *
     * @param inflated 解压后的完整扫描线流
     * @return zlib 字节
     * @throws IOException 压缩失败
     */
    static byte[] zlib(final byte[] inflated) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        Deflater deflater = new Deflater(Deflater.NO_COMPRESSION);
        try {
            DeflaterOutputStream zlib = new DeflaterOutputStream(output, deflater);
            zlib.write(inflated);
            zlib.finish();
        } finally {
            deflater.end();
        }
        return output.toByteArray();
    }

    /**
     * 生成标准 IHDR、sRGB、连续 IDAT、IEND 容器。
     *
     * @param ihdrData     IHDR 数据
     * @param compressed   完整 zlib 字节
     * @param idatChunkSize 单个 IDAT 数据上限
     * @return PNG 文件字节
     * @throws IOException 写出失败
     */
    static byte[] standardPng(final byte[] ihdrData, final byte[] compressed,
                              final int idatChunkSize) throws IOException {
        List<ChunkSpec> chunks = new ArrayList<>();
        chunks.add(new ChunkSpec("IHDR", ihdrData));
        chunks.add(new ChunkSpec("sRGB", new byte[]{0}));
        int offset = 0;
        while (offset < compressed.length) {
            int count = Math.min(idatChunkSize, compressed.length - offset);
            byte[] part = new byte[count];
            System.arraycopy(compressed, offset, part, 0, count);
            chunks.add(new ChunkSpec("IDAT", part));
            offset += count;
        }
        chunks.add(new ChunkSpec("IEND", new byte[0]));
        return png(chunks.toArray(new ChunkSpec[0]));
    }

    /**
     * 按给定顺序组装 PNG 块。
     *
     * @param chunks 块序列
     * @return PNG 文件字节
     * @throws IOException 写出失败
     */
    static byte[] png(final ChunkSpec... chunks) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        PngChunkWriter writer = new PngChunkWriter(output);
        writer.writeSignature();
        for (ChunkSpec chunk : chunks) {
            writer.writeChunk(chunk.type, chunk.data);
        }
        return output.toByteArray();
    }

    /**
     * 把一行原始样本编码为指定 PNG filter 的差分字节。
     *
     * @param filterType   filter 0–4
     * @param raw          当前行原始样本
     * @param previous     上一行原始样本；首行可为 {@code null}
     * @param bytesPerPixel 像素步长
     * @return 过滤后的新数组
     */
    static byte[] filter(final int filterType, final byte[] raw,
                         final byte[] previous, final int bytesPerPixel) {
        byte[] filtered = new byte[raw.length];
        for (int i = 0; i < raw.length; i++) {
            int left = i >= bytesPerPixel ? raw[i - bytesPerPixel] & 0xff : 0;
            int up = previous == null ? 0 : previous[i] & 0xff;
            int upperLeft = previous != null && i >= bytesPerPixel
                    ? previous[i - bytesPerPixel] & 0xff
                    : 0;
            int predictor = switch (filterType) {
                case PngFilters.NONE -> 0;
                case PngFilters.SUB -> left;
                case PngFilters.UP -> up;
                case PngFilters.AVERAGE -> (left + up) >>> 1;
                case PngFilters.PAETH -> paeth(left, up, upperLeft);
                default -> throw new IllegalArgumentException("未知 filter: " + filterType);
            };
            filtered[i] = (byte) ((raw[i] & 0xff) - predictor);
        }
        return filtered;
    }

    /**
     * 定位 PNG 中每个块 CRC 的最后一个字节。
     *
     * @param png PNG 字节
     * @return CRC 尾字节偏移数组
     */
    static int[] chunkCrcLastOffsets(final byte[] png) {
        List<Integer> offsets = new ArrayList<>();
        int cursor = 8;
        while (cursor < png.length) {
            int length = ByteBuffer.wrap(png, cursor, 4).order(ByteOrder.BIG_ENDIAN).getInt();
            int crcLast = cursor + 4 + 4 + length + 4 - 1;
            offsets.add(crcLast);
            cursor = crcLast + 1;
        }
        return offsets.stream().mapToInt(Integer::intValue).toArray();
    }

    /**
     * 计算 Paeth 预测值，供测试 PNG 编码使用。
     *
     * @param left      左侧字节
     * @param up        上方字节
     * @param upperLeft 左上字节
     * @return 预测值
     */
    private static int paeth(final int left, final int up, final int upperLeft) {
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
     * 测试用 PNG 块描述。
     *
     * @author ErgouTree
     * @since 2026/9/16
     */
    static final class ChunkSpec {

        /**
         * 块类型。
         */
        private final String type;

        /**
         * 块数据。
         */
        private final byte[] data;

        /**
         * 创建测试块。
         *
         * @param type 块类型
         * @param data 块数据
         */
        ChunkSpec(final String type, final byte[] data) {
            this.type = type;
            this.data = data;
        }
    }
}
