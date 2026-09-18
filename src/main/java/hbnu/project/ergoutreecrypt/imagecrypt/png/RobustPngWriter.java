package hbnu.project.ergoutreecrypt.imagecrypt.png;

import hbnu.project.ergoutreecrypt.exception.ErrorKind;
import hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptException;
import hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptProtocol;
import hbnu.project.ergoutreecrypt.imagecrypt.robust.RobustCarrier;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Objects;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;

/**
 * 把 RS 交织字节写成 8 阶灰度 RGB8 PNG。
 *
 * <p>编码位流每 3 bit 对应一个灰度像素；重建值位于 32 宽量化区间的中心。PNG 本身
 * 保持无损，聊天软件转为 JPEG 后可按亮度区间重新判决。
 *
 * @author ErgouTree
 * @since 2026/9/17
 */
public final class RobustPngWriter {

    /** 单个 IDAT 块的最大数据量。 */
    private static final int IDAT_CHUNK_BYTES = 1 << 20;

    /** sRGB 感知渲染意图。 */
    private static final byte SRGB_RENDERING_INTENT = 0;

    /**
     * 流式写出抗重编码 PNG。
     *
     * @param output PNG 输出；本方法不关闭
     * @param width 画布宽度
     * @param height 画布高度
     * @param logical 逻辑协议帧；本方法不关闭
     * @param logicalLength 逻辑帧精确长度
     * @throws IOException 底层读写失败
     * @throws ImageCryptException 画布容量不足或输入长度非法
     */
    public void write(final OutputStream output, final int width, final int height,
                      final InputStream logical, final long logicalLength)
            throws IOException, ImageCryptException {
        Objects.requireNonNull(output, "output");
        Objects.requireNonNull(logical, "logical");
        validate(width, height, logicalLength);

        PngChunkWriter chunks = new PngChunkWriter(output);
        chunks.writeSignature();
        chunks.writeChunk("IHDR", createIhdr(width, height));
        chunks.writeChunk("sRGB", new byte[]{SRGB_RENDERING_INTENT});

        ChunkedIdatOutputStream idat = new ChunkedIdatOutputStream(chunks);
        Deflater deflater = new Deflater(Deflater.BEST_SPEED);
        try {
            DeflaterOutputStream zlib = new DeflaterOutputStream(idat, deflater, 64 * 1024);
            writePixels(zlib, width, height, logical, logicalLength);
            zlib.finish();
            idat.finish();
        } finally {
            deflater.end();
        }
        chunks.writeChunk("IEND", new byte[0]);
        chunks.flush();
    }

    /**
     * 校验画布和逻辑长度。
     *
     * @param width 宽度
     * @param height 高度
     * @param logicalLength 逻辑长度
     * @throws ImageCryptException 参数非法
     */
    private static void validate(final int width, final int height, final long logicalLength)
            throws ImageCryptException {
        if (width <= 0 || height <= 0 || width > RobustCarrier.MAX_CANVAS_SIDE
                || height > RobustCarrier.MAX_CANVAS_SIDE) {
            throw new ImageCryptException(ErrorKind.INVALID_HEADER,
                    "抗重编码画布尺寸越界: " + width + "×" + height);
        }
        long required = RobustCarrier.groupsFor(logicalLength) * RobustCarrier.GROUP_PIXELS;
        if ((long) width * height < required) {
            throw new ImageCryptException(ErrorKind.CAPACITY_INSUFFICIENT,
                    "抗重编码画布像素不足: 需要 " + required);
        }
    }

    /**
     * 创建标准 RGB8 IHDR。
     *
     * @param width 宽度
     * @param height 高度
     * @return 13 字节 IHDR
     */
    private static byte[] createIhdr(final int width, final int height) {
        return ByteBuffer.allocate(ImageCryptProtocol.PNG_IHDR_LENGTH)
                .order(ByteOrder.BIG_ENDIAN)
                .putInt(width)
                .putInt(height)
                .put((byte) ImageCryptProtocol.PNG_BIT_DEPTH)
                .put((byte) ImageCryptProtocol.PNG_COLOR_TYPE_RGB)
                .put((byte) ImageCryptProtocol.PNG_COMPRESSION_METHOD)
                .put((byte) ImageCryptProtocol.PNG_FILTER_METHOD)
                .put((byte) ImageCryptProtocol.PNG_INTERLACE_NONE)
                .array();
    }

    /**
     * 写出全部灰度像素和固定中灰 padding。
     *
     * @param zlib zlib 输出
     * @param width 宽度
     * @param height 高度
     * @param logical 逻辑帧
     * @param logicalLength 逻辑长度
     * @throws IOException 读写失败
     */
    private static void writePixels(final OutputStream zlib, final int width, final int height,
                                    final InputStream logical, final long logicalLength)
            throws IOException {
        try (InputStream encoded = RobustCarrier.encodingStream(logical, logicalLength)) {
            int bitBuffer = 0;
            int bitCount = 0;
            boolean exhausted = false;
            byte[] row = new byte[width * 3];
            for (int y = 0; y < height; y++) {
                int offset = 0;
                for (int x = 0; x < width; x++) {
                    int level = 128;
                    while (!exhausted && bitCount < 3) {
                        int value = encoded.read();
                        if (value < 0) {
                            exhausted = true;
                        } else {
                            bitBuffer = (bitBuffer << 8) | value;
                            bitCount += 8;
                        }
                    }
                    if (bitCount >= 3) {
                        bitCount -= 3;
                        int symbol = (bitBuffer >>> bitCount) & 0x07;
                        bitBuffer = bitCount == 0 ? 0 : bitBuffer & ((1 << bitCount) - 1);
                        level = symbol * 32 + 16;
                    }
                    row[offset++] = (byte) level;
                    row[offset++] = (byte) level;
                    row[offset++] = (byte) level;
                }
                zlib.write(PngFilters.NONE);
                zlib.write(row);
            }
            if (bitCount != 0 || !exhausted && encoded.read() >= 0) {
                throw new IOException("抗重编码画布未消费完整编码流");
            }
        }
    }

    /**
     * 把连续 zlib 数据切成有限大小的 IDAT 块。
     *
     * @author ErgouTree
     * @since 2026/9/17
     */
    private static final class ChunkedIdatOutputStream extends OutputStream {

        /** PNG 块 writer。 */
        private final PngChunkWriter chunks;

        /** IDAT 缓冲。 */
        private final byte[] buffer = new byte[IDAT_CHUNK_BYTES];

        /** 当前有效字节数。 */
        private int count;

        /** 是否已经结束。 */
        private boolean finished;

        /**
         * 创建 IDAT 输出。
         *
         * @param chunks PNG 块 writer
         */
        private ChunkedIdatOutputStream(final PngChunkWriter chunks) {
            this.chunks = chunks;
        }

        /**
         * 写一个字节。
         *
         * @param value 字节值
         * @throws IOException 写入失败
         */
        @Override
        public void write(final int value) throws IOException {
            ensureOpen();
            if (count == buffer.length) {
                emit();
            }
            buffer[count++] = (byte) value;
        }

        /**
         * 写入数组片段。
         *
         * @param data 数据
         * @param offset 起始偏移
         * @param length 长度
         * @throws IOException 写入失败
         */
        @Override
        public void write(final byte[] data, final int offset, final int length)
                throws IOException {
            Objects.checkFromIndexSize(offset, length, data.length);
            ensureOpen();
            int cursor = offset;
            int remaining = length;
            while (remaining > 0) {
                if (count == buffer.length) {
                    emit();
                }
                int copied = Math.min(remaining, buffer.length - count);
                System.arraycopy(data, cursor, buffer, count, copied);
                cursor += copied;
                count += copied;
                remaining -= copied;
            }
        }

        /**
         * 写出最后一个块。
         *
         * @throws IOException 写入失败
         */
        private void finish() throws IOException {
            if (!finished && count > 0) {
                emit();
            }
            finished = true;
        }

        /**
         * 写出当前缓冲。
         *
         * @throws IOException 写入失败
         */
        private void emit() throws IOException {
            chunks.writeChunk("IDAT", buffer, 0, count);
            count = 0;
        }

        /**
         * 拒绝结束后的写入。
         *
         * @throws IOException 流已结束
         */
        private void ensureOpen() throws IOException {
            if (finished) {
                throw new IOException("IDAT 输出已经结束");
            }
        }
    }
}
