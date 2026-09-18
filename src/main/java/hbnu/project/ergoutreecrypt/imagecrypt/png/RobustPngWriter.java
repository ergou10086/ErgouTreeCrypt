package hbnu.project.ergoutreecrypt.imagecrypt.png;

import hbnu.project.ergoutreecrypt.exception.ErrorKind;
import hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptException;
import hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptProtocol;
import hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptRobustness;
import hbnu.project.ergoutreecrypt.imagecrypt.robust.RobustCarrier;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.Objects;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;

/**
 * 把分级 Reed-Solomon 交织字节写成量化灰度 RGB8 PNG。
 *
 * <p>均衡、增强和极强档分别使用 8、4、2 个等距灰度级。每个重建值位于量化区间中心，
 * 为 JPEG 引入的亮度偏移保留最大判决余量；极强档还把每个符号复制到 2×2 像素块。
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
     * 按兼容的均衡档流式写出抗重编码 PNG。
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
        write(output, width, height, logical, logicalLength,
                ImageCryptRobustness.BALANCED);
    }

    /**
     * 按指定抗干扰强度流式写出抗重编码 PNG。
     *
     * @param output PNG 输出；本方法不关闭
     * @param width 画布宽度
     * @param height 画布高度
     * @param logical 逻辑协议帧；本方法不关闭
     * @param logicalLength 逻辑帧精确长度
     * @param profile 抗干扰强度
     * @throws IOException 底层读写失败
     * @throws ImageCryptException 画布容量不足或输入长度非法
     */
    public void write(final OutputStream output, final int width, final int height,
                      final InputStream logical, final long logicalLength,
                      final ImageCryptRobustness profile)
            throws IOException, ImageCryptException {
        Objects.requireNonNull(output, "output");
        Objects.requireNonNull(logical, "logical");
        validate(width, height, logicalLength, profile);

        PngChunkWriter chunks = new PngChunkWriter(output);
        chunks.writeSignature();
        chunks.writeChunk("IHDR", createIhdr(width, height));
        chunks.writeChunk("sRGB", new byte[]{SRGB_RENDERING_INTENT});

        ChunkedIdatOutputStream idat = new ChunkedIdatOutputStream(chunks);
        Deflater deflater = new Deflater(Deflater.BEST_SPEED);
        try {
            DeflaterOutputStream zlib = new DeflaterOutputStream(idat, deflater, 64 * 1024);
            writePixels(zlib, width, height, logical, logicalLength, profile);
            zlib.finish();
            idat.finish();
        } finally {
            deflater.end();
        }
        chunks.writeChunk("IEND", new byte[0]);
        chunks.flush();
    }

    /**
     * 校验画布、档位和逻辑长度。
     *
     * @param width 宽度
     * @param height 高度
     * @param logicalLength 逻辑长度
     * @param profile 抗干扰强度
     * @throws ImageCryptException 参数非法
     */
    private static void validate(final int width, final int height, final long logicalLength,
                                 final ImageCryptRobustness profile)
            throws ImageCryptException {
        if (profile == null || !profile.enabled()) {
            throw new ImageCryptException(ErrorKind.INVALID_HEADER,
                    "抗重编码 PNG 必须指定纠错强度");
        }
        if (width <= 0 || height <= 0 || width > RobustCarrier.MAX_CANVAS_SIDE
                || height > RobustCarrier.MAX_CANVAS_SIDE
                || width % profile.moduleSize() != 0
                || height % profile.moduleSize() != 0) {
            throw new ImageCryptException(ErrorKind.INVALID_HEADER,
                    "抗重编码画布尺寸越界或未按符号块对齐: " + width + "×" + height);
        }
        long required = RobustCarrier.groupsFor(logicalLength, profile)
                * RobustCarrier.symbolsPerGroup(profile);
        long capacity = (long) (width / profile.moduleSize())
                * (height / profile.moduleSize());
        if (capacity < required) {
            throw new ImageCryptException(ErrorKind.CAPACITY_INSUFFICIENT,
                    "抗重编码画布符号不足: 需要 " + required + "，实际 " + capacity);
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
     * 写出全部灰度符号块和固定中灰填充。
     *
     * @param zlib zlib 输出
     * @param width 画布宽度
     * @param height 画布高度
     * @param logical 逻辑帧
     * @param logicalLength 逻辑长度
     * @param profile 抗干扰强度
     * @throws IOException 读写失败
     */
    private static void writePixels(final OutputStream zlib, final int width, final int height,
                                    final InputStream logical, final long logicalLength,
                                    final ImageCryptRobustness profile)
            throws IOException {
        int moduleSize = profile.moduleSize();
        int moduleColumns = width / moduleSize;
        int moduleRows = height / moduleSize;
        int symbolBits = profile.bitsPerSymbol();
        int symbolMask = (1 << symbolBits) - 1;
        int quantizationShift = 8 - symbolBits;
        try (InputStream encoded = RobustCarrier.encodingStream(logical, logicalLength,
                profile)) {
            int bitBuffer = 0;
            int bitCount = 0;
            boolean exhausted = false;
            byte[] row = new byte[width * 3];
            for (int moduleY = 0; moduleY < moduleRows; moduleY++) {
                int offset = 0;
                for (int moduleX = 0; moduleX < moduleColumns; moduleX++) {
                    int level = 128;
                    while (!exhausted && bitCount < symbolBits) {
                        int value = encoded.read();
                        if (value < 0) {
                            exhausted = true;
                        } else {
                            bitBuffer = (bitBuffer << 8) | value;
                            bitCount += 8;
                        }
                    }
                    if (bitCount >= symbolBits) {
                        bitCount -= symbolBits;
                        int symbol = (bitBuffer >>> bitCount) & symbolMask;
                        bitBuffer = bitCount == 0 ? 0
                                : bitBuffer & ((1 << bitCount) - 1);
                        level = (symbol << quantizationShift)
                                + (1 << (quantizationShift - 1));
                    }
                    for (int repeatX = 0; repeatX < moduleSize; repeatX++) {
                        row[offset++] = (byte) level;
                        row[offset++] = (byte) level;
                        row[offset++] = (byte) level;
                    }
                }
                for (int repeatY = 0; repeatY < moduleSize; repeatY++) {
                    zlib.write(PngFilters.NONE);
                    zlib.write(row);
                }
                Arrays.fill(row, (byte) 0);
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

        /** PNG 块写入器。 */
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
         * @param chunks PNG 块写入器
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
