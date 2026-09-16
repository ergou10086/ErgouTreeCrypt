package hbnu.project.ergoutreecrypt.imagecrypt.png;

import hbnu.project.ergoutreecrypt.exception.ErrorKind;
import hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptException;
import hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptProtocol;
import hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptRandomSource;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Objects;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;

/**
 * 把逻辑字节流映射为标准 RGB8 非交错 PNG。
 *
 * <p>每条扫描线写出 filter 0，随后按 R、G、B 顺序承载逻辑字节。
 * 逻辑数据结束后的画布空间由随机字节填充；padding 不属于调用方输入。
 * zlib 使用无压缩档，输出被固定大小缓冲切成连续 IDAT 块，因此工作内存不随图片高度或载荷长度增长。
 *
 * <p>本类不关闭输入流或输出流。调用方必须给出精确的逻辑长度，输入提前结束或包含额外
 * 字节都会失败，以防上层长度字段和实际帧发生分歧。
 *
 * @author ErgouTree
 * @since 2026/9/16
 */
public final class PixelPngWriter {

    /**
     * padding 随机池大小，避免对极短尾部调用带全零健全性检查的随机源。
     */
    private static final int PADDING_POOL_BYTES = 8192;

    /**
     * PNG sRGB rendering intent：Perceptual。
     */
    private static final byte SRGB_RENDERING_INTENT = 0;

    /**
     * 画布 padding 的随机来源。
     */
    private final ImageCryptRandomSource randomSource;

    /**
     * 单个 IDAT 块的数据上限。
     */
    private final int idatChunkSize;

    /**
     * 创建使用密码学安全随机 padding 与默认 1 MiB IDAT 分块的 writer。
     */
    public PixelPngWriter() {
        this(ImageCryptRandomSource.secure(), ImageCryptProtocol.PNG_IDAT_CHUNK_BYTES);
    }

    /**
     * 创建可注入随机源与分块大小的 writer。
     *
     * <p>该构造器保持包内可见，仅供同包测试生成可复现语料；生产门面只使用无参构造器。
     *
     * @param randomSource  padding 随机来源
     * @param idatChunkSize 单个 IDAT 块的数据上限
     */
    PixelPngWriter(final ImageCryptRandomSource randomSource, final int idatChunkSize) {
        this.randomSource = Objects.requireNonNull(randomSource, "randomSource");
        if (idatChunkSize <= 0) {
            throw new IllegalArgumentException("IDAT 分块大小必须为正");
        }
        this.idatChunkSize = idatChunkSize;
    }

    /**
     * 流式写出 RGB8 PNG。
     *
     * @param output        PNG 目标流；本方法不会关闭
     * @param canvasWidth   画布宽度，范围为 1–8192
     * @param canvasHeight  画布高度，范围为 1–8192
     * @param logicalInput  待映射的逻辑字节流；本方法不会关闭
     * @param logicalLength 逻辑字节精确长度
     * @throws IOException           底层读写失败
     * @throws ImageCryptException   画布非法、容量不足或输入长度不一致
     */
    public void write(final OutputStream output, final int canvasWidth, final int canvasHeight,
                      final InputStream logicalInput, final long logicalLength)
            throws IOException, ImageCryptException {
        Objects.requireNonNull(output, "output");
        Objects.requireNonNull(logicalInput, "logicalInput");
        validateGeometry(canvasWidth, canvasHeight, logicalLength);

        PngChunkWriter chunkWriter = new PngChunkWriter(output);
        chunkWriter.writeSignature();
        chunkWriter.writeChunk("IHDR", createIhdr(canvasWidth, canvasHeight));
        chunkWriter.writeChunk("sRGB", new byte[]{SRGB_RENDERING_INTENT});

        ChunkedIdatOutputStream idatOutput = new ChunkedIdatOutputStream(chunkWriter, idatChunkSize);
        Deflater deflater = new Deflater(Deflater.NO_COMPRESSION);
        try {
            DeflaterOutputStream zlibOutput = new DeflaterOutputStream(idatOutput, deflater, 64 * 1024);
            writeScanlines(zlibOutput, canvasWidth, canvasHeight, logicalInput, logicalLength);
            zlibOutput.finish();
            idatOutput.finish();
        } finally {
            deflater.end();
        }

        chunkWriter.writeChunk("IEND", new byte[0]);
        chunkWriter.flush();
    }

    /**
     * 校验画布边界、容量与逻辑长度。
     *
     * @param width         画布宽度
     * @param height        画布高度
     * @param logicalLength 逻辑长度
     * @throws ImageCryptException 参数不满足 v1 上限
     */
    private static void validateGeometry(final int width, final int height, final long logicalLength)
            throws ImageCryptException {
        if (!ImageCryptProtocol.isCanvasSideValid(width, height)) {
            throw new ImageCryptException(ErrorKind.INVALID_HEADER,
                    "PNG 画布尺寸越界: " + width + "x" + height);
        }
        if (logicalLength < 0) {
            throw new ImageCryptException(ErrorKind.INVALID_HEADER, "PNG 逻辑载荷长度不得为负");
        }
        long capacity = ImageCryptProtocol.canvasCapacity(width, height);
        if (logicalLength > capacity) {
            throw new ImageCryptException(ErrorKind.CAPACITY_INSUFFICIENT,
                    "PNG 画布容量不足: 需要 " + logicalLength + " 字节，容量为 " + capacity + " 字节");
        }
    }

    /**
     * 构造 v1 固定配置的 IHDR 数据。
     *
     * @param width  画布宽度
     * @param height 画布高度
     * @return 13 字节 IHDR 数据
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
     * 流式生成 filter 0 扫描线。
     *
     * @param zlibOutput    zlib 输出流
     * @param width         画布宽度
     * @param height        画布高度
     * @param logicalInput  逻辑输入
     * @param logicalLength 逻辑输入精确长度
     * @throws IOException         底层读写失败
     * @throws ImageCryptException 输入提前结束、包含额外字节或随机源返回非法长度
     */
    private void writeScanlines(final OutputStream zlibOutput, final int width, final int height,
                                final InputStream logicalInput, final long logicalLength)
            throws IOException, ImageCryptException {
        int rowBytes = Math.multiplyExact(width, ImageCryptProtocol.PNG_BYTES_PER_PIXEL);
        byte[] row = new byte[rowBytes];
        PaddingPool padding = new PaddingPool(randomSource);
        long remaining = logicalLength;

        for (int y = 0; y < height; y++) {
            int logicalInRow = (int) Math.min((long) rowBytes, remaining);
            readFully(logicalInput, row, 0, logicalInRow);
            remaining -= logicalInRow;
            if (logicalInRow < rowBytes) {
                padding.fill(row, logicalInRow, rowBytes - logicalInRow);
            }
            zlibOutput.write(PngFilters.NONE);
            zlibOutput.write(row, 0, row.length);
        }

        if (remaining != 0) {
            throw new ImageCryptException(ErrorKind.INTERNAL_ERROR,
                    "PNG 扫描线结束后仍有未消费的逻辑载荷: " + remaining);
        }
        if (logicalInput.read() >= 0) {
            throw new ImageCryptException(ErrorKind.INVALID_HEADER,
                    "PNG 逻辑输入包含超出声明长度的额外字节");
        }
    }

    /**
     * 从逻辑输入精确读取指定长度。
     *
     * @param input  输入流
     * @param target 目标数组
     * @param offset 起始偏移
     * @param length 读取长度
     * @throws IOException         底层读取失败
     * @throws ImageCryptException 输入提前结束
     */
    private static void readFully(final InputStream input, final byte[] target,
                                  final int offset, final int length)
            throws IOException, ImageCryptException {
        int cursor = offset;
        int end = offset + length;
        while (cursor < end) {
            int count = input.read(target, cursor, end - cursor);
            if (count < 0) {
                throw new ImageCryptException(ErrorKind.INVALID_HEADER,
                        "PNG 逻辑输入短于声明长度");
            }
            if (count > 0) {
                cursor += count;
            }
        }
    }

    /**
     * 固定大小的随机 padding 池。
     *
     * <p>生产随机源会把「全零返回」视为 RNG 故障。以 8 KiB 为单位取样既维持流式内存，
     * 也避免最后只缺 1 字节时出现 1/256 的无意义故障概率。
     *
     * @author ErgouTree
     * @since 2026/9/16
     */
    private static final class PaddingPool {

        /**
         * 随机来源。
         */
        private final ImageCryptRandomSource source;

        /**
         * 当前随机池。
         */
        private byte[] pool = new byte[0];

        /**
         * 当前读取位置。
         */
        private int cursor;

        /**
         * 创建 padding 池。
         *
         * @param source 随机来源
         */
        private PaddingPool(final ImageCryptRandomSource source) {
            this.source = source;
        }

        /**
         * 用随机字节填充目标数组区段。
         *
         * @param target 目标数组
         * @param offset 起始偏移
         * @param length 填充长度
         * @throws ImageCryptException 随机源返回 null 或错误长度
         */
        private void fill(final byte[] target, final int offset, final int length)
                throws ImageCryptException {
            int outputCursor = offset;
            int remaining = length;
            while (remaining > 0) {
                if (cursor == pool.length) {
                    pool = source.nextBytes(PADDING_POOL_BYTES);
                    cursor = 0;
                    if (pool == null || pool.length != PADDING_POOL_BYTES) {
                        throw new ImageCryptException(ErrorKind.INTERNAL_ERROR,
                                "图片 padding 随机源返回了错误长度");
                    }
                }
                int count = Math.min(remaining, pool.length - cursor);
                System.arraycopy(pool, cursor, target, outputCursor, count);
                cursor += count;
                outputCursor += count;
                remaining -= count;
            }
        }
    }

    /**
     * 把连续 zlib 字节切分成连续 IDAT 块的输出流。
     *
     * @author ErgouTree
     * @since 2026/9/16
     */
    private static final class ChunkedIdatOutputStream extends OutputStream {

        /**
         * PNG 块 writer。
         */
        private final PngChunkWriter chunkWriter;

        /**
         * 单块缓冲。
         */
        private final byte[] buffer;

        /**
         * 缓冲中的有效字节数。
         */
        private int count;

        /**
         * 是否已经完成最后一个 IDAT。
         */
        private boolean finished;

        /**
         * 创建 IDAT 分块流。
         *
         * @param chunkWriter PNG 块 writer
         * @param chunkSize   单块数据上限
         */
        private ChunkedIdatOutputStream(final PngChunkWriter chunkWriter, final int chunkSize) {
            this.chunkWriter = chunkWriter;
            this.buffer = new byte[chunkSize];
        }

        /**
         * 写入一个压缩字节。
         *
         * @param value 字节值
         * @throws IOException 底层输出失败
         */
        @Override
        public void write(final int value) throws IOException {
            ensureOpen();
            if (count == buffer.length) {
                emitChunk();
            }
            buffer[count++] = (byte) value;
        }

        /**
         * 写入一段压缩字节。
         *
         * @param source 源数组
         * @param offset 起始偏移
         * @param length 长度
         * @throws IOException 底层输出失败
         */
        @Override
        public void write(final byte[] source, final int offset, final int length) throws IOException {
            Objects.requireNonNull(source, "source");
            if (offset < 0 || length < 0 || offset > source.length - length) {
                throw new IndexOutOfBoundsException("IDAT 输出数组区段越界");
            }
            ensureOpen();
            int sourceCursor = offset;
            int remaining = length;
            while (remaining > 0) {
                if (count == buffer.length) {
                    emitChunk();
                }
                int copied = Math.min(remaining, buffer.length - count);
                System.arraycopy(source, sourceCursor, buffer, count, copied);
                count += copied;
                sourceCursor += copied;
                remaining -= copied;
            }
        }

        /**
         * 刷新底层输出流，不提前截断当前 IDAT 分块。
         *
         * @throws IOException 底层刷新失败
         */
        @Override
        public void flush() throws IOException {
            chunkWriter.flush();
        }

        /**
         * 写出最后一个非空 IDAT 块。
         *
         * @throws IOException 底层输出失败
         */
        private void finish() throws IOException {
            if (finished) {
                return;
            }
            if (count > 0) {
                emitChunk();
            }
            finished = true;
        }

        /**
         * 把当前缓冲写成一个 IDAT 块。
         *
         * @throws IOException 底层输出失败
         */
        private void emitChunk() throws IOException {
            chunkWriter.writeChunk("IDAT", buffer, 0, count);
            count = 0;
        }

        /**
         * 拒绝在完成后继续写入。
         *
         * @throws IOException 输出已经完成
         */
        private void ensureOpen() throws IOException {
            if (finished) {
                throw new IOException("IDAT 输出已经完成");
            }
        }
    }
}
