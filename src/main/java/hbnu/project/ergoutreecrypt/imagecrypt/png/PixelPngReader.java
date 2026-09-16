package hbnu.project.ergoutreecrypt.imagecrypt.png;

import hbnu.project.ergoutreecrypt.exception.ErrorKind;
import hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptException;
import hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptFrame;
import hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptProtocol;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Objects;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;
import java.util.zip.ZipException;

/**
 * 从标准 RGB8 非交错 PNG 中流式恢复逻辑字节。
 *
 * <p>reader 验证 PNG 签名、IHDR、所有块 CRC、关键块次序、IDAT 连续性、zlib 精确结束和
 * IEND 物理文件末尾。扫描线按 filter 0–4 反滤波，但只接受 EGTC-IMG v1 规定的 RGB8、
 * 非交错画布。维度在分配行缓冲前受 8192 单边上限约束，因此内存仅与单行及固定压缩缓冲有关。
 *
 * <p>{@link #readFrame(InputStream, OutputStream)} 先缓冲并校验 184 字节 OuterHeader，再按头中
 * 的 ciphertextLength 只向下游输出协议帧，padding 仍会被消费和校验但不会暴露给调用方。
 * 本类不关闭输入流或输出流。
 *
 * @author ErgouTree
 * @since 2026/9/16
 */
public final class PixelPngReader {

    /**
     * inflate 输入缓冲大小。
     */
    private static final int INFLATE_INPUT_BYTES = 64 * 1024;

    /**
     * 创建无状态的 PNG reader。
     */
    public PixelPngReader() {
    }

    /**
     * 从 PNG 样本中抽取调用方指定长度的逻辑前缀。
     *
     * <p>该入口用于容器边界测试和非帧级调用；即使只输出前缀，仍会反滤波全部扫描线并验证
     * zlib、全部块 CRC、IEND 和物理 EOF。
     *
     * @param input         PNG 输入流；本方法不会关闭
     * @param logicalOutput 逻辑字节目标流；本方法不会关闭
     * @param logicalLength 需要输出的逻辑前缀长度
     * @throws IOException           底层读写失败
     * @throws ImageCryptException   PNG 结构、CRC、zlib、过滤器或长度非法
     */
    public void read(final InputStream input, final OutputStream logicalOutput,
                     final long logicalLength) throws IOException, ImageCryptException {
        LogicalExtractor extractor = LogicalExtractor.fixed(logicalOutput, logicalLength);
        decode(input, extractor);
    }

    /**
     * 读取 EGTC-IMG 帧并丢弃认证载荷之后的随机 padding。
     *
     * @param input       PNG 输入流；本方法不会关闭
     * @param frameOutput 帧字节目标流；依次收到 header、ciphertext 与 AuthTag，本方法不会关闭
     * @return 已完成 CRC、字段与画布一致性校验的外层头
     * @throws IOException           底层读写失败
     * @throws ImageCryptException   PNG 或 EGTC-IMG 头非法、长度不自洽或载荷截断
     */
    public ImageCryptFrame readFrame(final InputStream input, final OutputStream frameOutput)
            throws IOException, ImageCryptException {
        LogicalExtractor extractor = LogicalExtractor.frame(frameOutput);
        decode(input, extractor);
        return extractor.frame();
    }

    /**
     * 执行共享的 PNG 解析、inflate、反滤波与末尾验证流程。
     *
     * @param input     PNG 输入流
     * @param extractor 逻辑样本接收器
     * @throws IOException         底层读写失败
     * @throws ImageCryptException PNG 或逻辑帧非法
     */
    private static void decode(final InputStream input, final LogicalExtractor extractor)
            throws IOException, ImageCryptException {
        Objects.requireNonNull(input, "input");
        PngChunkReader chunks = new PngChunkReader(input);
        chunks.readSignature();

        PngChunkReader.ChunkHeader ihdrHeader = chunks.nextChunk();
        if (ihdrHeader == null || !ihdrHeader.isType("IHDR")) {
            throw invalid("PNG 的第一个块必须是 IHDR");
        }
        int[] geometry = readIhdr(chunks, ihdrHeader);
        int width = geometry[0];
        int height = geometry[1];
        extractor.initialize(width, height);

        PngChunkReader.ChunkHeader firstIdat = findFirstIdat(chunks);
        IdatSequenceInputStream idatInput = new IdatSequenceInputStream(chunks, firstIdat);
        Inflater inflater = new Inflater();
        InflaterInputStream zlibInput = new InflaterInputStream(
                idatInput, inflater, INFLATE_INPUT_BYTES);
        try {
            readScanlines(zlibInput, extractor, width, height);
            requireExactZlibEnd(zlibInput, inflater, idatInput);
        } catch (PngStreamException e) {
            throw e.imageCause();
        } catch (EOFException | ZipException e) {
            throw new ImageCryptException(ErrorKind.INVALID_HEADER,
                    "PNG zlib 数据损坏或提前结束", e);
        } finally {
            inflater.end();
        }

        validateTail(chunks, idatInput.nextHeader());
        extractor.finish();
    }

    /**
     * 读取并校验 IHDR 的 v1 固定配置。
     *
     * @param chunks PNG 块 reader
     * @param header IHDR 块头
     * @return 二元素数组：宽度、高度
     * @throws IOException         底层读取失败
     * @throws ImageCryptException IHDR 长度、维度或格式配置非法
     */
    private static int[] readIhdr(final PngChunkReader chunks,
                                  final PngChunkReader.ChunkHeader header)
            throws IOException, ImageCryptException {
        if (header.length() != ImageCryptProtocol.PNG_IHDR_LENGTH) {
            throw invalid("PNG IHDR 长度必须为 " + ImageCryptProtocol.PNG_IHDR_LENGTH);
        }
        byte[] data = chunks.readChunkBytes(ImageCryptProtocol.PNG_IHDR_LENGTH);
        ByteBuffer buffer = ByteBuffer.wrap(data).order(ByteOrder.BIG_ENDIAN);
        long width = Integer.toUnsignedLong(buffer.getInt());
        long height = Integer.toUnsignedLong(buffer.getInt());
        int bitDepth = buffer.get() & 0xff;
        int colorType = buffer.get() & 0xff;
        int compressionMethod = buffer.get() & 0xff;
        int filterMethod = buffer.get() & 0xff;
        int interlaceMethod = buffer.get() & 0xff;

        if (width == 0 || height == 0
                || width > ImageCryptProtocol.LIMIT_CANVAS_SIDE
                || height > ImageCryptProtocol.LIMIT_CANVAS_SIDE) {
            throw invalid("PNG 画布尺寸越界: " + width + "x" + height);
        }
        if (bitDepth != ImageCryptProtocol.PNG_BIT_DEPTH
                || colorType != ImageCryptProtocol.PNG_COLOR_TYPE_RGB
                || compressionMethod != ImageCryptProtocol.PNG_COMPRESSION_METHOD
                || filterMethod != ImageCryptProtocol.PNG_FILTER_METHOD
                || interlaceMethod != ImageCryptProtocol.PNG_INTERLACE_NONE) {
            throw invalid("EGTC-IMG v1 只接受 RGB8、标准压缩/过滤方法、非交错 PNG");
        }
        return new int[]{(int) width, (int) height};
    }

    /**
     * 验证 IDAT 前的块序列并定位第一个 IDAT。
     *
     * <p>允许并验证 ancillary chunk，但拒绝未知关键块、重复 IHDR、提前 IEND 与重复 sRGB。
     *
     * @param chunks PNG 块 reader
     * @return 第一个 IDAT 块头
     * @throws IOException         底层读取失败
     * @throws ImageCryptException 块次序或内容非法
     */
    private static PngChunkReader.ChunkHeader findFirstIdat(final PngChunkReader chunks)
            throws IOException, ImageCryptException {
        boolean srgbSeen = false;
        while (true) {
            PngChunkReader.ChunkHeader header = chunks.nextChunk();
            if (header == null) {
                throw invalid("PNG 缺少 IDAT 和 IEND");
            }
            if (header.isType("IDAT")) {
                return header;
            }
            if (header.isType("IHDR")) {
                throw invalid("PNG 包含重复 IHDR");
            }
            if (header.isType("IEND")) {
                throw invalid("PNG 在 IDAT 前提前出现 IEND");
            }
            if (header.isType("sRGB")) {
                if (srgbSeen) {
                    throw invalid("PNG 包含重复 sRGB");
                }
                validateSrgb(chunks, header);
                srgbSeen = true;
                continue;
            }
            if (header.critical()) {
                throw invalid("EGTC-IMG PNG 不支持关键块: " + header.type());
            }
            chunks.skipChunk();
        }
    }

    /**
     * 校验 sRGB 块长度与 rendering intent。
     *
     * @param chunks PNG 块 reader
     * @param header sRGB 块头
     * @throws IOException         底层读取失败
     * @throws ImageCryptException sRGB 内容非法
     */
    private static void validateSrgb(final PngChunkReader chunks,
                                     final PngChunkReader.ChunkHeader header)
            throws IOException, ImageCryptException {
        if (header.length() != 1) {
            throw invalid("PNG sRGB 块长度必须为 1");
        }
        byte[] value = chunks.readChunkBytes(1);
        if ((value[0] & 0xff) > 3) {
            throw invalid("PNG sRGB rendering intent 非法: " + (value[0] & 0xff));
        }
    }

    /**
     * 逐行 inflate、反滤波并转交 RGB 样本。
     *
     * @param inflater  zlib 游标
     * @param extractor 逻辑样本接收器
     * @param width     画布宽度
     * @param height    画布高度
     * @throws IOException         底层读写失败
     * @throws ImageCryptException zlib 提前结束或过滤器非法
     */
    private static void readScanlines(final InputStream zlibInput,
                                      final LogicalExtractor extractor,
                                      final int width, final int height)
            throws IOException, ImageCryptException {
        int rowBytes = Math.multiplyExact(width, ImageCryptProtocol.PNG_BYTES_PER_PIXEL);
        byte[] previous = null;
        byte[] current = new byte[rowBytes];
        byte[] filter = new byte[1];

        for (int y = 0; y < height; y++) {
            readInflatedFully(zlibInput, filter, 0, 1);
            readInflatedFully(zlibInput, current, 0, current.length);
            PngFilters.unfilter(filter[0] & 0xff, current, previous,
                    ImageCryptProtocol.PNG_BYTES_PER_PIXEL);
            extractor.accept(current, 0, current.length);

            byte[] completed = current;
            current = previous == null ? new byte[rowBytes] : previous;
            previous = completed;
        }
    }

    /**
     * 从 zlib 输出中精确读取扫描线字节。
     *
     * @param input  zlib 解压流
     * @param target 目标数组
     * @param offset 起始偏移
     * @param length 精确读取长度
     * @throws IOException         底层读取失败
     * @throws ImageCryptException zlib 在扫描线结束前提前结束
     */
    private static void readInflatedFully(final InputStream input, final byte[] target,
                                          final int offset, final int length)
            throws IOException, ImageCryptException {
        int cursor = offset;
        int end = offset + length;
        while (cursor < end) {
            int count = input.read(target, cursor, end - cursor);
            if (count < 0) {
                throw invalid("PNG zlib 在扫描线结束前提前结束");
            }
            if (count > 0) {
                cursor += count;
            }
        }
    }

    /**
     * 在预期扫描线输出后验证 zlib 与连续 IDAT 都精确结束。
     *
     * @param zlibInput zlib 解压流
     * @param inflater  底层 inflater
     * @param idatInput 连续 IDAT 输入
     * @throws IOException         底层读取失败
     * @throws ImageCryptException 存在额外输出、额外压缩字节或非正常 zlib 结束
     */
    private static void requireExactZlibEnd(final InputStream zlibInput, final Inflater inflater,
                                            final IdatSequenceInputStream idatInput)
            throws IOException, ImageCryptException {
        if (zlibInput.read() >= 0) {
            throw invalid("PNG zlib 解压输出超过 IHDR 声明的扫描线容量");
        }
        if (!inflater.finished()) {
            throw invalid("PNG zlib 流未正常结束");
        }
        if (inflater.getRemaining() != 0) {
            throw invalid("PNG zlib 流结束后仍有额外 IDAT 压缩字节");
        }
        if (idatInput.read() >= 0) {
            throw invalid("PNG zlib 流结束后仍有额外 IDAT 压缩字节");
        }
    }

    /**
     * 验证 IDAT 后块序列、IEND 与物理 EOF。
     *
     * @param chunks      PNG 块 reader
     * @param firstHeader IDAT 序列之后的第一个块；物理 EOF 时为 {@code null}
     * @throws IOException         底层读取失败
     * @throws ImageCryptException 非连续 IDAT、未知关键块、缺少 IEND 或尾随数据
     */
    private static void validateTail(final PngChunkReader chunks,
                                     final PngChunkReader.ChunkHeader firstHeader)
            throws IOException, ImageCryptException {
        PngChunkReader.ChunkHeader header = firstHeader;
        while (header != null) {
            if (header.isType("IDAT")) {
                throw invalid("PNG IDAT 块必须连续");
            }
            if (header.isType("IEND")) {
                if (header.length() != 0) {
                    throw invalid("PNG IEND 块长度必须为 0");
                }
                chunks.requireEndOfStream();
                return;
            }
            if (header.isType("IHDR")) {
                throw invalid("PNG 包含重复 IHDR");
            }
            if (header.isType("sRGB")) {
                throw invalid("PNG sRGB 必须位于 IDAT 之前");
            }
            if (header.critical()) {
                throw invalid("IDAT 后存在不支持的关键块: " + header.type());
            }
            chunks.skipChunk();
            header = chunks.nextChunk();
        }
        throw invalid("PNG 缺少 IEND");
    }

    /**
     * 构造 PNG 格式错误。
     *
     * @param message 诊断消息
     * @return 分类为非法头的异常
     */
    private static ImageCryptException invalid(final String message) {
        return new ImageCryptException(ErrorKind.INVALID_HEADER, message);
    }

    /**
     * 把连续的 IDAT 块暴露为单一压缩字节流。
     *
     * <p>首次遇到非 IDAT 块便结束，并保留该块头供尾部验证；因此后续再次出现 IDAT 时可被
     * 明确识别为「IDAT 不连续」。每个 IDAT 的 CRC 都由 {@link PngChunkReader} 在边界验证。
     *
     * @author ErgouTree
     * @since 2026/9/16
     */
    private static final class IdatSequenceInputStream extends InputStream {

        /**
         * PNG 块 reader。
         */
        private final PngChunkReader chunks;

        /**
         * 单字节读取缓冲。
         */
        private final byte[] single = new byte[1];

        /**
         * IDAT 序列后的第一个块头。
         */
        private PngChunkReader.ChunkHeader nextHeader;

        /**
         * 是否已经到达 IDAT 序列末尾。
         */
        private boolean ended;

        /**
         * 创建 IDAT 连续流。
         *
         * @param chunks      PNG 块 reader
         * @param firstHeader 已激活的第一个 IDAT 块头
         */
        private IdatSequenceInputStream(final PngChunkReader chunks,
                                        final PngChunkReader.ChunkHeader firstHeader) {
            this.chunks = chunks;
            if (firstHeader == null || !firstHeader.isType("IDAT")) {
                throw new IllegalArgumentException("首块必须是 IDAT");
            }
        }

        /**
         * 读取一个压缩字节。
         *
         * @return 无符号字节值；IDAT 序列结束时为 {@code -1}
         * @throws IOException 底层读取或 PNG 校验失败
         */
        @Override
        public int read() throws IOException {
            int count;
            do {
                count = read(single, 0, 1);
            } while (count == 0);
            return count < 0 ? -1 : single[0] & 0xff;
        }

        /**
         * 读取连续 IDAT 数据。
         *
         * @param target 目标缓冲
         * @param offset 起始偏移
         * @param length 最大读取长度
         * @return 实际读取数；序列结束时为 {@code -1}
         * @throws IOException 底层读取或 PNG 校验失败
         */
        @Override
        public int read(final byte[] target, final int offset, final int length) throws IOException {
            Objects.requireNonNull(target, "target");
            if (offset < 0 || length < 0 || offset > target.length - length) {
                throw new IndexOutOfBoundsException("IDAT 输入缓冲区段越界");
            }
            if (length == 0) {
                return 0;
            }
            if (ended) {
                return -1;
            }

            try {
                while (true) {
                    int count = chunks.readChunkData(target, offset, length);
                    if (count >= 0) {
                        return count;
                    }
                    PngChunkReader.ChunkHeader header = chunks.nextChunk();
                    if (header == null || !header.isType("IDAT")) {
                        nextHeader = header;
                        ended = true;
                        return -1;
                    }
                }
            } catch (ImageCryptException e) {
                throw new PngStreamException(e);
            }
        }

        /**
         * 返回 IDAT 序列后的第一个块头。
         *
         * @return 后继块；物理 EOF 时为 {@code null}
         * @throws ImageCryptException 尚未把 IDAT 序列消费到末尾，或读取期间发生 PNG 错误
         */
        private PngChunkReader.ChunkHeader nextHeader() throws ImageCryptException {
            if (!ended) {
                throw invalid("尚未完整消费 PNG IDAT 序列");
            }
            return nextHeader;
        }
    }

    /**
     * 在 {@link InputStream} 接口中暂存结构化 PNG 异常的 IOException 包装。
     *
     * @author ErgouTree
     * @since 2026/9/16
     */
    private static final class PngStreamException extends IOException {

        /**
         * 创建包装异常。
         *
         * @param cause 原始图片协议异常
         */
        private PngStreamException(final ImageCryptException cause) {
            super(cause.getMessage(), cause);
        }

        /**
         * 返回原始图片协议异常。
         *
         * @return 原始异常
         */
        private ImageCryptException imageCause() {
            return (ImageCryptException) getCause();
        }
    }

    /**
     * 从反滤波 RGB 样本中抽取固定前缀或 EGTC-IMG 精确帧。
     *
     * @author ErgouTree
     * @since 2026/9/16
     */
    private static final class LogicalExtractor {

        /**
         * 逻辑输出流。
         */
        private final OutputStream output;

        /**
         * 是否从 OuterHeader 动态推导长度。
         */
        private final boolean frameAware;

        /**
         * OuterHeader 临时缓冲。
         */
        private final byte[] headerBytes;

        /**
         * 固定或动态得到的目标长度。
         */
        private long targetLength;

        /**
         * 已输出的逻辑字节数。
         */
        private long written;

        /**
         * 已收集的头字节数。
         */
        private int headerCount;

        /**
         * IHDR 画布宽度。
         */
        private int canvasWidth;

        /**
         * IHDR 画布高度。
         */
        private int canvasHeight;

        /**
         * 已解析的 EGTC-IMG 外层头。
         */
        private ImageCryptFrame frame;

        /**
         * 创建逻辑抽取器。
         *
         * @param output       逻辑输出流
         * @param frameAware   是否解析 OuterHeader
         * @param targetLength 固定模式目标长度
         */
        private LogicalExtractor(final OutputStream output, final boolean frameAware,
                                 final long targetLength) {
            this.output = Objects.requireNonNull(output, "logicalOutput");
            this.frameAware = frameAware;
            this.targetLength = targetLength;
            this.headerBytes = frameAware
                    ? new byte[ImageCryptProtocol.OUTER_HEADER_LENGTH]
                    : null;
        }

        /**
         * 创建固定长度抽取器。
         *
         * @param output       逻辑输出流
         * @param targetLength 目标长度
         * @return 抽取器
         */
        private static LogicalExtractor fixed(final OutputStream output, final long targetLength) {
            return new LogicalExtractor(output, false, targetLength);
        }

        /**
         * 创建帧感知抽取器。
         *
         * @param output 帧输出流
         * @return 抽取器
         */
        private static LogicalExtractor frame(final OutputStream output) {
            return new LogicalExtractor(output, true, -1L);
        }

        /**
         * 在 IHDR 验证后初始化画布约束。
         *
         * @param width  画布宽度
         * @param height 画布高度
         * @throws ImageCryptException 固定目标长度为负或超过画布容量
         */
        private void initialize(final int width, final int height) throws ImageCryptException {
            canvasWidth = width;
            canvasHeight = height;
            if (!frameAware) {
                long capacity = ImageCryptProtocol.canvasCapacity(width, height);
                if (targetLength < 0) {
                    throw invalid("PNG 逻辑抽取长度不得为负");
                }
                if (targetLength > capacity) {
                    throw new ImageCryptException(ErrorKind.CAPACITY_INSUFFICIENT,
                            "PNG 逻辑抽取长度超过画布容量");
                }
            }
        }

        /**
         * 接收一段反滤波后的 RGB 样本。
         *
         * @param samples RGB 样本数组
         * @param offset  起始偏移
         * @param length  样本长度
         * @throws IOException         逻辑输出失败
         * @throws ImageCryptException OuterHeader 或帧长度非法
         */
        private void accept(final byte[] samples, final int offset, final int length)
                throws IOException, ImageCryptException {
            int cursor = offset;
            int end = offset + length;
            if (frameAware && frame == null) {
                int count = Math.min(end - cursor, headerBytes.length - headerCount);
                System.arraycopy(samples, cursor, headerBytes, headerCount, count);
                headerCount += count;
                cursor += count;
                if (headerCount == headerBytes.length) {
                    initializeFrame();
                }
            }

            if (!frameAware || frame != null) {
                long remaining = targetLength - written;
                if (remaining > 0 && cursor < end) {
                    int count = (int) Math.min((long) (end - cursor), remaining);
                    output.write(samples, cursor, count);
                    written += count;
                }
            }
        }

        /**
         * 解析缓冲的 OuterHeader 并建立动态目标长度。
         *
         * @throws IOException         写出已验证头失败
         * @throws ImageCryptException 头字段、画布或长度非法
         */
        private void initializeFrame() throws IOException, ImageCryptException {
            frame = ImageCryptFrame.fromBytes(headerBytes);
            if (frame.canvasWidth() != canvasWidth || frame.canvasHeight() != canvasHeight) {
                throw invalid("EGTC-IMG 头部画布尺寸与 PNG IHDR 不一致");
            }
            try {
                targetLength = Math.addExact((long) ImageCryptProtocol.OUTER_HEADER_LENGTH,
                        frame.ciphertextLength());
                targetLength = Math.addExact(targetLength,
                        (long) ImageCryptProtocol.AUTH_TAG_LENGTH);
            } catch (ArithmeticException e) {
                throw new ImageCryptException(ErrorKind.INVALID_HEADER, "EGTC-IMG 帧长度溢出", e);
            }
            output.write(headerBytes);
            written = headerBytes.length;
        }

        /**
         * 在 PNG 全部验证后检查抽取长度是否精确满足。
         *
         * @throws ImageCryptException 头未完整出现或帧被截断
         */
        private void finish() throws ImageCryptException {
            if (frameAware && frame == null) {
                throw invalid("PNG RGB 样本不足以容纳完整 EGTC-IMG 头");
            }
            if (written != targetLength) {
                throw invalid("PNG RGB 样本不足: 需要 " + targetLength + " 字节，实际 " + written);
            }
        }

        /**
         * 返回已解析的外层头。
         *
         * @return EGTC-IMG 外层头
         * @throws IllegalStateException 当前不是帧模式或尚未解析完成
         */
        private ImageCryptFrame frame() {
            if (!frameAware || frame == null) {
                throw new IllegalStateException("尚未完成 EGTC-IMG 帧解析");
            }
            return frame;
        }
    }
}
