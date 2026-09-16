package hbnu.project.ergoutreecrypt.imagecrypt.png;

import hbnu.project.ergoutreecrypt.exception.ErrorKind;
import hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptException;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Objects;
import java.util.zip.CRC32;

/**
 * 有界、流式的 PNG 块读取器。
 *
 * <p>读取器不会按块声明长度分配数组。调用方先取得 {@link ChunkHeader}，再流式读取或跳过
 * 当前块数据；CRC32 在数据消费完毕时立即验证。这样即使输入伪造了接近 2 GiB 的块长度，
 * 也只会使用固定大小缓冲，不会触发等长内存分配。
 *
 * <p>本类不解释 IHDR 或块次序，协议子集约束由 {@link PixelPngReader} 负责。调用方持有并
 * 负责关闭底层输入流。
 *
 * @author ErgouTree
 * @since 2026/9/16
 */
public final class PngChunkReader {

    /**
     * PNG 标准 8 字节签名。
     */
    private static final byte[] PNG_SIGNATURE = {
            (byte) 0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a
    };

    /**
     * 跳过大块时使用的固定缓冲大小。
     */
    private static final int SKIP_BUFFER_BYTES = 8192;

    /**
     * 底层输入流。
     */
    private final InputStream input;

    /**
     * 当前块的 CRC32 累加器。
     */
    private final CRC32 currentCrc = new CRC32();

    /**
     * 当前块头；尚未读取时为 {@code null}。
     */
    private ChunkHeader currentHeader;

    /**
     * 当前块尚未消费的数据字节数。
     */
    private long currentRemaining;

    /**
     * 当前块数据与 CRC 是否已经完整验证。
     */
    private boolean currentFinished;

    /**
     * PNG 签名是否已经验证。
     */
    private boolean signatureRead;

    /**
     * 创建 PNG 块 reader。
     *
     * @param input PNG 输入流；生命周期由调用方管理
     */
    public PngChunkReader(final InputStream input) {
        this.input = Objects.requireNonNull(input, "input");
    }

    /**
     * 读取并验证 PNG 标准签名。
     *
     * @throws IOException             底层读取失败
     * @throws ImageCryptException     输入截断或签名不匹配
     * @throws IllegalStateException   签名已经读取
     */
    public void readSignature() throws IOException, ImageCryptException {
        if (signatureRead) {
            throw new IllegalStateException("PNG 签名只能读取一次");
        }
        byte[] actual = new byte[PNG_SIGNATURE.length];
        readFully(actual, 0, actual.length, "PNG 签名不完整");
        if (!Arrays.equals(PNG_SIGNATURE, actual)) {
            throw invalid("PNG 签名不匹配");
        }
        signatureRead = true;
    }

    /**
     * 读取下一个 PNG 块头。
     *
     * <p>返回 {@code null} 表示在完整块边界处到达物理 EOF。若上一个块尚未消费完毕，
     * 会快速失败，避免调用方绕过其 CRC 校验。
     *
     * @return 下一个块头；物理 EOF 时为 {@code null}
     * @throws IOException           底层读取失败
     * @throws ImageCryptException   块头截断、长度超限或类型非法
     * @throws IllegalStateException 签名尚未验证或上一个块尚未消费完毕
     */
    public ChunkHeader nextChunk() throws IOException, ImageCryptException {
        if (!signatureRead) {
            throw new IllegalStateException("读取 PNG 块前必须先验证签名");
        }
        if (currentHeader != null && !currentFinished) {
            throw new IllegalStateException("读取下一个 PNG 块前必须消费当前块");
        }

        byte[] lengthBytes = new byte[4];
        int first = input.read();
        if (first < 0) {
            currentHeader = null;
            return null;
        }
        lengthBytes[0] = (byte) first;
        readFully(lengthBytes, 1, 3, "PNG 块长度字段不完整");
        long length = unsignedInt(lengthBytes);
        if (length > Integer.MAX_VALUE) {
            throw invalid("PNG 块长度超过规范上限: " + length);
        }

        byte[] typeBytes = new byte[4];
        readFully(typeBytes, 0, typeBytes.length, "PNG 块类型字段不完整");
        validateType(typeBytes);
        String type = new String(typeBytes, StandardCharsets.US_ASCII);

        currentHeader = new ChunkHeader(type, length, (typeBytes[0] & 0x20) == 0);
        currentRemaining = length;
        currentFinished = false;
        currentCrc.reset();
        currentCrc.update(typeBytes, 0, typeBytes.length);
        if (currentRemaining == 0) {
            finishCurrentChunk();
        }
        return currentHeader;
    }

    /**
     * 流式读取当前块的数据。
     *
     * <p>读到块数据末尾后会先验证 CRC，再在下一次调用时返回 {@code -1}。
     *
     * @param buffer 目标缓冲
     * @param offset 起始偏移
     * @param length 最多读取的字节数
     * @return 实际读取数；当前块已结束时为 {@code -1}
     * @throws IOException           底层读取失败
     * @throws ImageCryptException   块数据截断或 CRC 不匹配
     * @throws IllegalStateException 尚未读取块头
     */
    public int readChunkData(final byte[] buffer, final int offset, final int length)
            throws IOException, ImageCryptException {
        Objects.requireNonNull(buffer, "buffer");
        if (offset < 0 || length < 0 || offset > buffer.length - length) {
            throw new IndexOutOfBoundsException("PNG 块读取缓冲区段越界");
        }
        if (currentHeader == null) {
            throw new IllegalStateException("尚未读取 PNG 块头");
        }
        if (length == 0) {
            return 0;
        }
        if (currentFinished) {
            return -1;
        }

        int requested = (int) Math.min((long) length, currentRemaining);
        int count = input.read(buffer, offset, requested);
        if (count < 0) {
            throw invalid("PNG 块数据被截断: " + currentHeader.type());
        }
        if (count == 0) {
            return 0;
        }
        currentCrc.update(buffer, offset, count);
        currentRemaining -= count;
        if (currentRemaining == 0) {
            finishCurrentChunk();
        }
        return count;
    }

    /**
     * 把当前小块完整读入数组。
     *
     * <p>调用方必须给出明确上限；若声明长度超过上限，本方法在分配前拒绝。
     *
     * @param maximumLength 允许的最大数据长度
     * @return 当前块数据
     * @throws IOException           底层读取失败
     * @throws ImageCryptException   块过大、截断或 CRC 不匹配
     * @throws IllegalStateException 尚未读取块头
     */
    public byte[] readChunkBytes(final int maximumLength) throws IOException, ImageCryptException {
        if (currentHeader == null) {
            throw new IllegalStateException("尚未读取 PNG 块头");
        }
        if (maximumLength < 0 || currentHeader.length() > maximumLength) {
            throw invalid("PNG 块 " + currentHeader.type() + " 长度超过允许上限: "
                    + currentHeader.length());
        }
        if (currentRemaining != currentHeader.length()) {
            throw new IllegalStateException("当前 PNG 块已经被部分消费");
        }
        byte[] data = new byte[(int) currentHeader.length()];
        int offset = 0;
        while (offset < data.length) {
            int count = readChunkData(data, offset, data.length - offset);
            if (count > 0) {
                offset += count;
            }
        }
        if (data.length == 0 && !currentFinished) {
            finishCurrentChunk();
        }
        return data;
    }

    /**
     * 使用固定缓冲消费并验证当前块，而不保留数据。
     *
     * @throws IOException           底层读取失败
     * @throws ImageCryptException   块截断或 CRC 不匹配
     * @throws IllegalStateException 尚未读取块头
     */
    public void skipChunk() throws IOException, ImageCryptException {
        if (currentHeader == null) {
            throw new IllegalStateException("尚未读取 PNG 块头");
        }
        byte[] buffer = new byte[SKIP_BUFFER_BYTES];
        while (!currentFinished) {
            readChunkData(buffer, 0, buffer.length);
        }
    }

    /**
     * 断言当前块之后已经到达物理 EOF。
     *
     * @throws IOException           底层读取失败
     * @throws ImageCryptException   当前块未完成或 IEND 后仍有尾随字节
     */
    public void requireEndOfStream() throws IOException, ImageCryptException {
        if (currentHeader != null && !currentFinished) {
            throw invalid("检查 PNG 末尾前当前块尚未消费完毕");
        }
        if (input.read() >= 0) {
            throw invalid("PNG IEND 后存在尾随数据");
        }
    }

    /**
     * 读取并验证当前块末尾的 CRC32。
     *
     * @throws IOException           底层读取失败
     * @throws ImageCryptException   CRC 字段截断或数值不匹配
     */
    private void finishCurrentChunk() throws IOException, ImageCryptException {
        byte[] crcBytes = new byte[4];
        readFully(crcBytes, 0, crcBytes.length, "PNG 块 CRC 字段不完整");
        long expected = unsignedInt(crcBytes);
        long actual = currentCrc.getValue();
        if (expected != actual) {
            throw invalid("PNG 块 CRC32 校验失败: " + currentHeader.type());
        }
        currentFinished = true;
    }

    /**
     * 精确读取指定长度，物理 EOF 视为格式截断。
     *
     * @param target  目标数组
     * @param offset  起始偏移
     * @param length  读取长度
     * @param message 截断诊断消息
     * @throws IOException           底层读取失败
     * @throws ImageCryptException   输入提前结束
     */
    private void readFully(final byte[] target, final int offset, final int length, final String message)
            throws IOException, ImageCryptException {
        int cursor = offset;
        int end = offset + length;
        while (cursor < end) {
            int count = input.read(target, cursor, end - cursor);
            if (count < 0) {
                throw invalid(message);
            }
            if (count > 0) {
                cursor += count;
            }
        }
    }

    /**
     * 把 4 字节大端数组扩展为无符号 long。
     *
     * @param bytes 4 字节数组
     * @return 0 到 2^32-1 的数值
     */
    private static long unsignedInt(final byte[] bytes) {
        return (long) (bytes[0] & 0xff) << 24
                | (long) (bytes[1] & 0xff) << 16
                | (long) (bytes[2] & 0xff) << 8
                | bytes[3] & 0xffL;
    }

    /**
     * 校验 PNG 块类型的 ASCII 字母与保留位规则。
     *
     * @param typeBytes 4 字节类型
     * @throws ImageCryptException 类型非法
     */
    private static void validateType(final byte[] typeBytes) throws ImageCryptException {
        for (byte value : typeBytes) {
            int unsigned = value & 0xff;
            if (!isAsciiLetter(unsigned)) {
                throw invalid("PNG 块类型包含非 ASCII 字母");
            }
        }
        if ((typeBytes[2] & 0x20) != 0) {
            throw invalid("PNG 块类型的第三个保留位必须为大写");
        }
    }

    /**
     * 判断数值是否为 ASCII 字母。
     *
     * @param value 无符号字节值
     * @return true 表示是大写或小写 ASCII 字母
     */
    private static boolean isAsciiLetter(final int value) {
        return value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z';
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
     * PNG 块头的不可变描述。
     *
     * <p>长度使用 {@code long} 保存无符号 32 位语义；读取器当前只接受 PNG 规范允许的
     * {@code 0..Integer.MAX_VALUE} 范围。
     *
     * @author ErgouTree
     * @since 2026/9/16
     */
    public static final class ChunkHeader {

        /**
         * 4 字节 ASCII 块类型。
         */
        private final String type;

        /**
         * 块数据长度。
         */
        private final long length;

        /**
         * 是否为关键块。
         */
        private final boolean critical;

        /**
         * 创建块头描述。
         *
         * @param type     块类型
         * @param length   数据长度
         * @param critical 是否为关键块
         */
        private ChunkHeader(final String type, final long length, final boolean critical) {
            this.type = type;
            this.length = length;
            this.critical = critical;
        }

        /**
         * 返回块类型。
         *
         * @return 4 字节 ASCII 类型
         */
        public String type() {
            return type;
        }

        /**
         * 返回块数据长度。
         *
         * @return 无符号 32 位长度
         */
        public long length() {
            return length;
        }

        /**
         * 返回是否为关键块。
         *
         * @return true 表示类型首字母为大写
         */
        public boolean critical() {
            return critical;
        }

        /**
         * 判断块类型是否等于给定文本。
         *
         * @param expected 期望类型
         * @return true 表示相等
         */
        public boolean isType(final String expected) {
            return type.equals(expected);
        }

        /**
         * 返回便于诊断的块头描述。
         *
         * @return 类型与长度
         */
        @Override
        public String toString() {
            return "ChunkHeader{type='" + type + "', length=" + length + '}';
        }
    }
}
