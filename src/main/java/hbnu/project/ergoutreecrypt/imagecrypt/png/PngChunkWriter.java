package hbnu.project.ergoutreecrypt.imagecrypt.png;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.zip.CRC32;

/**
 * 以流式方式写出 PNG 签名和块结构。
 *
 * <p>本类只负责 PNG 块的通用二进制封装：4 字节大端长度、4 字节 ASCII 类型、块数据，
 * 以及覆盖「类型 + 数据」的 CRC32。块次序由上层 {@link PixelPngWriter} 统一控制。
 * 调用方持有并负责关闭底层输出流，本类不会缓存整张图片。
 *
 * @author ErgouTree
 * @since 2026/9/16
 */
public final class PngChunkWriter {

    /**
     * PNG 标准 8 字节签名。
     */
    private static final byte[] PNG_SIGNATURE = {
            (byte) 0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a
    };

    /**
     * PNG 块类型固定长度。
     */
    private static final int CHUNK_TYPE_LENGTH = 4;

    /**
     * 底层输出流。
     */
    private final OutputStream output;

    /**
     * 是否已经写出 PNG 签名。
     */
    private boolean signatureWritten;

    /**
     * 创建 PNG 块 writer。
     *
     * @param output 目标输出流；生命周期由调用方管理
     */
    public PngChunkWriter(final OutputStream output) {
        this.output = Objects.requireNonNull(output, "output");
    }

    /**
     * 写出 PNG 标准签名。
     *
     * @throws IOException           底层输出失败
     * @throws IllegalStateException 签名已写出
     */
    public void writeSignature() throws IOException {
        if (signatureWritten) {
            throw new IllegalStateException("PNG 签名只能写出一次");
        }
        output.write(PNG_SIGNATURE);
        signatureWritten = true;
    }

    /**
     * 写出一个完整 PNG 块。
     *
     * @param type 4 字节 ASCII 块类型
     * @param data 块数据
     * @throws IOException              底层输出失败
     * @throws IllegalArgumentException 块类型或数据非法
     * @throws IllegalStateException    尚未写出 PNG 签名
     */
    public void writeChunk(final String type, final byte[] data) throws IOException {
        Objects.requireNonNull(data, "data");
        writeChunk(type, data, 0, data.length);
    }

    /**
     * 从给定数组区段写出一个完整 PNG 块。
     *
     * @param type   4 字节 ASCII 块类型
     * @param data   块数据数组
     * @param offset 起始偏移
     * @param length 数据长度
     * @throws IOException              底层输出失败
     * @throws IllegalArgumentException 块类型或数组区段非法
     * @throws IllegalStateException    尚未写出 PNG 签名
     */
    public void writeChunk(final String type, final byte[] data, final int offset, final int length)
            throws IOException {
        if (!signatureWritten) {
            throw new IllegalStateException("写 PNG 块前必须先写出签名");
        }
        Objects.requireNonNull(data, "data");
        if (offset < 0 || length < 0 || offset > data.length - length) {
            throw new IllegalArgumentException("PNG 块数据区段越界");
        }

        byte[] typeBytes = encodeType(type);
        writeInt(length);
        output.write(typeBytes);
        output.write(data, offset, length);

        CRC32 crc = new CRC32();
        crc.update(typeBytes, 0, typeBytes.length);
        crc.update(data, offset, length);
        writeInt((int) crc.getValue());
    }

    /**
     * 刷新底层输出流，但不关闭它。
     *
     * @throws IOException 刷新失败
     */
    public void flush() throws IOException {
        output.flush();
    }

    /**
     * 校验并编码 PNG 块类型。
     *
     * <p>四个字节必须都是 ASCII 字母，且第三个保留位必须为大写。
     *
     * @param type 块类型
     * @return 4 字节 ASCII 编码
     */
    private static byte[] encodeType(final String type) {
        if (type == null || type.length() != CHUNK_TYPE_LENGTH) {
            throw new IllegalArgumentException("PNG 块类型必须恰好为 4 个 ASCII 字母");
        }
        byte[] bytes = type.getBytes(StandardCharsets.US_ASCII);
        for (byte value : bytes) {
            int unsigned = value & 0xff;
            if (!isAsciiLetter(unsigned)) {
                throw new IllegalArgumentException("PNG 块类型只能包含 ASCII 字母: " + type);
            }
        }
        if ((bytes[2] & 0x20) != 0) {
            throw new IllegalArgumentException("PNG 块类型的第三个保留位必须为大写: " + type);
        }
        return bytes;
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
     * 以大端序写出 32 位整数。
     *
     * @param value 待写数值
     * @throws IOException 底层输出失败
     */
    private void writeInt(final int value) throws IOException {
        output.write((value >>> 24) & 0xff);
        output.write((value >>> 16) & 0xff);
        output.write((value >>> 8) & 0xff);
        output.write(value & 0xff);
    }
}
