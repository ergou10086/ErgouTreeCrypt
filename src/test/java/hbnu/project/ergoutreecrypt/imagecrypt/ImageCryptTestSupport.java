package hbnu.project.ergoutreecrypt.imagecrypt;

import hbnu.project.ergoutreecrypt.exception.ErrorKind;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * 图片加密测试的共享夹具与断言工具。
 *
 * <p>集中放置十六进制转换、协议头字段改写、以及五种首期格式的最小合法样本构造器，
 * 避免各测试类各写一套字节拼装。
 *
 * @author ErgouTree
 * @since 2026/9/15
 */
final class ImageCryptTestSupport {

    /**
     * 测试用画布边长基数，保证容量足够容纳小载荷。
     */
    static final int DEFAULT_CANVAS_WIDTH = 64;

    /**
     * 测试用画布高度基数。
     */
    static final int DEFAULT_CANVAS_HEIGHT = 64;

    private ImageCryptTestSupport() {
    }

    /**
     * 把十六进制文本解析为字节数组。
     *
     * @param hex 十六进制文本（允许空白与换行）
     * @return 解析结果
     */
    static byte[] hex(final String hex) {
        String compact = hex.replaceAll("\\s", "");
        byte[] out = new byte[compact.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(compact.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    /**
     * 把字节数组渲染为小写十六进制文本。
     *
     * @param data 字节数组
     * @return 十六进制文本
     */
    static String hex(final byte[] data) {
        StringBuilder builder = new StringBuilder(data.length * 2);
        for (byte b : data) {
            builder.append(Character.forDigit((b >> 4) & 0xf, 16));
            builder.append(Character.forDigit(b & 0xf, 16));
        }
        return builder.toString();
    }

    /**
     * 读取测试资源中的夹具文件。
     *
     * @param name 资源名（相对 {@code /imagecrypt/fixtures/}）
     * @return 文件字节
     * @throws IOException 资源缺失或读取失败
     */
    static byte[] fixture(final String name) throws IOException {
        String path = "/imagecrypt/fixtures/" + name;
        try (InputStream in = ImageCryptTestSupport.class.getResourceAsStream(path)) {
            if (in == null) {
                throw new IOException("缺少测试夹具: " + path);
            }
            return in.readAllBytes();
        }
    }

    /**
     * 断言异常分类。
     *
     * @param expected 期望的错误分类
     * @param action   触发异常的代码
     * @return 捕获到的异常
     */
    static ImageCryptException assertKind(final ErrorKind expected, final Executable action) {
        ImageCryptException thrown = assertThrows(ImageCryptException.class, action::run);
        assertEquals(expected, thrown.kind(), "错误分类不符: " + thrown.getMessage());
        return thrown;
    }

    /**
     * 改写协议头中的一段字段并重算 CRC32，用于隔离单一缺陷。
     *
     * @param raw    原始协议头字节
     * @param offset 起始偏移
     * @param value  新的大端整数值
     * @param length 字段字节数
     * @return 改写后的副本
     */
    static byte[] rewriteField(final byte[] raw, final int offset, final long value, final int length) {
        byte[] copy = raw.clone();
        for (int i = 0; i < length; i++) {
            int shift = (length - 1 - i) * 8;
            copy[offset + i] = (byte) (value >>> shift);
        }
        refreshCrc32(copy);
        return copy;
    }

    /**
     * 改写协议头中的一个字节并重算 CRC32。
     *
     * @param raw    原始协议头字节
     * @param offset 偏移
     * @param value  新值
     * @return 改写后的副本
     */
    static byte[] rewriteByte(final byte[] raw, final int offset, final int value) {
        byte[] copy = raw.clone();
        copy[offset] = (byte) value;
        refreshCrc32(copy);
        return copy;
    }

    /**
     * 重算协议头末尾的 headerCrc32。
     *
     * @param raw 协议头字节（原地修改）
     */
    static void refreshCrc32(final byte[] raw) {
        java.util.zip.CRC32 crc = new java.util.zip.CRC32();
        crc.update(raw, 0, ImageCryptProtocol.MAC_COVERED_HEADER_LENGTH);
        ByteBuffer.wrap(raw)
                .order(ByteOrder.BIG_ENDIAN)
                .putInt(ImageCryptProtocol.OFF_HEADER_CRC32, (int) crc.getValue());
    }

    // ==================== 最小合法图片样本 ====================

    /**
     * 构造一个只有签名与 IHDR 的最小 PNG。
     *
     * @param width  宽度
     * @param height 高度
     * @return PNG 字节
     */
    static byte[] minimalPng(final int width, final int height) {
        byte[] header = new byte[33];
        byte[] signature = {(byte) 0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a};
        System.arraycopy(signature, 0, header, 0, signature.length);
        ByteBuffer buffer = ByteBuffer.wrap(header).order(ByteOrder.BIG_ENDIAN);
        buffer.position(8);
        buffer.putInt(13);
        buffer.put("IHDR".getBytes(StandardCharsets.US_ASCII));
        buffer.putInt(width);
        buffer.putInt(height);
        buffer.put((byte) 8);
        buffer.put((byte) 6);
        buffer.put((byte) 0);
        buffer.put((byte) 0);
        buffer.put((byte) 0);
        buffer.putInt(0);
        return header;
    }

    /**
     * 构造一个含 APP0 段与 SOF0 的最小 JPEG。
     *
     * @param width  宽度
     * @param height 高度
     * @return JPEG 字节
     */
    static byte[] minimalJpeg(final int width, final int height) {
        byte[] app0 = hex("ffd8ffe000104a46494600010100000100010000");
        byte[] sof = new byte[11];
        ByteBuffer buffer = ByteBuffer.wrap(sof).order(ByteOrder.BIG_ENDIAN);
        buffer.put((byte) 0xff);
        buffer.put((byte) 0xc0);
        buffer.putShort((short) 17);
        buffer.put((byte) 8);
        buffer.putShort((short) height);
        buffer.putShort((short) width);
        buffer.put((byte) 3);
        byte[] out = new byte[app0.length + sof.length];
        System.arraycopy(app0, 0, out, 0, app0.length);
        System.arraycopy(sof, 0, out, app0.length, sof.length);
        return out;
    }

    /**
     * 构造一个只有逻辑屏幕描述符的最小 GIF89a。
     *
     * @param width  宽度
     * @param height 高度
     * @return GIF 字节
     */
    static byte[] minimalGif(final int width, final int height) {
        byte[] out = new byte[13];
        System.arraycopy("GIF89a".getBytes(StandardCharsets.US_ASCII), 0, out, 0, 6);
        ByteBuffer buffer = ByteBuffer.wrap(out).order(ByteOrder.LITTLE_ENDIAN);
        buffer.position(6);
        buffer.putShort((short) width);
        buffer.putShort((short) height);
        buffer.put((byte) 0);
        buffer.put((byte) 0);
        buffer.put((byte) 0);
        return out;
    }

    /**
     * 构造一个 BITMAPINFOHEADER 的最小 BMP。
     *
     * @param width    宽度
     * @param height   高度（负数表示 top-down）
     * @param dibSize  DIB 头长度
     * @return BMP 字节
     */
    static byte[] minimalBmp(final int width, final int height, final int dibSize) {
        byte[] out = new byte[54];
        out[0] = 'B';
        out[1] = 'M';
        ByteBuffer buffer = ByteBuffer.wrap(out).order(ByteOrder.LITTLE_ENDIAN);
        buffer.position(14);
        buffer.putInt(dibSize);
        if (dibSize == 12) {
            buffer.putShort((short) width);
            buffer.putShort((short) height);
        } else {
            buffer.putInt(width);
            buffer.putInt(height);
        }
        return out;
    }

    /**
     * 构造一个 VP8X 扩展格式的 WebP 头。
     *
     * @param width  画布宽度
     * @param height 画布高度
     * @return WebP 字节
     */
    static byte[] webpVp8x(final int width, final int height) {
        byte[] out = new byte[30];
        ByteBuffer buffer = ByteBuffer.wrap(out).order(ByteOrder.LITTLE_ENDIAN);
        buffer.put("RIFF".getBytes(StandardCharsets.US_ASCII));
        buffer.putInt(out.length - 8);
        buffer.put("WEBP".getBytes(StandardCharsets.US_ASCII));
        buffer.put("VP8X".getBytes(StandardCharsets.US_ASCII));
        buffer.putInt(10);
        buffer.put((byte) 0x10);
        buffer.put(new byte[3]);
        putUInt24(buffer, width - 1);
        putUInt24(buffer, height - 1);
        return out;
    }

    /**
     * 构造一个 VP8L 无损格式的 WebP 头。
     *
     * @param width  宽度
     * @param height 高度
     * @return WebP 字节
     */
    static byte[] webpVp8l(final int width, final int height) {
        byte[] out = new byte[26];
        ByteBuffer buffer = ByteBuffer.wrap(out).order(ByteOrder.LITTLE_ENDIAN);
        buffer.put("RIFF".getBytes(StandardCharsets.US_ASCII));
        buffer.putInt(out.length - 8);
        buffer.put("WEBP".getBytes(StandardCharsets.US_ASCII));
        buffer.put("VP8L".getBytes(StandardCharsets.US_ASCII));
        buffer.putInt(5);
        buffer.put((byte) 0x2F);
        int w = width - 1;
        int h = height - 1;
        buffer.put((byte) (w & 0xff));
        buffer.put((byte) (((w >> 8) & 0x3f) | ((h & 0x03) << 6)));
        buffer.put((byte) ((h >> 2) & 0xff));
        buffer.put((byte) ((h >> 10) & 0x0f));
        return out;
    }

    /**
     * 构造一个 VP8 有损格式的 WebP 头。
     *
     * @param width  宽度
     * @param height 高度
     * @return WebP 字节
     */
    static byte[] webpVp8(final int width, final int height) {
        byte[] out = new byte[30];
        ByteBuffer buffer = ByteBuffer.wrap(out).order(ByteOrder.LITTLE_ENDIAN);
        buffer.put("RIFF".getBytes(StandardCharsets.US_ASCII));
        buffer.putInt(out.length - 8);
        buffer.put("WEBP".getBytes(StandardCharsets.US_ASCII));
        buffer.put("VP8 ".getBytes(StandardCharsets.US_ASCII));
        buffer.putInt(10);
        buffer.put(new byte[3]);
        buffer.put(hex("9d012a"));
        buffer.putShort((short) width);
        buffer.putShort((short) height);
        return out;
    }

    /**
     * 写入 3 字节小端整数。
     *
     * @param buffer 目标缓冲
     * @param value  数值
     */
    private static void putUInt24(final ByteBuffer buffer, final int value) {
        buffer.put((byte) (value & 0xff));
        buffer.put((byte) ((value >> 8) & 0xff));
        buffer.put((byte) ((value >> 16) & 0xff));
    }

    /**
     * 可抛出受检异常的代码块，供 {@link #assertKind} 使用。
     */
    @FunctionalInterface
    interface Executable {

        /**
         * 执行被测代码。
         *
         * @throws Exception 任意失败
         */
        void run() throws Exception;
    }
}
