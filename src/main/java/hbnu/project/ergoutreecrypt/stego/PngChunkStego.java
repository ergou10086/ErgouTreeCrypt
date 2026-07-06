package hbnu.project.ergoutreecrypt.stego;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;

/**
 * Chunk 结构隐写引擎——将加密数据追加在 PNG 的 IEND 块之后。
 *
 * <p>PNG 规范保证 IEND 是文件的最后一个块，解码器读到 IEND 即停止。
 * 因此 IEND 之后追加的数据对图像查看器完全透明——图片显示与原图无异，
 * 且可嵌入的数据量不受像素尺寸限制（仅受文件系统和 PNG 总大小限制）。
 *
 * <h3>文件布局</h3>
 * <pre>
 *   [原始 PNG 数据，以 IEND 块结束]
 *   [加密载荷：encryptedSize 字节]
 *   [ChunkTrailer 序列化字节]
 *   [trailerSize：4 字节 int]
 *   [MAGIC：16 字节 "EGTC-CHUNK-END01"]
 * </pre>
 *
 * @author ErgouTree
 */
public final class PngChunkStego {

    private PngChunkStego() {
    }

    /**
     * 将加密后的载荷追加到 PNG 文件末尾。
     *
     * @param source          原始 PNG 文件
     * @param output          输出隐写文件
     * @param encryptedPayload 加密后的文件内容
     * @param trailer         尾部元数据
     */
    public static void embed(final Path source, final Path output,
                              final byte[] encryptedPayload,
                              final ChunkTrailer trailer) throws IOException, ImageStegoException {
        byte[] original = Files.readAllBytes(source);
        // 确保原文件以有效的 PNG 结尾（至少末尾是 IEND）
        validatePngEnd(original);

        byte[] trailerBytes = trailer.toBytes();
        int trailerSize = trailerBytes.length;

        ByteBuffer footer = ByteBuffer.allocate(trailerSize + 4 + ChunkTrailer.MAGIC_LEN)
                .order(ByteOrder.BIG_ENDIAN);
        footer.put(trailerBytes);
        footer.putInt(trailerSize);
        footer.put(ChunkTrailer.MAGIC);
        footer.flip();

        try (OutputStream out = Files.newOutputStream(output, StandardOpenOption.CREATE,
                StandardOpenOption.TRUNCATE_EXISTING)) {
            out.write(original);
            out.write(encryptedPayload);
            out.write(footer.array());
        }
    }

    /**
     * 从 PNG 文件中提取追加的加密载荷和元数据。
     *
     * @param source 隐写 PNG 文件
     * @return 提取结果
     * @throws IOException         读取失败
     * @throws ImageStegoException 未检测到隐写数据
     */
    public static ChunkExtractResult extract(final Path source)
            throws IOException, ImageStegoException {
        long fileLen = Files.size(source);
        if (fileLen < ChunkTrailer.MAGIC_LEN + 4) {
            throw new ImageStegoException("文件太小，不可能包含 Chunk 隐写数据");
        }

        // 从文件末尾读取 MAGIC + trailerSize
        byte[] suffix = new byte[ChunkTrailer.FOOTER_SUFFIX_LEN];
        try (InputStream in = Files.newInputStream(source)) {
            skipFully(in, fileLen - suffix.length);
            int read = in.readNBytes(suffix, 0, suffix.length);
            if (read != suffix.length) {
                throw new ImageStegoException("读取文件末尾失败");
            }
        }

        ByteBuffer footer = ByteBuffer.wrap(suffix).order(ByteOrder.BIG_ENDIAN);
        int trailerSize = footer.getInt(suffix.length - 4 - ChunkTrailer.MAGIC_LEN);
        byte[] magic = new byte[ChunkTrailer.MAGIC_LEN];
        System.arraycopy(suffix, suffix.length - ChunkTrailer.MAGIC_LEN,
                magic, 0, ChunkTrailer.MAGIC_LEN);

        if (!Arrays.equals(magic, ChunkTrailer.MAGIC)) {
            throw new ImageStegoException("未检测到 Chunk 隐写数据（魔数不匹配）");
        }

        if (trailerSize <= 0 || trailerSize > fileLen - ChunkTrailer.FOOTER_SUFFIX_LEN) {
            throw new ImageStegoException("Chunk trailer 大小异常: " + trailerSize);
        }

        // 读取 trailer 字节
        byte[] trailerBytes = new byte[trailerSize];
        long trailerStart = fileLen - ChunkTrailer.FOOTER_SUFFIX_LEN - trailerSize;
        try (InputStream in = Files.newInputStream(source)) {
            skipFully(in, trailerStart);
            int read = in.readNBytes(trailerBytes, 0, trailerSize);
            if (read != trailerSize) {
                throw new ImageStegoException("读取 Chunk trailer 不完整");
            }
        }

        ChunkTrailer trailer = ChunkTrailer.fromBytes(trailerBytes);
        long encryptedSize = trailer.encryptedSize;
        if (encryptedSize <= 0 || encryptedSize > Integer.MAX_VALUE) {
            throw new ImageStegoException("加密载荷大小异常: " + encryptedSize);
        }

        long payloadStart = trailerStart - encryptedSize;
        if (payloadStart < 0) {
            throw new ImageStegoException("加密载荷起始位置异常");
        }

        byte[] encryptedPayload = new byte[(int) encryptedSize];
        try (InputStream in = Files.newInputStream(source)) {
            skipFully(in, payloadStart);
            int read = in.readNBytes(encryptedPayload, 0, (int) encryptedSize);
            if (read != encryptedSize) {
                throw new ImageStegoException("读取加密载荷不完整");
            }
        }

        return new ChunkExtractResult(trailer, encryptedPayload);
    }

    /**
     * 快速检测文件是否包含 Chunk 隐写数据（仅检查末尾魔数）。
     */
    public static boolean isChunkStego(final Path file) throws IOException {
        try {
            long len = Files.size(file);
            if (len < ChunkTrailer.MAGIC_LEN) return false;
            byte[] tail = new byte[ChunkTrailer.MAGIC_LEN];
            try (InputStream in = Files.newInputStream(file)) {
                skipFully(in, len - tail.length);
                in.readNBytes(tail, 0, tail.length);
            }
            return Arrays.equals(tail, ChunkTrailer.MAGIC);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * 跳过指定字节数（循环 skip，确保完全跳过）。
     */
    private static void skipFully(final InputStream in, final long n) throws IOException {
        long remaining = n;
        while (remaining > 0) {
            long skipped = in.skip(remaining);
            if (skipped <= 0) {
                throw new IOException("无法跳过 " + remaining + " 字节");
            }
            remaining -= skipped;
        }
    }

    /**
     * 验证 PNG 以有效 IEND 结束（至少检查最后 12 字节）。
     */
    private static void validatePngEnd(final byte[] data) throws ImageStegoException {
        if (data.length < 12) {
            throw new ImageStegoException("文件太小，不是有效 PNG");
        }
        // PNG 签名
        if (data[0] != (byte) 0x89 || data[1] != 'P' || data[2] != 'N' || data[3] != 'G') {
            throw new ImageStegoException("不是有效的 PNG 文件（签名不匹配）");
        }
    }

    /**
     * Chunk 提取结果。
     */
    public record ChunkExtractResult(ChunkTrailer trailer, byte[] encryptedPayload) {
    }
}
