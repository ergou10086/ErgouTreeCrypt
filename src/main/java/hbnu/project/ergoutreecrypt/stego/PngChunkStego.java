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
 * 因此 IEND 之后追加的数据对图像查看器完全透明。
 *
 * <h3>普通模式文件布局</h3>
 * <pre>
 *   [原始 PNG 数据，以 IEND 块结束]
 *   [加密载荷]
 *   [ChunkTrailer 序列化字节]
 *   [trailerSize：4 字节 int]
 *   [MAGIC：16 字节 "EGTC-CHUNK-END01"]
 * </pre>
 *
 * <h3>隐蔽模式文件布局</h3>
 * <pre>
 *   [原始 PNG 数据，以 IEND 块结束]
 *   [加密载荷]
 *   [ChunkTrailer 序列化字节]
 *   [trailerSize：4 字节 int]
 *   [stealthSalt：16 字节]
 *   [stealthMagic：16 字节 HMAC 派生]
 * </pre>
 *
 * @author ErgouTree
 */
public final class PngChunkStego {

    private PngChunkStego() {}

    /**
     * 将加密后的载荷追加到 PNG 文件末尾。
     *
     * @param stealthSalt  隐蔽模式盐（普通模式为 null）
     * @param stealthMagic 隐蔽模式魔数（普通模式为 null）
     */
    public static void embed(final Path source, final Path output,
                              final byte[] encryptedPayload,
                              final ChunkTrailer trailer,
                              final byte[] stealthSalt,
                              final byte[] stealthMagic)
            throws IOException, ImageStegoException {
        byte[] original = Files.readAllBytes(source);
        validatePngEnd(original);

        byte[] trailerBytes = trailer.toBytes();
        int trailerSize = trailerBytes.length;

        boolean isStealth = (stealthSalt != null && stealthMagic != null);
        int suffixLen = isStealth
                ? ChunkTrailer.STEALTH_FOOTER_SUFFIX_LEN
                : ChunkTrailer.FOOTER_SUFFIX_LEN;

        ByteBuffer footer = ByteBuffer.allocate(trailerSize + suffixLen)
                .order(ByteOrder.BIG_ENDIAN);
        footer.put(trailerBytes);
        footer.putInt(trailerSize);
        if (isStealth) {
            footer.put(stealthSalt);
            footer.put(stealthMagic);
        } else {
            footer.put(ChunkTrailer.MAGIC);
        }
        footer.flip();

        try (OutputStream out = Files.newOutputStream(output, StandardOpenOption.CREATE,
                StandardOpenOption.TRUNCATE_EXISTING)) {
            out.write(original);
            out.write(encryptedPayload);
            out.write(footer.array());
        }
    }

    /** 向后兼容：普通模式嵌入。 */
    public static void embed(final Path source, final Path output,
                              final byte[] encryptedPayload,
                              final ChunkTrailer trailer)
            throws IOException, ImageStegoException {
        embed(source, output, encryptedPayload, trailer, null, null);
    }

    /**
     * 从 PNG 文件中提取追加的加密载荷和元数据。
     *
     * @param source   隐写 PNG 文件
     * @param password 密码（隐蔽模式需要；普通模式可为 null）
     */
    public static ChunkExtractResult extract(final Path source, final byte[] password)
            throws IOException, ImageStegoException {
        long fileLen = Files.size(source);
        if (fileLen < ChunkTrailer.FOOTER_SUFFIX_LEN) {
            throw new ImageStegoException("文件太小，不可能包含 Chunk 隐写数据");
        }

        // 先读文件末尾最后 16 字节检测魔数类型
        byte[] last16 = new byte[ChunkTrailer.MAGIC_LEN];
        try (InputStream in = Files.newInputStream(source)) {
            skipFully(in, fileLen - last16.length);
            in.readNBytes(last16, 0, last16.length);
        }

        boolean isStealth;
        int suffixLen;
        if (ChunkTrailer.isMagicMatch(last16)) {
            // 普通模式：末尾 16B = MAGIC
            isStealth = false;
            suffixLen = ChunkTrailer.FOOTER_SUFFIX_LEN;
        } else {
            // 隐蔽模式：末尾 16B = stealthMagic，其前 16B = stealthSalt
            if (password == null || password.length == 0) {
                throw new ImageStegoException(
                        "检测到隐蔽模式 Chunk 隐写数据，需要提供密码才能提取");
            }
            isStealth = true;
            suffixLen = ChunkTrailer.STEALTH_FOOTER_SUFFIX_LEN;
            if (fileLen < suffixLen) {
                throw new ImageStegoException("文件太小，不可能包含隐蔽模式 Chunk 隐写数据");
            }
        }

        // 读取完整后缀（精确 suffixLen 字节）
        byte[] suffix = new byte[suffixLen];
        try (InputStream in = Files.newInputStream(source)) {
            skipFully(in, fileLen - suffixLen);
            int read = in.readNBytes(suffix, 0, suffixLen);
            if (read != suffixLen) {
                throw new ImageStegoException("读取文件末尾失败");
            }
        }

        // 隐蔽模式：验证 stealthMagic
        if (isStealth) {
            int stealthMagicStart = suffixLen - ChunkTrailer.STEALTH_MAGIC_LEN;
            int stealthSaltStart = stealthMagicStart - ChunkTrailer.STEALTH_SALT_LEN;
            byte[] stealthSalt = Arrays.copyOfRange(suffix, stealthSaltStart, stealthMagicStart);
            byte[] storedMagic = Arrays.copyOfRange(suffix, stealthMagicStart, suffixLen);
            byte[] expected = ChunkTrailer.deriveStealthMagic(stealthSalt, password);
            if (!Arrays.equals(storedMagic, expected)) {
                throw new ImageStegoException("密码错误（隐蔽魔数不匹配）");
            }
        }

        // 解析 trailerSize：在 suffix 中，trailerSize 紧邻魔数（或 stealthSalt）之前
        ByteBuffer footer = ByteBuffer.wrap(suffix).order(ByteOrder.BIG_ENDIAN);
        int trailerSizeOffset = suffixLen - ChunkTrailer.MAGIC_LEN - 4;
        if (isStealth) {
            trailerSizeOffset = suffixLen - ChunkTrailer.STEALTH_MAGIC_LEN
                    - ChunkTrailer.STEALTH_SALT_LEN - 4;
        }
        int trailerSize = footer.getInt(trailerSizeOffset);

        if (trailerSize <= 0 || trailerSize > fileLen - suffixLen) {
            throw new ImageStegoException("Chunk trailer 大小异常: " + trailerSize);
        }

        // 读取 trailer 字节
        byte[] trailerBytes = new byte[trailerSize];
        long trailerStart = fileLen - suffixLen - trailerSize;
        try (InputStream in = Files.newInputStream(source)) {
            skipFully(in, trailerStart);
            int read = in.readNBytes(trailerBytes, 0, trailerSize);
            if (read != trailerSize) {
                throw new ImageStegoException("读取 Chunk trailer 不完整");
            }
        }

        ChunkTrailer trailer = ChunkTrailer.fromBytes(trailerBytes, isStealth);
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

    /** 向后兼容：不带密码提取（仅支持普通模式）。 */
    public static ChunkExtractResult extract(final Path source)
            throws IOException, ImageStegoException {
        return extract(source, null);
    }

    /** 快速检测文件是否包含 Chunk 隐写数据。 */
    public static boolean isChunkStego(final Path file) throws IOException {
        try {
            long len = Files.size(file);
            // 检查普通模式
            if (len >= ChunkTrailer.MAGIC_LEN) {
                byte[] tail = new byte[ChunkTrailer.MAGIC_LEN];
                try (InputStream in = Files.newInputStream(file)) {
                    skipFully(in, len - tail.length);
                    in.readNBytes(tail, 0, tail.length);
                }
                if (ChunkTrailer.isMagicMatch(tail)) {
                    return true;
                }
            }
            // 隐蔽模式无法快速检测（无固定魔数），返回 false
            return false;
        } catch (Exception e) {
            return false;
        }
    }

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

    private static void validatePngEnd(final byte[] data) throws ImageStegoException {
        if (data.length < 12) {
            throw new ImageStegoException("文件太小，不是有效 PNG");
        }
        if (data[0] != (byte) 0x89 || data[1] != 'P' || data[2] != 'N' || data[3] != 'G') {
            throw new ImageStegoException("不是有效的 PNG 文件（签名不匹配）");
        }
    }

    public record ChunkExtractResult(ChunkTrailer trailer, byte[] encryptedPayload) {}
}
