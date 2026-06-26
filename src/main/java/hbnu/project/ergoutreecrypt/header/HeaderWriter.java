package hbnu.project.ergoutreecrypt.header;

import hbnu.project.ergoutreecrypt.encoding.Fec;
import hbnu.project.ergoutreecrypt.encoding.ReedSolomon;
import hbnu.project.ergoutreecrypt.encoding.RsCodecs;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;

/**
 * 卷头写入器。
 *
 * <p>写入分两阶段：
 * <ol>
 *   <li>{@link #writeHeader(VolumeHeader)} 顺序写入所有 RS 编码字段，auth 值位置写零占位符；</li>
 *   <li>加密完成后调用 {@link #writeAuthValues} 以 {@code FileChannel} 精确回填 auth 值。</li>
 * </ol>
 *
 * @author ErgouTree
 */
public final class HeaderWriter {

    /**
     * header 输出流。
     */
    private final OutputStream out;

    /**
     * 预初始化的 RS 编解码器。
     */
    private final RsCodecs rs;

    /**
     * @param out header 输出流
     * @param rs  预初始化的 RS 编解码器集合
     */
    public HeaderWriter(OutputStream out, RsCodecs rs) {
        this.out = out;
        this.rs = rs;
    }

    /**
     * 写入完整卷头（auth 值位置写入零占位符）。返回总写入字节数。
     *
     * <p>写入顺序：version → commentLen → comments → flags → salt → hkdfSalt → serpentIV
     * → nonce → keyHash(零占位) → keyfileHash(零占位) → authTag(零占位)。
     *
     * @param h 待写入的卷头数据
     * @return 总写入字节数
     * @throws IOException               I/O 错误
     * @throws IllegalArgumentException 若注释超长
     */
    public int writeHeader(VolumeHeader h) throws IOException {
        String comments = h.getComments() == null ? "" : h.getComments();
        byte[] commentBytes = comments.getBytes(StandardCharsets.UTF_8);
        if (commentBytes.length > VolumeHeader.MAX_COMMENT_LEN) {
            throw new IllegalArgumentException("comments exceed maximum length");
        }

        int totalWritten = 0;

        // 1. version: RS5(5→15)
        byte[] versionRaw = toFixedBytes(h.getVersion(), HeaderLayout.VERSION_SRC_SIZE);
        byte[] versionEnc = ReedSolomon.encode(rs.rs5, versionRaw);
        totalWritten += writeAll(versionEnc);

        // 2. comment length: RS5(5→15)，UTF-8 字节数格式化为 5 位十进制
        String commentLenStr = String.format("%05d", commentBytes.length);
        byte[] commentLenRaw = commentLenStr.getBytes(StandardCharsets.UTF_8);
        byte[] commentLenEnc = ReedSolomon.encode(rs.rs5, commentLenRaw);
        totalWritten += writeAll(commentLenEnc);

        // 3. comments: 每个字节 RS1(1→3)
        for (byte c : commentBytes) {
            byte[] charEnc = ReedSolomon.encode(rs.rs1, new byte[] { c });
            totalWritten += writeAll(charEnc);
        }

        // 4. flags: RS5(5→15)
        byte[] flagsRaw = h.getFlags().toBytes();
        byte[] flagsEnc = ReedSolomon.encode(rs.rs5, flagsRaw);
        totalWritten += writeAll(flagsEnc);

        // 5. salt: RS16(16→48)
        totalWritten += writeAll(ReedSolomon.encode(rs.rs16, h.getSalt()));

        // 6. hkdfSalt: RS32(32→96)
        totalWritten += writeAll(ReedSolomon.encode(rs.rs32, h.getHkdfSalt()));

        // 7. serpentIV: RS16(16→48)
        totalWritten += writeAll(ReedSolomon.encode(rs.rs16, h.getSerpentIV()));

        // 8. nonce: RS24(24→72)
        totalWritten += writeAll(ReedSolomon.encode(rs.rs24, h.getNonce()));

        // 9. keyHash 占位符: 192 字节零
        totalWritten += writeAll(new byte[HeaderLayout.KEY_HASH_ENC_SIZE]);

        // 10. keyfileHash 占位符: 96 字节零
        totalWritten += writeAll(new byte[HeaderLayout.KEYFILE_HASH_ENC_SIZE]);

        // 11. authTag 占位符: 192 字节零
        totalWritten += writeAll(new byte[HeaderLayout.AUTH_TAG_ENC_SIZE]);

        return totalWritten;
    }

    /**
     * 回填 auth 值到已写入文件的正确偏移位置。
     *
     * <p>各 auth 值按 RS 编码后通过 FileChannel 在指定偏移处写入，依次为 keyHash、keyfileHash、authTag。
     *
     * @param ch          可定位的文件通道（如 RandomAccessFile.getChannel()）
     * @param offset      auth 值起始偏移（通过 {@link HeaderLayout#authValuesOffset(int)} 计算）
     * @param keyHash     64 字节 keyHash（RS 编码前）
     * @param keyfileHash 32 字节 keyfileHash（RS 编码前）
     * @param authTag     64 字节 authTag（RS 编码前）
     * @param rs          预初始化的 RS 编解码器集合
     * @throws IOException I/O 错误
     */
    public static void writeAuthValues(FileChannel ch, int offset,
                                       byte[] keyHash, byte[] keyfileHash, byte[] authTag,
                                       RsCodecs rs) throws IOException {
        ByteBuffer keyHashBuf = ByteBuffer.wrap(ReedSolomon.encode(rs.rs64, keyHash));
        ByteBuffer keyfileHashBuf = ByteBuffer.wrap(ReedSolomon.encode(rs.rs32, keyfileHash));
        ByteBuffer authTagBuf = ByteBuffer.wrap(ReedSolomon.encode(rs.rs64, authTag));

        ch.write(keyHashBuf, offset);
        offset += HeaderLayout.KEY_HASH_ENC_SIZE;
        ch.write(keyfileHashBuf, offset);
        offset += HeaderLayout.KEYFILE_HASH_ENC_SIZE;
        ch.write(authTagBuf, offset);
    }

    /**
     * 写入字节数组到输出流并返回写入长度。
     */
    private int writeAll(byte[] data) throws IOException {
        out.write(data);
        return data.length;
    }

    /**
     * 将字符串截断或右填充为零至指定长度（用于固定宽度 version 字段）。
     */
    private static byte[] toFixedBytes(String s, int len) {
        byte[] out = new byte[len];
        if (s != null) {
            byte[] raw = s.getBytes(StandardCharsets.UTF_8);
            int copyLen = Math.min(raw.length, len);
            System.arraycopy(raw, 0, out, 0, copyLen);
        }
        return out;
    }
}
