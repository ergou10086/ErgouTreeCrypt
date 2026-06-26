package hbnu.project.ergoutreecrypt.mediacrypt.mp4;

import hbnu.project.ergoutreecrypt.mediacrypt.MediaCryptException;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

/**
 * MP4 加密元数据载体：自定义 {@code uuid} box，追加在文件末尾。
 *
 * <p>{@code uuid} box 是 ISO-BMFF 标准的用户扩展 box（{@code [size:4][type='uuid'][usertype:16][data]}）。
 * 标准解析器会跳过未知 {@code uuid} box，因此不影响播放/解析。追加在末尾可保持 {@code mdat} 偏移不变，
 * 使加解密区间一致。
 *
 * <p>本 box payload 布局：{@code [META_UUID:16B][metadata 字节]}。
 *
 * @author ErgouTree
 */
public final class Mp4UuidMetadata {

    private static final String UUID_TYPE = "uuid";

    private Mp4UuidMetadata() {
    }

    /**
     * 把元数据作为 {@code uuid} box 追加到文件末尾。
     *
     * @return 追加的总字节数
     */
    public static long append(Path file, byte[] metadata) throws IOException {
        int payloadLen = BoxParser.META_UUID.length + metadata.length;
        long boxSize = 8L + payloadLen; // size(4)+type(4)+payload
        ByteBuffer bb = ByteBuffer.allocate((int) boxSize).order(ByteOrder.BIG_ENDIAN);
        bb.putInt((int) boxSize);
        bb.put(UUID_TYPE.getBytes(StandardCharsets.US_ASCII));
        bb.put(BoxParser.META_UUID);
        bb.put(metadata);
        bb.flip();

        try (FileChannel ch = FileChannel.open(file, StandardOpenOption.WRITE)) {
            long end = ch.size();
            while (bb.hasRemaining()) {
                end += ch.write(bb, end);
            }
        }
        return boxSize;
    }

    /**
     * 从指定 uuid box 读取 metadata 原始字节（跳过 16 字节 usertype）。
     */
    public static byte[] readMetadata(Path file, Mp4Box uuidBox) throws MediaCryptException, IOException {
        if (uuidBox.payloadSize() < BoxParser.META_UUID.length) {
            throw new MediaCryptException("MP4 uuid 元数据 box 过小");
        }
        long metaOffset = uuidBox.payloadOffset() + BoxParser.META_UUID.length;
        int metaLen = (int) (uuidBox.payloadSize() - BoxParser.META_UUID.length);
        try (FileChannel ch = FileChannel.open(file, StandardOpenOption.READ)) {
            ByteBuffer bb = ByteBuffer.allocate(metaLen);
            int read = 0;
            while (read < metaLen) {
                int n = ch.read(bb, metaOffset + read);
                if (n < 0) {
                    throw new IOException("读取 MP4 uuid 元数据时遇到意外文件结束");
                }
                read += n;
            }
            return bb.array();
        }
    }
}
