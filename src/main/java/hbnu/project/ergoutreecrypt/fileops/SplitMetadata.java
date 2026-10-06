package hbnu.project.ergoutreecrypt.fileops;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.UUID;
import java.util.zip.CRC32;

/**
 * * 每卷重复保存的 64 字节元数据尾部；密文认证仍由原有 MAC 和 RS 流程完成。
 * @param index 从 0 开始的卷编号
 * @param count 总卷数
 * @param total 合并后的密文字节数
 * @param chunkSize 每卷最大密文字节数
 * @param group 本次分卷的随机批次标识
 */
record SplitMetadata(int index, int count, long total, long chunkSize, UUID group) {
    static final int SIZE = Splitter.METADATA_BYTES;
    private static final long MAGIC = 0x45475443564f4c32L;
    private static final long END_MAGIC = 0x324c4f5654434745L;
    private static final int VERSION = 2;

    /** @return 本卷的密文字节数，不含元数据尾部。 */
    long payloadSize() { return index == count - 1 ? total - (long) index * chunkSize : chunkSize; }

    /**
     * @param other 另一卷的元数据
     * @return 是否属于同一批次且参数完全一致。
     */
    boolean sameGroup(SplitMetadata other) {
        return other != null && count == other.count && total == other.total
                && chunkSize == other.chunkSize && group.equals(other.group);
    }

    /** @return 固定大小的大端序尾部。 */
    byte[] encode() {
        ByteBuffer b = ByteBuffer.allocate(SIZE);
        b.putLong(MAGIC).putInt(index).putInt(count).putLong(total).putLong(chunkSize)
                .putLong(group.getMostSignificantBits()).putLong(group.getLeastSignificantBits()).putInt(VERSION);
        CRC32 crc = new CRC32();
        crc.update(b.array(), 0, 52);
        b.putInt((int) crc.getValue()).putLong(END_MAGIC);
        return b.array();
    }

    /**
     * @param path 分卷路径
     * @return 元数据，旧原始字节分卷为 null
     * @throws IOException 尾部非法或读取失败。
     */
    static SplitMetadata read(Path path) throws IOException {
        try (SeekableByteChannel channel = Files.newByteChannel(path)) {
            if (channel.size() < SIZE) return null;
            channel.position(channel.size() - SIZE);
            ByteBuffer b = ByteBuffer.allocate(SIZE);
            while (b.hasRemaining()) {
                if (channel.read(b) < 0) throw new IOException("split volume changed during inspection");
            }
            return decode(b.array());
        }
    }

    /**
     * @param bytes 完整尾部
     * @return 元数据，未出现任一格式标记时为 null
     * @throws IOException 格式或校验和错误。
     */
    static SplitMetadata decode(byte[] bytes) throws IOException {
        if (bytes.length != SIZE) throw new IOException("truncated split metadata");
        ByteBuffer b = ByteBuffer.wrap(bytes);
        boolean start = b.getLong(0) == MAGIC, end = b.getLong(56) == END_MAGIC;
        if (!start && !end) return null;
        CRC32 crc = new CRC32();
        crc.update(bytes, 0, 52);
        if (!start || !end || b.getInt(48) != VERSION || b.getInt(52) != (int) crc.getValue()) {
            throw new IOException("invalid split metadata checksum or version");
        }
        b.position(8);
        SplitMetadata metadata = new SplitMetadata(b.getInt(), b.getInt(), b.getLong(), b.getLong(),
                new UUID(b.getLong(), b.getLong()));
        long computed = metadata.total == 0 ? 1 : 1 + (metadata.total - 1) / Math.max(1, metadata.chunkSize);
        if (metadata.total < 0 || metadata.chunkSize <= 0 || metadata.count <= 0
                || metadata.count > Splitter.MAX_CHUNKS || metadata.index < 0
                || metadata.index >= metadata.count || metadata.count != computed
                || metadata.payloadSize() > Long.MAX_VALUE - SIZE) {
            throw new IOException("inconsistent split metadata");
        }
        return metadata;
    }
}
