package hbnu.project.ergoutreecrypt.mediacrypt.mp3;

import hbnu.project.ergoutreecrypt.mediacrypt.MediaCryptException;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

/**
 * MP3 加密元数据载体：在文件<b>末尾追加</b>一个自包含尾块。
 *
 * <p>设计取舍：文档原方案是写 ID3v2 {@code PRIV} 帧。
 * 但 ID3v2 位于文件<b>头部</b>，插入会改变所有音频帧的偏移，给"原地等长 XOR"带来额外的偏移换算复杂度与出错风险。
 * 改为<b>追加尾块</b>有两个好处：
 * <ol>
 *   <li>所有音频帧偏移保持不变 → 加解密区间天然一致、实现简单且不易错；</li>
 *   <li>绝大多数 MP3 播放器按帧解析、忽略音频帧之后的未知尾部数据（与 ID3v1/APE 共存机制一致），
 *       因此文件仍可播放（内容为噪声）。</li>
 * </ol>
 *
 * <p>尾块布局（追加在原文件末尾）：
 * <pre>
 *   [ metadata 字节（见 MediaMetadata.toBytes，变长） ]
 *   [ trailerLen : 4B 大端 = metadata 长度 ]
 *   [ trailerMagic : 8B = "EGTCMP3T" ]
 * </pre>
 * 解密时从文件尾读固定 12 字节定位，再回读 metadata，并按"原文件长度 = 当前长度 - 尾块总长"剥离。
 *
 * @author ErgouTree
 */
public final class Mp3MetadataTrailer {

    /**
     * 尾块魔数（区别于通用元数据魔数，用于从文件尾快速定位）。
     */
    static final byte[] TRAILER_MAGIC = "EGTCMP3T".getBytes(StandardCharsets.US_ASCII);
    /**
     * 尾块固定后缀长度：4 字节长度 + 8 字节魔数。
     */
    static final int TRAILER_SUFFIX_LEN = 4 + TRAILER_MAGIC.length;

    private Mp3MetadataTrailer() {
    }

    /**
     * 把元数据作为尾块追加到文件末尾。
     *
     * @return 追加的总字节数
     */
    public static long append(Path file, byte[] metadata) throws IOException {
        ByteBuffer bb = ByteBuffer.allocate(metadata.length + TRAILER_SUFFIX_LEN)
                .order(ByteOrder.BIG_ENDIAN);
        bb.put(metadata);
        bb.putInt(metadata.length);
        bb.put(TRAILER_MAGIC);
        bb.flip();

        try (FileChannel ch = FileChannel.open(file, StandardOpenOption.WRITE)) {
            long end = ch.size();
            while (bb.hasRemaining()) {
                end += ch.write(bb, end);
            }
        }
        return metadata.length + TRAILER_SUFFIX_LEN;
    }

    /**
     * 检测文件末尾是否带本工具的 MP3 尾块魔数。
     */
    public static boolean hasTrailer(Path file) throws IOException {
        try (FileChannel ch = FileChannel.open(file, StandardOpenOption.READ)) {
            long size = ch.size();
            if (size < TRAILER_SUFFIX_LEN) {
                return false;
            }
            ByteBuffer bb = ByteBuffer.allocate(TRAILER_MAGIC.length);
            readInto(ch, bb, size - TRAILER_MAGIC.length, TRAILER_MAGIC.length);
            for (int i = 0; i < TRAILER_MAGIC.length; i++) {
                if (bb.get(i) != TRAILER_MAGIC[i]) {
                    return false;
                }
            }
            return true;
        }
    }

    /**
     * 读取尾块中的 metadata 原始字节。
     *
     * @throws MediaCryptException 尾块缺失或损坏
     */
    public static byte[] readMetadata(Path file) throws MediaCryptException, IOException {
        try (FileChannel ch = FileChannel.open(file, StandardOpenOption.READ)) {
            long size = ch.size();
            if (size < TRAILER_SUFFIX_LEN) {
                throw new MediaCryptException("MP3 文件过小，缺少加密尾块");
            }
            ByteBuffer suffix = ByteBuffer.allocate(TRAILER_SUFFIX_LEN).order(ByteOrder.BIG_ENDIAN);
            readInto(ch, suffix, size - TRAILER_SUFFIX_LEN, TRAILER_SUFFIX_LEN);

            int metaLen = suffix.getInt(0);
            for (int i = 0; i < TRAILER_MAGIC.length; i++) {
                if (suffix.get(4 + i) != TRAILER_MAGIC[i]) {
                    throw new MediaCryptException("MP3 加密尾块魔数不符");
                }
            }
            if (metaLen < 0 || metaLen + TRAILER_SUFFIX_LEN > size) {
                throw new MediaCryptException("MP3 加密尾块长度非法");
            }

            long metaOffset = size - TRAILER_SUFFIX_LEN - metaLen;
            ByteBuffer meta = ByteBuffer.allocate(metaLen);
            readInto(ch, meta, metaOffset, metaLen);
            return meta.array();
        }
    }

    /**
     * 返回剥离尾块后原始内容的字节长度（= 文件长度 - metadata 长度 - 后缀长度）。
     */
    public static long originalLength(Path file) throws MediaCryptException, IOException {
        byte[] meta = readMetadata(file);
        long size;
        try (FileChannel ch = FileChannel.open(file, StandardOpenOption.READ)) {
            size = ch.size();
        }
        return size - meta.length - TRAILER_SUFFIX_LEN;
    }

    private static void readInto(FileChannel ch, ByteBuffer bb, long pos, int len)
            throws IOException {
        int read = 0;
        while (read < len) {
            int n = ch.read(bb, pos + read);
            if (n < 0) {
                throw new IOException("读取 MP3 尾块时遇到意外文件结束，位置 " + pos);
            }
            read += n;
        }
        bb.flip();
    }
}
