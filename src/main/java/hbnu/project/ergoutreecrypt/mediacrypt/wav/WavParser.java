package hbnu.project.ergoutreecrypt.mediacrypt.wav;

import hbnu.project.ergoutreecrypt.mediacrypt.MediaCryptException;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;

/**
 * RIFF/WAVE 容器解析器：扫描所有 chunk，定位 {@code fmt }、{@code data} 及自定义元数据 chunk。
 *
 * <p>WAV 总体结构：{@code "RIFF" <size4> "WAVE" <chunk>...}。本解析器只关心 chunk 的位置与长度，
 * 不解码 PCM 内容——音视频加密只需对 {@code data} chunk 的 payload 做等长 XOR。
 *
 * <p>当前支持：标准 WAV（RIFF 头）。{@code RF64}（>4GiB 变体）暂不支持，会显式报错。
 *
 * @author ErgouTree
 */
public final class WavParser {

    /**
     * 自定义元数据 chunk ID（4 字符）。
     */
    public static final String META_CHUNK_ID = "EgTc";

    private static final long RIFF_HEADER_LEN = 12; // "RIFF"+size4+"WAVE"

    private final List<WavChunk> chunks;
    private final long riffSizeFieldOffset;
    private final long fileSize;

    private WavParser(List<WavChunk> chunks, long riffSizeFieldOffset, long fileSize) {
        this.chunks = chunks;
        this.riffSizeFieldOffset = riffSizeFieldOffset;
        this.fileSize = fileSize;
    }

    /**
     * 解析 WAV 文件。
     *
     * @throws MediaCryptException 非法 RIFF/WAVE 或不支持的变体
     */
    public static WavParser parse(Path path) throws MediaCryptException, IOException {
        try (FileChannel ch = FileChannel.open(path, StandardOpenOption.READ)) {
            long fileSize = ch.size();
            if (fileSize < RIFF_HEADER_LEN) {
                throw new MediaCryptException("文件过小，不是合法 WAV");
            }

            ByteBuffer head = readAt(ch, 0, 12);
            String riff = ascii(head, 0, 4);
            String wave = ascii(head, 8, 4);
            if ("RF64".equals(riff)) {
                throw new MediaCryptException("暂不支持 RF64（大文件 WAV 变体）");
            }
            if (!"RIFF".equals(riff) || !"WAVE".equals(wave)) {
                throw new MediaCryptException("不是合法的 RIFF/WAVE 文件");
            }

            List<WavChunk> chunks = new ArrayList<>();
            long pos = RIFF_HEADER_LEN;
            while (pos + 8 <= fileSize) {
                ByteBuffer hdr = readAt(ch, pos, 8);
                String id = ascii(hdr, 0, 4);
                long size = hdr.order(ByteOrder.LITTLE_ENDIAN).getInt(4) & 0xFFFFFFFFL;
                long payloadOffset = pos + 8;

                // 防御：size 越界则截断到文件尾，避免读越界。
                if (payloadOffset + size > fileSize) {
                    size = Math.max(0, fileSize - payloadOffset);
                }

                WavChunk chunk = new WavChunk(id, pos, payloadOffset, size);
                chunks.add(chunk);
                pos += chunk.totalSize();
            }

            return new WavParser(chunks, 4, fileSize);
        }
    }

    private static ByteBuffer readAt(FileChannel ch, long pos, int len) throws IOException {
        ByteBuffer bb = ByteBuffer.allocate(len);
        int read = 0;
        while (read < len) {
            int n = ch.read(bb, pos + read);
            if (n < 0) {
                throw new IOException("读取 WAV 时遇到意外文件结束，位置 " + pos);
            }
            read += n;
        }
        bb.flip();
        return bb;
    }

    private static String ascii(ByteBuffer bb, int off, int len) {
        byte[] b = new byte[len];
        for (int i = 0; i < len; i++) {
            b[i] = bb.get(off + i);
        }
        return new String(b, StandardCharsets.US_ASCII);
    }

    /**
     * 查找指定 ID 的首个 chunk。
     *
     * @return chunk 或 {@code null}（不存在）
     */
    public WavChunk findChunk(String id) {
        for (WavChunk c : chunks) {
            if (c.id().equals(id)) {
                return c;
            }
        }
        return null;
    }

    /**
     * 返回 {@code data} chunk。
     *
     * @throws MediaCryptException 缺少 data chunk
     */
    public WavChunk requireDataChunk() throws MediaCryptException {
        WavChunk data = findChunk("data");
        if (data == null) {
            throw new MediaCryptException("WAV 缺少 data chunk");
        }
        return data;
    }

    public List<WavChunk> chunks() {
        return chunks;
    }

    /**
     * RIFF 总长度 size 字段在文件中的偏移（固定为 4）。
     */
    public long riffSizeFieldOffset() {
        return riffSizeFieldOffset;
    }

    public long fileSize() {
        return fileSize;
    }
}
