package hbnu.project.ergoutreecrypt.mediacrypt.wav;

import java.nio.charset.StandardCharsets;

/**
 * 一个 RIFF chunk 的定位信息
 * 不含 payload 内容，仅记录位置与长度
 *
 * <p>RIFF chunk 结构：4 字节 ID + 4 字节小端 size + size 字节 payload（+ size 为奇数时 1 字节填充）。
 *
 * @param id            4 字符 chunk ID（如 {@code "fmt "} / {@code "data"}）
 * @param idOffset      chunk ID 在文件中的偏移（即 chunk 头起点）
 * @param payloadOffset payload 在文件中的偏移（= idOffset + 8）
 * @param payloadSize   payload 字节数（来自 size 字段）
 * @author ErgouTree
 */
public record WavChunk(String id, long idOffset, long payloadOffset, long payloadSize) {

    /**
     * 该 chunk 占用的总字节数（含 8 字节头 + payload + 奇数填充）。
     */
    public long totalSize() {
        long size = 8 + payloadSize;
        if ((payloadSize & 1L) == 1L) {
            // RIFF 规定 payload 长度为奇数时补 1 字节填充。
            size += 1;
        }
        return size;
    }

    /**
     * 把 4 字符 ID 转为字节（ASCII）。
     */
    public byte[] idBytes() {
        return id.getBytes(StandardCharsets.US_ASCII);
    }
}
