package hbnu.project.ergoutreecrypt.mediacrypt.mp4;

import java.nio.charset.StandardCharsets;

/**
 * 一个 ISO-BMFF（MP4）box/atom 的定位信息。
 *
 * <p>box 结构：{@code [size:4B 大端][type:4B] [payload]}。
 * 当 {@code size==1} 时，紧随 type 之后有 8 字节 {@code largesize}（64 位）；
 * 当 {@code size==0} 时，box 延伸至文件尾。
 *
 * @param type          4 字符 box 类型（如 {@code "ftyp"} / {@code "moov"} / {@code "mdat"}）
 * @param boxOffset     box 起始偏移（size 字段起点）
 * @param headerSize    box 头长度（8 或 16，含 largesize）
 * @param payloadOffset payload 起始偏移（= boxOffset + headerSize）
 * @param payloadSize   payload 字节数
 * @param zeroSize      原始 size 字段是否为 0（延伸至文件尾）
 *
 * @author ErgouTree
 */
public record Mp4Box(String type, long boxOffset, int headerSize, long payloadOffset,
                     long payloadSize, boolean zeroSize) {

    /**
     * 兼容构造器：zeroSize 默认为 false。
     */
    public Mp4Box(String type, long boxOffset, int headerSize, long payloadOffset,
                  long payloadSize) {
        this(type, boxOffset, headerSize, payloadOffset, payloadSize, false);
    }

    /**
     * 整个 box 占用的字节数（头 + payload）。
     */
    public long totalSize() {
        return headerSize + payloadSize;
    }

    public byte[] typeBytes() {
        return type.getBytes(StandardCharsets.US_ASCII);
    }
}
