package hbnu.project.ergoutreecrypt.mediacrypt;

/**
 * 文件中一段连续的可加密区间，由起始偏移与长度描述。
 *
 * <p>各格式解析器扫描容器后产出一组 {@code ByteRange}
 * WAV: data payload；MP3: 各帧体；MP4: mdat payload
 * 加密器对这些区间按顺序连续 XOR keystream，区间之外的容器结构原样保留。
 *
 * <p>区间在文件中应<b>按 offset 升序、互不重叠</b>，以保证 keystream 推进顺序在加解密两端一致。
 *
 * @param offset 区间在文件中的起始字节偏移（从 0 计）
 * @param length 区间长度（字节）
 * @author ErgouTree
 */
public record ByteRange(long offset, long length) {

    public ByteRange {
        if (offset < 0) {
            throw new IllegalArgumentException("offset 不能为负: " + offset);
        }
        if (length < 0) {
            throw new IllegalArgumentException("length 不能为负: " + length);
        }
    }

    /**
     * 区间结束偏移（不含）。
     */
    public long end() {
        return offset + length;
    }

    /**
     * 是否为空区间。
     */
    public boolean isEmpty() {
        return length == 0;
    }
}
