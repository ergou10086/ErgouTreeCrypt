package hbnu.project.ergoutreecrypt.mediacrypt.mp3;

import hbnu.project.ergoutreecrypt.mediacrypt.ByteRange;

/**
 * 一个 MP3 音频帧的定位信息。
 *
 * <p>帧物理布局：{@code [Header(4B)] [CRC(0/2B)] [SideInfo] [MainData]}。
 * 音视频加密只需知道各区段的偏移与长度，不解码 Huffman 内容。
 *
 * @param offset       帧在文件中的起始偏移（帧头起点）
 * @param frameLength  整帧字节长度（含帧头）
 * @param headerLength 帧头长度（固定 4）
 * @param crcLength    CRC 长度（0 或 2）
 * @param sideInfoLength side info 长度'
 *
 * @author ErgouTree
 */
public record Mp3Frame(long offset, int frameLength, int headerLength, int crcLength,
                       int sideInfoLength) {

    /**
     * 帧头之后的"帧体"区间（CRC + SideInfo + MainData），即 M-BODY 档加密的范围。
     */
    public ByteRange bodyRange() {
        long bodyOffset = offset + headerLength;
        long bodyLength = frameLength - headerLength;
        return new ByteRange(bodyOffset, bodyLength);
    }

    /**
     * 仅 MainData 区间（M-SAFE 档加密的范围，保留 side info）。
     */
    public ByteRange mainDataRange() {
        long mainOffset = offset + headerLength + crcLength + sideInfoLength;
        long mainLength = frameLength - headerLength - crcLength - sideInfoLength;
        return new ByteRange(mainOffset, Math.max(0, mainLength));
    }
}
