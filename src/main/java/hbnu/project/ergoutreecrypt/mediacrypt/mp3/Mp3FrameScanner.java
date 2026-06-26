package hbnu.project.ergoutreecrypt.mediacrypt.mp3;

import hbnu.project.ergoutreecrypt.mediacrypt.MediaCryptException;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;

/**
 * MP3 帧扫描器：跳过前置 ID3v2 标签，按"同步字 + 帧长推进"定位所有音频帧。
 *
 * <ul>
 *   <li><b>依赖帧长推进而非纯扫描同步字</b>：MainData 中可能出现伪同步字 {@code 0xFFE}，
 *       一旦锁定首帧，就用帧长跳到下一帧头，避免误判；</li>
 *   <li>遇到非法帧头时（如尾部 ID3v1 / APE / 填充）停止，把剩余视为非音频区，不加密；</li>
 *   <li>用"双帧校验"确认首帧：某位置解析为合法帧头，且其后紧跟的也是合法帧头，才认为找到音频起点。</li>
 * </ul>
 *
 * <p>当前面向 CBR/常见 VBR 的逐帧扫描；不依赖 Xing/VBRI 头，认为这些头本身就是一个普通帧，会被照常加密帧体。
 *
 * @author ErgouTree
 */
public final class Mp3FrameScanner {

    private final List<Mp3Frame> frames;
    private final long audioStart;
    private final long audioEnd;

    private Mp3FrameScanner(List<Mp3Frame> frames, long audioStart, long audioEnd) {
        this.frames = frames;
        this.audioStart = audioStart;
        this.audioEnd = audioEnd;
    }

    /**
     * 扫描 MP3 文件的帧序列。
     *
     * @throws MediaCryptException 找不到任何合法音频帧
     */
    public static Mp3FrameScanner scan(Path path) throws MediaCryptException, IOException {
        byte[] data = readAll(path);
        long fileLen = data.length;

        long pos = skipId3v2(data);
        long firstFrame = findFirstFrame(data, pos);
        if (firstFrame < 0) {
            throw new MediaCryptException("未找到合法的 MP3 音频帧");
        }

        List<Mp3Frame> frames = new ArrayList<>();
        long p = firstFrame;
        while (p + 4 <= fileLen) {
            Mp3HeaderTables.FrameHeader h = parseAt(data, p);
            if (!h.valid()) {
                break; // 遇到非帧数据（如尾部 ID3v1/填充），停止。
            }
            if (p + h.frameLength() > fileLen) {
                break; // 末帧被截断，丢弃不完整帧。
            }
            int crcLen = h.hasCrc() ? 2 : 0;
            int sideLen = (h.layer() == Mp3HeaderTables.LAYER_3)
                    ? Mp3HeaderTables.sideInfoLength(h.version(), h.channelMode())
                    : 0;
            frames.add(new Mp3Frame(p, h.frameLength(), 4, crcLen, sideLen));
            p += h.frameLength();
        }

        if (frames.isEmpty()) {
            throw new MediaCryptException("未找到合法的 MP3 音频帧");
        }
        return new Mp3FrameScanner(frames, firstFrame, p);
    }

    /**
     * 跳过前置 ID3v2 标签，返回音频数据可能的起始偏移。
     *
     * <p>ID3v2 头 10 字节：{@code "ID3" ver(2) flags(1) size(4, synchsafe)}。
     * synchsafe：每字节仅低 7 位有效。
     */
    public static long skipId3v2(byte[] data) {
        if (data.length >= 10 && data[0] == 'I' && data[1] == 'D' && data[2] == '3') {
            int size = ((data[6] & 0x7F) << 21)
                    | ((data[7] & 0x7F) << 14)
                    | ((data[8] & 0x7F) << 7)
                    | (data[9] & 0x7F);
            long total = 10L + size;
            // footer 标志（flags bit4）存在时再加 10 字节。
            if ((data[5] & 0x10) != 0) {
                total += 10;
            }
            return Math.min(total, data.length);
        }
        return 0;
    }

    /**
     * 从 {@code start} 起寻找首个"自洽"音频帧：当前位置是合法帧头，且按帧长跳到的下一位置也是合法帧头。
     *
     * @return 首帧偏移，或 -1 未找到
     */
    private static long findFirstFrame(byte[] data, long start) {
        long limit = data.length - 4;
        for (long i = start; i <= limit; i++) {
            if ((data[(int) i] & 0xff) != 0xFF) {
                continue;
            }
            Mp3HeaderTables.FrameHeader h = parseAt(data, i);
            if (!h.valid()) {
                continue;
            }
            long next = i + h.frameLength();
            // 末帧情况：恰好到文件尾也接受。
            if (next == data.length) {
                return i;
            }
            if (next + 4 <= data.length && parseAt(data, next).valid()) {
                return i;
            }
        }
        return -1;
    }

    private static Mp3HeaderTables.FrameHeader parseAt(byte[] data, long pos) {
        int p = (int) pos;
        if (p + 4 > data.length) {
            return new Mp3HeaderTables.FrameHeader(false, 0, 0, false, 0, 0, 0, 0, 0);
        }
        return Mp3HeaderTables.parse(data[p], data[p + 1], data[p + 2], data[p + 3]);
    }

    private static byte[] readAll(Path path) throws IOException {
        try (FileChannel ch = FileChannel.open(path, StandardOpenOption.READ)) {
            long size = ch.size();
            if (size > Integer.MAX_VALUE - 8) {
                throw new IOException("MP3 文件过大，超出当前实现上限");
            }
            ByteBuffer bb = ByteBuffer.allocate((int) size);
            while (bb.hasRemaining()) {
                if (ch.read(bb) < 0) {
                    break;
                }
            }
            return bb.array();
        }
    }

    public List<Mp3Frame> frames() {
        return frames;
    }

    /**
     * 首帧偏移（音频区起点；其前是 ID3v2 等非音频数据）。
     */
    public long audioStart() {
        return audioStart;
    }

    /**
     * 音频区结束偏移（末帧之后；其后可能是 ID3v1 等）。
     */
    public long audioEnd() {
        return audioEnd;
    }
}
