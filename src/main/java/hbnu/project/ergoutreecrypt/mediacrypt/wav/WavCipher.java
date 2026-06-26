package hbnu.project.ergoutreecrypt.mediacrypt.wav;

import hbnu.project.ergoutreecrypt.mediacrypt.*;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.List;

/**
 * WAV 格式保持加密（W-FULL 档）。
 *
 * <p>仅对 {@code data} chunk 的 PCM payload 做等长 XChaCha20 XOR，其余 chunk（{@code fmt } / 元数据 / 头）原样保留。
 *
 * <p>元数据载体：在文件末尾追加一个自定义 {@code EgTc} chunk（{@link WavParser#META_CHUNK_ID}），
 * 并相应增大 RIFF 总长 size 字段。标准播放器会忽略未知 chunk，文件依然合法可播放（内容为噪声）。
 * 由于追加在 {@code data} 之后，{@code data} payload 偏移不变，加解密区间一致。
 *
 * <p>解密时读取并剥离 {@code EgTc} chunk、复原 RIFF size，再对 {@code data} payload XOR 还原，实现逐字节无损还原原始 WAV。
 *
 * @author ErgouTree
 */
public final class WavCipher extends AbstractMediaCipher {

    /**
     * 每个 pattern 周期的总字节数。
     */
    private static final int SEL_PERIOD = 8192;
    /**
     * 每个 pattern 周期内加密的字节数（其余保留明文，用于预览/性能档）。
     */
    private static final int SEL_BLOCK = 4096;

    private static long readLeUint32(FileChannel ch, long pos) throws IOException {
        ByteBuffer bb = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN);
        readInto(ch, bb, pos, 4);
        return bb.getInt(0) & 0xFFFFFFFFL;
    }

    private static void writeLeUint32(FileChannel ch, long pos, long value) throws IOException {
        ByteBuffer bb = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN);
        bb.putInt((int) (value & 0xFFFFFFFFL));
        bb.flip();
        while (bb.hasRemaining()) {
            pos += ch.write(bb, pos);
        }
    }

    private static byte[] readBytes(FileChannel ch, long pos, int len) throws IOException {
        ByteBuffer bb = ByteBuffer.allocate(len);
        readInto(ch, bb, pos, len);
        return bb.array();
    }

    private static void readInto(FileChannel ch, ByteBuffer bb, long pos, int len) throws IOException {
        int read = 0;
        while (read < len) {
            int n = ch.read(bb, pos + read);
            if (n < 0) {
                throw new IOException("读取 WAV 时遇到意外文件结束，位置 " + pos);
            }
            read += n;
        }
        bb.flip();
    }

    private static void copyRange(FileChannel in, FileChannel out, long start, long len)
            throws IOException {
        long transferred = 0;
        while (transferred < len) {
            long n = in.transferTo(start + transferred, len - transferred, out);
            if (n <= 0) {
                break;
            }
            transferred += n;
        }
        if (transferred != len) {
            throw new IOException("复制 WAV 数据不完整：期望 " + len + "，实际 " + transferred);
        }
    }

    /**
     * 按档位计算 {@code data} chunk 的待加密区间。
     *
     * <ul>
     *   <li><b>W-FULL（安全档）</b>：整个 data payload；</li>
     *   <li><b>W-SEL（性能/预览档）</b>：pattern 选择性加密——每 {@value #SEL_PERIOD} 字节中加密前
     *       {@value #SEL_BLOCK} 字节（借鉴 CENC pattern 思想，少量区间、速度更快；机密性弱于 W-FULL，
     *       仅作预览/访问控制用途）。</li>
     * </ul>
     * 加解密两端调用本方法得到一致区间。
     */
    private static List<ByteRange> rangesFor(MediaCryptProfile profile, WavChunk data)
            throws MediaCryptException {
        long start = data.payloadOffset();
        long size = data.payloadSize();
        return switch (profile) {
            case W_FULL -> List.of(new ByteRange(start, size));
            case W_SEL -> patternRanges(start, size);
            default -> throw new MediaCryptException("WAV 不支持的档位: " + profile);
        };
    }

    /**
     * 将区间按 SEL_PERIOD 分割，每周期内取 SEL_BLOCK 字节生成加密区间列表。
     */
    private static List<ByteRange> patternRanges(long start, long size) {
        java.util.List<ByteRange> ranges = new java.util.ArrayList<>();
        long offset = 0;
        while (offset < size) {
            long encLen = Math.min(SEL_BLOCK, size - offset);
            if (encLen > 0) {
                ranges.add(new ByteRange(start + offset, encLen));
            }
            offset += SEL_PERIOD;
        }
        if (ranges.isEmpty()) {
            ranges.add(new ByteRange(start, size));
        }
        return ranges;
    }

    @Override
    public MediaFormat format() {
        return MediaFormat.WAV;
    }

    @Override
    protected EncryptPlan planEncrypt(Path input, MediaCryptProfile profile)
            throws MediaCryptException, IOException {
        WavParser parser = WavParser.parse(input);
        WavChunk data = parser.requireDataChunk();
        return new EncryptPlan(rangesFor(profile, data));
    }

    @Override
    protected void writeMetadata(Path output, MediaMetadata metadata, EncryptPlan plan)
            throws IOException {
        byte[] meta = metadata.toBytes();
        long appended = appendMetaChunk(output, meta);

        // 更新 RIFF 总长 size 字段：原值 + 追加 chunk 的总字节数
        try (FileChannel ch = FileChannel.open(output, StandardOpenOption.READ, StandardOpenOption.WRITE)) {
            long oldRiffSize = readLeUint32(ch, 4);
            long newRiffSize = oldRiffSize + appended;
            writeLeUint32(ch, 4, newRiffSize);
        }
    }

    @Override
    protected DecryptPlan readMetadata(Path input, Path output)
            throws MediaCryptException, IOException {
        WavParser parser = WavParser.parse(input);
        WavChunk meta = parser.findChunk(WavParser.META_CHUNK_ID);
        if (meta == null) {
            throw new MediaCryptException("WAV 中未找到加密元数据（EgTc chunk），可能不是本工具加密的文件");
        }

        byte[] metaBytes;
        try (FileChannel ch = FileChannel.open(input, StandardOpenOption.READ)) {
            metaBytes = readBytes(ch, meta.payloadOffset(), (int) meta.payloadSize());
        }
        MediaMetadata metadata = MediaMetadata.fromBytes(metaBytes);

        // 剥离 EgTc chunk：把 [0, meta.idOffset) 写入输出，并复原 RIFF size
        long keepLen = meta.idOffset();
        try (FileChannel in = FileChannel.open(input, StandardOpenOption.READ);
             FileChannel out = FileChannel.open(output, StandardOpenOption.CREATE,
                     StandardOpenOption.READ, StandardOpenOption.WRITE,
                     StandardOpenOption.TRUNCATE_EXISTING)) {
            copyRange(in, out, 0, keepLen);

            long curRiffSize = readLeUint32(out, 4);
            long appended = parser.fileSize() - keepLen;
            writeLeUint32(out, 4, curRiffSize - appended);
        }

        WavParser restored = WavParser.parse(output);
        WavChunk data = restored.requireDataChunk();
        return new DecryptPlan(metadata, rangesFor(metadata.profile(), data));
    }

    @Override
    public boolean isEncrypted(Path input) throws IOException {
        try {
            WavParser parser = WavParser.parse(input);
            return parser.findChunk(WavParser.META_CHUNK_ID) != null;
        } catch (MediaCryptException e) {
            return false;
        }
    }

    /**
     * 在文件末尾追加 {@code EgTc} chunk（8 字节头 + payload + 奇数填充）。
     *
     * @param file    目标文件
     * @param payload chunk payload 字节
     * @return 追加的总字节数
     */
    private long appendMetaChunk(Path file, byte[] payload) throws IOException {
        boolean pad = (payload.length & 1) == 1;
        int total = 8 + payload.length + (pad ? 1 : 0);
        ByteBuffer bb = ByteBuffer.allocate(total).order(ByteOrder.LITTLE_ENDIAN);
        bb.put(WavParser.META_CHUNK_ID.getBytes(StandardCharsets.US_ASCII));
        bb.putInt(payload.length);
        bb.put(payload);
        if (pad) {
            bb.put((byte) 0);
        }
        bb.flip();

        try (FileChannel ch = FileChannel.open(file, StandardOpenOption.WRITE)) {
            long end = ch.size();
            while (bb.hasRemaining()) {
                end += ch.write(bb, end);
            }
        }
        return total;
    }
}
