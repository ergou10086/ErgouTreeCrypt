package hbnu.project.ergoutreecrypt.mediacrypt.mp3;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;

import hbnu.project.ergoutreecrypt.mediacrypt.AbstractMediaCipher;
import hbnu.project.ergoutreecrypt.mediacrypt.ByteRange;
import hbnu.project.ergoutreecrypt.mediacrypt.MediaCryptException;
import hbnu.project.ergoutreecrypt.mediacrypt.MediaCryptProfile;
import hbnu.project.ergoutreecrypt.mediacrypt.MediaFormat;
import hbnu.project.ergoutreecrypt.mediacrypt.MediaMetadata;

/**
 * MP3 格式保持加密。
 *
 * <p>默认 <b>M-BODY 档</b>（{@link MediaCryptProfile#M_BODY}）：对每帧"帧头之后的全部字节"（CRC + SideInfo + MainData）连续 XChaCha20 XOR，帧头 4 字节原样保留 → 文件仍是合法 MP3、时长/采样率正常，但内容为噪声。
 * 按物理帧体处理，不解析 Huffman 语义，从而规避 "压缩域 XOR 致 Huffman 同步错误"，且物理字节级可逆。
 *
 * <p>另支持 <b>M-SAFE 档</b>（{@link MediaCryptProfile#M_SAFE}）：仅加密 MainData、保留 Side Info，兼容性更好。
 *
 * <p>元数据载体：文件末尾追加自包含尾块（{@link Mp3MetadataTrailer}），不改变任何音频帧偏移。
 *
 * @author ErgouTree
 */
public final class Mp3Cipher extends AbstractMediaCipher {

    @Override
    public MediaFormat format() {
        return MediaFormat.MP3;
    }

    @Override
    protected EncryptPlan planEncrypt(Path input, MediaCryptProfile profile)
            throws MediaCryptException, IOException {
        Mp3FrameScanner scanner = Mp3FrameScanner.scan(input);
        List<ByteRange> ranges = collectRanges(scanner, profile);
        return new EncryptPlan(ranges);
    }

    @Override
    protected void writeMetadata(Path output, MediaMetadata metadata, EncryptPlan plan)
            throws IOException {
        Mp3MetadataTrailer.append(output, metadata.toBytes());
    }

    @Override
    protected DecryptPlan readMetadata(Path input, Path output)
            throws MediaCryptException, IOException {
        byte[] metaBytes = Mp3MetadataTrailer.readMetadata(input);
        MediaMetadata metadata = MediaMetadata.fromBytes(metaBytes);

        // 剥离尾块：把原始内容长度的前缀拷贝到输出。
        long originalLen = Mp3MetadataTrailer.originalLength(input);
        try (FileChannel in = FileChannel.open(input, StandardOpenOption.READ);
             FileChannel out = FileChannel.open(output, StandardOpenOption.CREATE,
                     StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING)) {
            long transferred = 0;
            while (transferred < originalLen) {
                long n = in.transferTo(transferred, originalLen - transferred, out);
                if (n <= 0) {
                    break;
                }
                transferred += n;
            }
            if (transferred != originalLen) {
                throw new IOException("剥离 MP3 尾块时复制不完整");
            }
        }

        // 在去尾块后的原始容器上重新扫描帧，得到与加密时一致的区间。
        Mp3FrameScanner scanner = Mp3FrameScanner.scan(output);
        List<ByteRange> ranges = collectRanges(scanner, metadata.profile());
        return new DecryptPlan(metadata, ranges);
    }

    @Override
    public boolean isEncrypted(Path input) throws IOException {
        return Mp3MetadataTrailer.hasTrailer(input);
    }

    /**
     * 按档位收集待加密区间。
     */
    private static List<ByteRange> collectRanges(Mp3FrameScanner scanner, MediaCryptProfile profile)
            throws MediaCryptException {
        List<ByteRange> ranges = new ArrayList<>();
        for (Mp3Frame frame : scanner.frames()) {
            ByteRange r = switch (profile) {
                case M_BODY -> frame.bodyRange();
                case M_SAFE -> frame.mainDataRange();
                default -> throw new MediaCryptException("MP3 不支持的档位: " + profile);
            };
            if (!r.isEmpty()) {
                ranges.add(r);
            }
        }
        if (ranges.isEmpty()) {
            throw new MediaCryptException("MP3 无可加密的帧体数据");
        }
        return ranges;
    }
}
