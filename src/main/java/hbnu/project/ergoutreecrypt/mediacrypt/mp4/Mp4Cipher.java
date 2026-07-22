package hbnu.project.ergoutreecrypt.mediacrypt.mp4;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.List;

import hbnu.project.ergoutreecrypt.mediacrypt.AbstractMediaCipher;
import hbnu.project.ergoutreecrypt.mediacrypt.ByteRange;
import hbnu.project.ergoutreecrypt.mediacrypt.MediaCryptException;
import hbnu.project.ergoutreecrypt.mediacrypt.MediaCryptProfile;
import hbnu.project.ergoutreecrypt.mediacrypt.MediaFormat;
import hbnu.project.ergoutreecrypt.mediacrypt.MediaMetadata;

/**
 * MP4（ISO-BMFF）格式保持加密。
 *
 * <p>默认 <b>V-MDAT 档</b>（{@link MediaCryptProfile#V_MDAT}）：
 * 对整个 {@code mdat} payload 连续 XChaCha20 XOR，其余 box（{@code ftyp}/{@code moov} 采样表等）原样保留 → 容器结构合法、{@code ffprobe} 可读出时长/分辨率/编码类型，但解码出的音视频是噪声。
 *
 * <p>元数据载体：文件末尾追加自定义 {@code uuid} box（{@link Mp4UuidMetadata}），不改变 {@code mdat} 偏移。
 *
 * <p>对 {@code mdat} 使用 size==0（ISO-BMFF"延伸至文件尾"）的源文件，
 * 解密时通过回退扫描（{@link BoxParser#scanForMetaUuidBox}）定位被 mdat 吞并的 uuid box，
 * 不会修改原文件的 mdat 头，因此解密可逐字节还原原始文件。
 *
 * @author ErgouTree
 */
public final class Mp4Cipher extends AbstractMediaCipher {

    @Override
    public MediaFormat format() {
        return MediaFormat.MP4;
    }

    @Override
    protected EncryptPlan planEncrypt(Path input, MediaCryptProfile profile)
            throws MediaCryptException, IOException {
        if (profile != MediaCryptProfile.V_MDAT) {
            throw new MediaCryptException("MP4 当前仅实现 V-MDAT 档，档位: " + profile);
        }
        BoxParser parser = BoxParser.parse(input);
        Mp4Box mdat = parser.requireMdat();
        // 防御：mdat 必须是文件中的最后一个有数据的 box，或之后追加 uuid 不会破坏结构。
        List<ByteRange> ranges = List.of(new ByteRange(mdat.payloadOffset(), mdat.payloadSize()));
        return new EncryptPlan(ranges);
    }

    @Override
    protected void writeMetadata(Path output, MediaMetadata metadata, EncryptPlan plan)
            throws IOException {
        Mp4UuidMetadata.append(output, metadata.toBytes());
    }

    @Override
    protected DecryptPlan readMetadata(Path input, Path output)
            throws MediaCryptException, IOException {
        // 先用常规解析查找 uuid box。
        BoxParser parser = BoxParser.parse(input);
        Mp4Box uuidBox = parser.findMetaUuidBox(input);
        if (uuidBox == null) {
            // 回退：直接扫描文件末尾，兼容 mdat 使用 size==0 的源文件。
            // 此时 mdat 延伸至文件尾会吞并追加的 uuid box，导致 parser 的 box
            // 列表中不包含 uuid，必须通过原始字节扫描定位。
            uuidBox = BoxParser.scanForMetaUuidBox(input);
        }
        if (uuidBox == null) {
            throw new MediaCryptException("MP4 中未找到加密元数据（uuid box），可能不是本工具加密的文件");
        }
        byte[] metaBytes = Mp4UuidMetadata.readMetadata(input, uuidBox);
        MediaMetadata metadata = MediaMetadata.fromBytes(metaBytes);

        // 剥离 uuid box：保留 [0, uuidBox.boxOffset) 即原始容器（box 追加在末尾）。
        long keepLen = uuidBox.boxOffset();
        try (FileChannel in = FileChannel.open(input, StandardOpenOption.READ);
             FileChannel out = FileChannel.open(output, StandardOpenOption.CREATE,
                     StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING)) {
            long transferred = 0;
            while (transferred < keepLen) {
                long n = in.transferTo(transferred, keepLen - transferred, out);
                if (n <= 0) {
                    break;
                }
                transferred += n;
            }
            if (transferred != keepLen) {
                throw new IOException("剥离 MP4 uuid box 时复制不完整");
            }
        }

        BoxParser restored = BoxParser.parse(output);
        Mp4Box mdat = restored.requireMdat();
        List<ByteRange> ranges = List.of(new ByteRange(mdat.payloadOffset(), mdat.payloadSize()));
        return new DecryptPlan(metadata, ranges);
    }

    @Override
    public boolean isEncrypted(Path input) throws IOException {
        try {
            BoxParser parser = BoxParser.parse(input);
            if (parser.findMetaUuidBox(input) != null) {
                return true;
            }
            // 回退：兼容 mdat 使用 size==0 的加密文件。
            return BoxParser.scanForMetaUuidBox(input) != null;
        } catch (MediaCryptException e) {
            return false;
        }
    }
}
