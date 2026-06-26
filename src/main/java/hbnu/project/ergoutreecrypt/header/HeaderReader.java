package hbnu.project.ergoutreecrypt.header;

import hbnu.project.ergoutreecrypt.encoding.ReedSolomon;
import hbnu.project.ergoutreecrypt.encoding.RsCodecs;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * 卷头读取器。
 *
 * <p>从输入流中按序读取并 RS 解码卷头的各字段。即使 RS 解码出错也尽可能返回 header
 * （用于强行解密场景），通过 {@link ReadResult} 的 decodeError 字段标明损坏类型与程度。
 *
 * @author ErgouTree
 */
public final class HeaderReader {

    /**
     * 错误信息：卷头损坏（RS 无法纠正）。
     */
    public static final String ERR_CORRUPTED_HEADER = "volume header is damaged";

    /**
     * 错误信息：version 格式非法。
     */
    public static final String ERR_INVALID_VERSION = "invalid version format";

    /**
     * 错误信息：注释长度字段损坏。
     */
    public static final String ERR_INVALID_COMMENT_LENGTH = "unable to read comments length";

    /**
     * 版本格式正则：{@code v<数字>.<两位数字>}，与 Go 端 {@code ^v\d\.\d{2}$} 一致并锚定。
     */
    private static final Pattern VERSION_RE = Pattern.compile("^v\\d\\.\\d{2}$");

    /**
     * 注释长度格式：5 位十进制数字。
     */
    private static final Pattern COMMENT_LEN_RE = Pattern.compile("^\\d{5}$");

    /**
     * 输入流，从中顺序读取 header 各字段。
     */
    private final InputStream in;

    /**
     * 预初始化的 RS 编解码器。
     */
    private final RsCodecs rs;

    /**
     * @param in header 数据的输入流
     * @param rs 预初始化的 RS 编解码器集合
     */
    public HeaderReader(InputStream in, RsCodecs rs) {
        this.in = in;
        this.rs = rs;
    }

    /**
     * 读取并 RS 解码完整卷头。
     *
     * <p>依次读取 version、注释长度、注释、flags、salt、hkdfSalt、serpentIV、nonce、
     * keyHash、keyfileHash、authTag 共 11 个字段，每个字段先 RS 解码再赋值。
     *
     * @return 含解码后 header 及错误详情的 ReadResult
     * @throws IOException 致命 I/O 错误或非法 version/注释格式
     */
    public ReadResult readHeader() throws IOException {
        VolumeHeader h = new VolumeHeader();
        List<String> decodeErrors = new ArrayList<>();
        boolean commentDecodeError = false;
        boolean nonCommentDecodeError = false;
        int bytesRead = 0;

        // 1. version: RS5(15→5)
        byte[] versionEnc = new byte[HeaderLayout.VERSION_ENC_SIZE];
        int n = readFull(versionEnc);
        bytesRead += n;

        ReedSolomon.DecodeResult vd = ReedSolomon.decode(rs.rs5, versionEnc, false);
        if (vd.corrupted) {
            decodeErrors.add(ERR_CORRUPTED_HEADER);
            nonCommentDecodeError = true;
        }
        h.setVersion(new String(vd.data, StandardCharsets.UTF_8));

        if (!matchVersion(vd.data)) {
            throw new IOException(ERR_INVALID_VERSION);
        }

        // 2. comment length: RS5(15→5)
        byte[] commentLenEnc = new byte[HeaderLayout.COMMENT_LEN_ENC_SIZE];
        n = readFull(commentLenEnc);
        bytesRead += n;

        ReedSolomon.DecodeResult cld = ReedSolomon.decode(rs.rs5, commentLenEnc, false);
        if (cld.corrupted) {
            decodeErrors.add(ERR_CORRUPTED_HEADER);
            nonCommentDecodeError = true;
        }

        String commentLenStr = new String(cld.data, StandardCharsets.UTF_8);
        if (!COMMENT_LEN_RE.matcher(commentLenStr).matches()) {
            throw new IOException(ERR_INVALID_COMMENT_LENGTH);
        }

        int commentsLen;
        try {
            commentsLen = Integer.parseInt(commentLenStr);
        } catch (NumberFormatException e) {
            throw new IOException(ERR_INVALID_COMMENT_LENGTH);
        }

        // 防御上限检查
        if (commentsLen < 0 || commentsLen > VolumeHeader.MAX_COMMENT_LEN) {
            throw new IOException(ERR_INVALID_COMMENT_LENGTH);
        }

        // 3. comments: 每个 UTF-8 字节 RS1(3→1)，收集后以 UTF-8 转为字符串
        byte[] commentBytes = new byte[commentsLen];
        for (int i = 0; i < commentsLen; i++) {
            byte[] charEnc = new byte[HeaderLayout.COMMENT_CHAR_ENC_SIZE];
            n = readFull(charEnc);
            bytesRead += n;

            ReedSolomon.DecodeResult cd = ReedSolomon.decode(rs.rs1, charEnc, false);
            if (cd.corrupted) {
                decodeErrors.add(ERR_CORRUPTED_HEADER);
                commentDecodeError = true;
            }
            commentBytes[i] = cd.data.length > 0 ? cd.data[0] : 0;
        }
        h.setComments(new String(commentBytes, StandardCharsets.UTF_8));

        // 4. flags: RS5(15→5)
        byte[] flagsEnc = new byte[HeaderLayout.FLAGS_ENC_SIZE];
        n = readFull(flagsEnc);
        bytesRead += n;

        ReedSolomon.DecodeResult fd = ReedSolomon.decode(rs.rs5, flagsEnc, false);
        if (fd.corrupted) {
            decodeErrors.add(ERR_CORRUPTED_HEADER);
            nonCommentDecodeError = true;
        }
        h.setFlags(Flags.fromBytes(fd.data));

        // 5. salt: RS16(48→16)
        byte[] saltEnc = new byte[HeaderLayout.SALT_ENC_SIZE];
        n = readFull(saltEnc);
        bytesRead += n;

        ReedSolomon.DecodeResult sd = ReedSolomon.decode(rs.rs16, saltEnc, false);
        if (sd.corrupted) {
            decodeErrors.add(ERR_CORRUPTED_HEADER);
            nonCommentDecodeError = true;
        }
        h.setSalt(sd.data);

        // 6. hkdfSalt: RS32(96→32)
        byte[] hkdfSaltEnc = new byte[HeaderLayout.HKDF_SALT_ENC_SIZE];
        n = readFull(hkdfSaltEnc);
        bytesRead += n;

        ReedSolomon.DecodeResult hd = ReedSolomon.decode(rs.rs32, hkdfSaltEnc, false);
        if (hd.corrupted) {
            decodeErrors.add(ERR_CORRUPTED_HEADER);
            nonCommentDecodeError = true;
        }
        h.setHkdfSalt(hd.data);

        // 7. serpentIV: RS16(48→16)
        byte[] serpentIVEnc = new byte[HeaderLayout.SERPENT_IV_ENC_SIZE];
        n = readFull(serpentIVEnc);
        bytesRead += n;

        ReedSolomon.DecodeResult sid = ReedSolomon.decode(rs.rs16, serpentIVEnc, false);
        if (sid.corrupted) {
            decodeErrors.add(ERR_CORRUPTED_HEADER);
            nonCommentDecodeError = true;
        }
        h.setSerpentIV(sid.data);

        // 8. nonce: RS24(72→24)
        byte[] nonceEnc = new byte[HeaderLayout.NONCE_ENC_SIZE];
        n = readFull(nonceEnc);
        bytesRead += n;

        ReedSolomon.DecodeResult nd = ReedSolomon.decode(rs.rs24, nonceEnc, false);
        if (nd.corrupted) {
            decodeErrors.add(ERR_CORRUPTED_HEADER);
            nonCommentDecodeError = true;
        }
        h.setNonce(nd.data);

        // 9. keyHash: RS64(192→64)
        byte[] keyHashEnc = new byte[HeaderLayout.KEY_HASH_ENC_SIZE];
        n = readFull(keyHashEnc);
        bytesRead += n;

        ReedSolomon.DecodeResult khd = ReedSolomon.decode(rs.rs64, keyHashEnc, false);
        if (khd.corrupted) {
            decodeErrors.add(ERR_CORRUPTED_HEADER);
            nonCommentDecodeError = true;
        }
        h.setKeyHash(khd.data);

        // 10. keyfileHash: RS32(96→32)
        byte[] keyfileHashEnc = new byte[HeaderLayout.KEYFILE_HASH_ENC_SIZE];
        n = readFull(keyfileHashEnc);
        bytesRead += n;

        ReedSolomon.DecodeResult kfhd = ReedSolomon.decode(rs.rs32, keyfileHashEnc, false);
        if (kfhd.corrupted) {
            decodeErrors.add(ERR_CORRUPTED_HEADER);
            nonCommentDecodeError = true;
        }
        h.setKeyfileHash(kfhd.data);

        // 11. authTag: RS64(192→64)
        byte[] authTagEnc = new byte[HeaderLayout.AUTH_TAG_ENC_SIZE];
        n = readFull(authTagEnc);
        bytesRead += n;

        ReedSolomon.DecodeResult atd = ReedSolomon.decode(rs.rs64, authTagEnc, false);
        if (atd.corrupted) {
            decodeErrors.add(ERR_CORRUPTED_HEADER);
            nonCommentDecodeError = true;
        }
        h.setAuthTag(atd.data);

        // 汇总错误信息
        Throwable error = decodeErrors.isEmpty() ? null
                : new RuntimeException(String.join("; ", decodeErrors));

        return new ReadResult(h, error, commentDecodeError, nonCommentDecodeError, bytesRead);
    }

    /**
     * 仅读取 version 字段以快速判断文件格式（不消费后续数据）。
     *
     * @param in header 数据的输入流
     * @param rs 预初始化的 RS 编解码器集合
     * @return version 字符串（如 "v2.14"）
     * @throws IOException I/O 错误或 RS 解码失败
     */
    public static String peekVersion(InputStream in, RsCodecs rs) throws IOException {
        byte[] versionEnc = new byte[HeaderLayout.VERSION_ENC_SIZE];
        if (in.read(versionEnc) != versionEnc.length) {
            throw new EOFException("read version: unexpected EOF");
        }
        ReedSolomon.DecodeResult vd = ReedSolomon.decode(rs.rs5, versionEnc, false);
        if (vd.corrupted) {
            throw new IOException(ERR_CORRUPTED_HEADER);
        }
        return new String(vd.data, StandardCharsets.UTF_8);
    }

    /**
     * 检查 version 字节是否匹配格式 {@code v\d.\d\d}。
     *
     * @param b 解码后的 version 字节
     * @return 若匹配格式则返回 true
     */
    public static boolean matchVersion(byte[] b) {
        return VERSION_RE.matcher(new String(b, StandardCharsets.UTF_8)).matches();
    }

    /**
     * 读满整个缓冲区，不足时阻塞等待，遇到 EOF 则抛出异常。
     */
    private int readFull(byte[] buf) throws IOException {
        int offset = 0;
        int len = buf.length;
        while (offset < len) {
            int n = in.read(buf, offset, len - offset);
            if (n < 0) {
                throw new EOFException("unexpected EOF at byte " + offset + " of " + len);
            }
            offset += n;
        }
        return offset;
    }
}
