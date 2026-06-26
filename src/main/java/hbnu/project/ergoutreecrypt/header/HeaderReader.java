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
 * 卷头读取器
 *
 * <p>从输入流中读取并 RS 解码卷头字段。即使 RS 解码出错也返回 header（用于强行解密场景），通过 {@link ReadResult} 的 decodeError 字段标明损坏程度。
 *
 * @author ErgouTree
 */
public final class HeaderReader {

    /** 错误：卷头损坏（RS 无法纠正）。 */
    public static final String ERR_CORRUPTED_HEADER = "volume header is damaged";
    /** 错误：version 格式非法。 */
    public static final String ERR_INVALID_VERSION = "invalid version format";
    /** 错误：注释长度字段损坏。 */
    public static final String ERR_INVALID_COMMENT_LENGTH = "unable to read comments length";

    /** 版本格式：{@code v<数字>.<两位数字>}。与 Go {@code ^v\d\.\d{2}$} 一致并锚定。 */
    private static final Pattern VERSION_RE = Pattern.compile("^v\\d\\.\\d{2}$");

    /** 注释长度格式：5 位十进制数字。 */
    private static final Pattern COMMENT_LEN_RE = Pattern.compile("^\\d{5}$");

    private final InputStream in;
    private final RsCodecs rs;

    public HeaderReader(InputStream in, RsCodecs rs) {
        this.in = in;
        this.rs = rs;
    }

    /**
     * 读取并 RS 解码完整卷头。对应 Go {@code Reader.ReadHeader()}。
     *
     * @return ReadResult 含解码后的 header 及错误信息
     * @throws IOException          I/O 错误（version/格式等致命错误也包装为 IOException）
     */
    public ReadResult readHeader() throws IOException {
        VolumeHeader h = new VolumeHeader();
        List<String> decodeErrors = new ArrayList<>();
        boolean commentDecodeError = false;
        boolean nonCommentDecodeError = false;
        int bytesRead = 0;

        // 1. version: 15→5 (RS5)
        byte[] versionEnc = new byte[HeaderLayout.VERSION_ENC_SIZE];
        int n = readFull(versionEnc);
        bytesRead += n;

        ReedSolomon.DecodeResult vd = ReedSolomon.decode(rs.rs5, versionEnc, false);
        if (vd.corrupted) {
            decodeErrors.add(ERR_CORRUPTED_HEADER);
            nonCommentDecodeError = true;
        }
        h.setVersion(new String(vd.data, StandardCharsets.UTF_8));

        // Validate version
        if (!matchVersion(vd.data)) {
            throw new IOException(ERR_INVALID_VERSION);
        }

        // 2. comment length: 15→5 (RS5)
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

        // D-02 defense-in-depth: cap to MaxCommentLen
        if (commentsLen < 0 || commentsLen > VolumeHeader.MAX_COMMENT_LEN) {
            throw new IOException(ERR_INVALID_COMMENT_LENGTH);
        }

        // 3. comments: each UTF-8 byte RS1(3→1)，收集所有字节后以 UTF-8 转回 String
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

        // 4. flags: 15→5 (RS5)
        byte[] flagsEnc = new byte[HeaderLayout.FLAGS_ENC_SIZE];
        n = readFull(flagsEnc);
        bytesRead += n;

        ReedSolomon.DecodeResult fd = ReedSolomon.decode(rs.rs5, flagsEnc, false);
        if (fd.corrupted) {
            decodeErrors.add(ERR_CORRUPTED_HEADER);
            nonCommentDecodeError = true;
        }
        h.setFlags(Flags.fromBytes(fd.data));

        // 5. salt: 48→16 (RS16)
        byte[] saltEnc = new byte[HeaderLayout.SALT_ENC_SIZE];
        n = readFull(saltEnc);
        bytesRead += n;

        ReedSolomon.DecodeResult sd = ReedSolomon.decode(rs.rs16, saltEnc, false);
        if (sd.corrupted) {
            decodeErrors.add(ERR_CORRUPTED_HEADER);
            nonCommentDecodeError = true;
        }
        h.setSalt(sd.data);

        // 6. hkdfSalt: 96→32 (RS32)
        byte[] hkdfSaltEnc = new byte[HeaderLayout.HKDF_SALT_ENC_SIZE];
        n = readFull(hkdfSaltEnc);
        bytesRead += n;

        ReedSolomon.DecodeResult hd = ReedSolomon.decode(rs.rs32, hkdfSaltEnc, false);
        if (hd.corrupted) {
            decodeErrors.add(ERR_CORRUPTED_HEADER);
            nonCommentDecodeError = true;
        }
        h.setHkdfSalt(hd.data);

        // 7. serpentIV: 48→16 (RS16)
        byte[] serpentIVEnc = new byte[HeaderLayout.SERPENT_IV_ENC_SIZE];
        n = readFull(serpentIVEnc);
        bytesRead += n;

        ReedSolomon.DecodeResult sid = ReedSolomon.decode(rs.rs16, serpentIVEnc, false);
        if (sid.corrupted) {
            decodeErrors.add(ERR_CORRUPTED_HEADER);
            nonCommentDecodeError = true;
        }
        h.setSerpentIV(sid.data);

        // 8. nonce: 72→24 (RS24)
        byte[] nonceEnc = new byte[HeaderLayout.NONCE_ENC_SIZE];
        n = readFull(nonceEnc);
        bytesRead += n;

        ReedSolomon.DecodeResult nd = ReedSolomon.decode(rs.rs24, nonceEnc, false);
        if (nd.corrupted) {
            decodeErrors.add(ERR_CORRUPTED_HEADER);
            nonCommentDecodeError = true;
        }
        h.setNonce(nd.data);

        // 9. keyHash: 192→64 (RS64)
        byte[] keyHashEnc = new byte[HeaderLayout.KEY_HASH_ENC_SIZE];
        n = readFull(keyHashEnc);
        bytesRead += n;

        ReedSolomon.DecodeResult khd = ReedSolomon.decode(rs.rs64, keyHashEnc, false);
        if (khd.corrupted) {
            decodeErrors.add(ERR_CORRUPTED_HEADER);
            nonCommentDecodeError = true;
        }
        h.setKeyHash(khd.data);

        // 10. keyfileHash: 96→32 (RS32)
        byte[] keyfileHashEnc = new byte[HeaderLayout.KEYFILE_HASH_ENC_SIZE];
        n = readFull(keyfileHashEnc);
        bytesRead += n;

        ReedSolomon.DecodeResult kfhd = ReedSolomon.decode(rs.rs32, keyfileHashEnc, false);
        if (kfhd.corrupted) {
            decodeErrors.add(ERR_CORRUPTED_HEADER);
            nonCommentDecodeError = true;
        }
        h.setKeyfileHash(kfhd.data);

        // 11. authTag: 192→64 (RS64)
        byte[] authTagEnc = new byte[HeaderLayout.AUTH_TAG_ENC_SIZE];
        n = readFull(authTagEnc);
        bytesRead += n;

        ReedSolomon.DecodeResult atd = ReedSolomon.decode(rs.rs64, authTagEnc, false);
        if (atd.corrupted) {
            decodeErrors.add(ERR_CORRUPTED_HEADER);
            nonCommentDecodeError = true;
        }
        h.setAuthTag(atd.data);

        // Assemble result
        Throwable error = decodeErrors.isEmpty() ? null
                : new RuntimeException(String.join("; ", decodeErrors));

        return new ReadResult(h, error, commentDecodeError, nonCommentDecodeError, bytesRead);
    }

    /**
     * 仅读取 version 字段以判断文件格式。对应 Go {@code PeekVersion}。
     *
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
     * 检查版本字符串是否匹配格式 {@code v\d.\d\d}。与 Go {@code MatchVersion} 对应。
     */
    public static boolean matchVersion(byte[] b) {
        return VERSION_RE.matcher(new String(b, StandardCharsets.UTF_8)).matches();
    }

    /** 读满整个缓冲区，遇到 EOF 抛出异常。 */
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
