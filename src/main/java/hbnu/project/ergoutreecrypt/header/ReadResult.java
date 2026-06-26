package hbnu.project.ergoutreecrypt.header;

/**
 * Header 读取结果
 *
 * <p>即使 RS 解码出错也会返回 header（用于强行解密场景），通过 {@code decodeError}
 * 和相关布尔值指示损坏程度。
 *
 * @author ErgouTree
 */
public final class ReadResult {

    private final VolumeHeader header;
    private final Throwable decodeError;
    private final boolean commentDecodeError;
    private final boolean nonCommentDecodeError;
    private final int bytesRead;

    ReadResult(VolumeHeader header, Throwable decodeError,
               boolean commentDecodeError, boolean nonCommentDecodeError,
               int bytesRead) {
        this.header = header;
        this.decodeError = decodeError;
        this.commentDecodeError = commentDecodeError;
        this.nonCommentDecodeError = nonCommentDecodeError;
        this.bytesRead = bytesRead;
    }

    public VolumeHeader getHeader() { return header; }
    public Throwable getDecodeError() { return decodeError; }
    public boolean isCommentDecodeError() { return commentDecodeError; }
    public boolean isNonCommentDecodeError() { return nonCommentDecodeError; }
    public int getBytesRead() { return bytesRead; }

    @Override
    public String toString() {
        return "ReadResult{header=" + header
                + ", decodeError=" + decodeError
                + ", commentDecodeError=" + commentDecodeError
                + ", nonCommentDecodeError=" + nonCommentDecodeError
                + ", bytesRead=" + bytesRead + '}';
    }
}
