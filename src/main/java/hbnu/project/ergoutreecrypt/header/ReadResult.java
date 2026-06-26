package hbnu.project.ergoutreecrypt.header;

/**
 * Header 读取结果容器。
 *
 * <p>即使 RS 解码出错也会返回 header（用于强行解密场景），通过 {@code decodeError}、
 * {@code commentDecodeError} 和 {@code nonCommentDecodeError} 区分损坏类型与程度。
 *
 * @author ErgouTree
 */
public final class ReadResult {

    /**
     * 解码后的卷头数据。
     */
    private final VolumeHeader header;

    /**
     * RS 解码错误（可为 null，表示无错误）。
     */
    private final Throwable decodeError;

    /**
     * 注释字段是否发生解码错误。
     */
    private final boolean commentDecodeError;

    /**
     * 非注释字段是否发生解码错误。
     */
    private final boolean nonCommentDecodeError;

    /**
     * 已读取的 header 总字节数。
     */
    private final int bytesRead;

    /**
     * @param header               解码后的卷头
     * @param decodeError          RS 解码错误（可为 null）
     * @param commentDecodeError   注释解码错误标志
     * @param nonCommentDecodeError 非注释解码错误标志
     * @param bytesRead            已读字节数
     */
    ReadResult(VolumeHeader header, Throwable decodeError,
               boolean commentDecodeError, boolean nonCommentDecodeError,
               int bytesRead) {
        this.header = header;
        this.decodeError = decodeError;
        this.commentDecodeError = commentDecodeError;
        this.nonCommentDecodeError = nonCommentDecodeError;
        this.bytesRead = bytesRead;
    }

    /**
     * 返回解码后的卷头。
     */
    public VolumeHeader getHeader() { return header; }

    /**
     * 返回 RS 解码错误（可为 null）。
     */
    public Throwable getDecodeError() { return decodeError; }

    /**
     * 注释字段是否发生解码错误。
     */
    public boolean isCommentDecodeError() { return commentDecodeError; }

    /**
     * 非注释字段是否发生解码错误。
     */
    public boolean isNonCommentDecodeError() { return nonCommentDecodeError; }

    /**
     * 已读取的 header 总字节数。
     */
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
