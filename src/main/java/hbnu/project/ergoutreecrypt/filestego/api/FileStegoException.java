package hbnu.project.ergoutreecrypt.filestego.api;

/**
 * 文件隐写异常——在文件隐写的整体流程中发生的错误。
 *
 * <p>这是 {@code FileStegoCodec} 对外抛出的统一异常类型，内部可能包装
 * {@link CarrierException} 或 {@link PayloadException} 等子层异常。
 *
 * @author ErgouTree
 * @since 2026/8/5
 */
public class FileStegoException extends Exception {

    /**
     * 创建携带错误消息的文件隐写异常。
     *
     * @param message 错误描述
     */
    public FileStegoException(final String message) {
        super(message);
    }

    /**
     * 创建携带错误消息和原因的文件隐写异常。
     *
     * @param message 错误描述
     * @param cause   底层异常
     */
    public FileStegoException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
