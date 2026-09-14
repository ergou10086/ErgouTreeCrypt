package hbnu.project.ergoutreecrypt.filestego.api;

import hbnu.project.ergoutreecrypt.exception.CryptoException;
import hbnu.project.ergoutreecrypt.exception.ErrorKind;

/**
 * 文件隐写异常——在文件隐写的整体流程中发生的错误。
 *
 * <p>这是 {@code FileStegoCodec} 对外抛出的统一异常类型，内部可能包装
 * {@link CarrierException} 或 {@link PayloadException} 等子层异常。默认归类为
 * {@link ErrorKind#INTERNAL_ERROR}，抛点应按语义覆盖为更精确的分类（如载体不识别用
 * {@link ErrorKind#UNSUPPORTED_FORMAT}、容量不足用 {@link ErrorKind#CAPACITY_INSUFFICIENT}、
 * 未检测到隐写数据用 {@link ErrorKind#NO_STEGO_DATA}），否则前端只能展示兜底的
 * 「发生内部错误」，用户无从判断该换文件还是该换选项。
 *
 * @author ErgouTree
 * @since 2026/8/5
 */
public class FileStegoException extends CryptoException {

    /**
     * 创建携带错误消息的文件隐写异常（默认归类为内部错误）。
     *
     * @param message 错误描述
     */
    public FileStegoException(final String message) {
        super(ErrorKind.INTERNAL_ERROR, message);
    }

    /**
     * 创建携带错误消息和原因的文件隐写异常（默认归类为内部错误）。
     *
     * @param message 错误描述
     * @param cause   底层异常
     */
    public FileStegoException(final String message, final Throwable cause) {
        super(ErrorKind.INTERNAL_ERROR, message, cause);
    }

    /**
     * 创建指定错误分类的文件隐写异常。
     *
     * @param kind    错误分类
     * @param message 错误描述（进日志，不直接面向用户）
     */
    public FileStegoException(final ErrorKind kind, final String message) {
        super(kind, message);
    }

    /**
     * 创建指定错误分类的文件隐写异常，并携带 i18n 格式化参数。
     *
     * <p>参数供 {@code ExceptionMapper} 在展示阶段拼入对应文案，例如容量不足的
     * 「需要 / 可用」两个尺寸值。
     *
     * @param kind    错误分类
     * @param message 错误描述（进日志）
     * @param args    i18n 格式化参数
     */
    public FileStegoException(final ErrorKind kind, final String message, final Object... args) {
        super(kind, message, args);
    }

    /**
     * 创建指定错误分类的文件隐写异常，并保留底层原因。
     *
     * @param kind    错误分类
     * @param message 错误描述
     * @param cause   底层异常
     */
    public FileStegoException(final ErrorKind kind, final String message, final Throwable cause) {
        super(kind, message, cause);
    }
}
