package hbnu.project.ergoutreecrypt.mediacrypt;

import hbnu.project.ergoutreecrypt.exception.CryptoException;
import hbnu.project.ergoutreecrypt.exception.ErrorKind;

/**
 * 音视频加密子系统的受检异常基类。
 *
 * <p>用于区分"格式解析/加解密流程"中的可预期错误（如非法容器、密码错误、不支持的变体），
 * 便于 UI 层捕获并展示友好提示，而不与运行时编程错误混淆。默认归类为
 * {@link ErrorKind#UNSUPPORTED_FORMAT}，抛点可按语义覆盖（如完整性校验失败用
 * {@link ErrorKind#TAMPERED_DATA}、元数据魔数不符用 {@link ErrorKind#INVALID_HEADER}）。
 *
 * @author ErgouTree
 */
public class MediaCryptException extends CryptoException {

    /**
     * 构造默认归类为「格式不支持」的异常。
     *
     * @param message 诊断消息（进日志，不直接面向用户）
     */
    public MediaCryptException(String message) {
        super(ErrorKind.UNSUPPORTED_FORMAT, message);
    }

    /**
     * 构造默认归类为「格式不支持」的异常，并保留底层原因。
     *
     * @param message 诊断消息
     * @param cause   底层异常
     */
    public MediaCryptException(String message, Throwable cause) {
        super(ErrorKind.UNSUPPORTED_FORMAT, message, cause);
    }

    /**
     * 构造指定错误分类的异常，供抛点按语义覆盖默认分类。
     *
     * @param kind    错误分类
     * @param message 诊断消息
     */
    public MediaCryptException(ErrorKind kind, String message) {
        super(kind, message);
    }

    /**
     * 构造指定错误分类的异常，并保留底层原因。
     *
     * @param kind    错误分类
     * @param message 诊断消息
     * @param cause   底层异常
     */
    public MediaCryptException(ErrorKind kind, String message, Throwable cause) {
        super(kind, message, cause);
    }
}
