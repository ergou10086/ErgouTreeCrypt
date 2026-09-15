package hbnu.project.ergoutreecrypt.imagecrypt;

import hbnu.project.ergoutreecrypt.exception.CryptoException;
import hbnu.project.ergoutreecrypt.exception.ErrorKind;

/**
 * 图片加密子系统的受检异常。
 *
 * <p>用于区分"协议解析 / 帧校验 / 密钥编排"中的可预期错误（非法帧、未知版本、
 * 非规范 KDF 组合、密码错误、载荷损坏），便于 UI 层通过 {@link ErrorKind} 做类型化
 * 映射，而不与运行时编程错误混淆。
 *
 * <p>默认归类为 {@link ErrorKind#UNSUPPORTED_FORMAT}，抛点应按语义覆盖：
 * 密码模式 keyConfirm 失败用 {@link ErrorKind#WRONG_PASSWORD}，MAC 失败用
 * {@link ErrorKind#TAMPERED_DATA}，未知协议版本用 {@link ErrorKind#UNSUPPORTED_VERSION}，
 * 输入不是 EGTC-IMG 用 {@link ErrorKind#NOT_IMAGE_CRYPT}。
 *
 * @author ErgouTree
 * @since 2026/9/15
 */
public class ImageCryptException extends CryptoException {

    /**
     * 构造默认归类为「格式不支持」的异常。
     *
     * @param message 诊断消息（进日志，不直接面向用户）
     */
    public ImageCryptException(final String message) {
        super(ErrorKind.UNSUPPORTED_FORMAT, message);
    }

    /**
     * 构造默认归类为「格式不支持」的异常，并保留底层原因。
     *
     * @param message 诊断消息
     * @param cause   底层异常
     */
    public ImageCryptException(final String message, final Throwable cause) {
        super(ErrorKind.UNSUPPORTED_FORMAT, message, cause);
    }

    /**
     * 构造指定错误分类的异常，供抛点按语义覆盖默认分类。
     *
     * @param kind    错误分类
     * @param message 诊断消息
     */
    public ImageCryptException(final ErrorKind kind, final String message) {
        super(kind, message);
    }

    /**
     * 构造指定错误分类的异常，并保留底层原因。
     *
     * @param kind    错误分类
     * @param message 诊断消息
     * @param cause   底层异常
     */
    public ImageCryptException(final ErrorKind kind, final String message, final Throwable cause) {
        super(kind, message, cause);
    }
}
