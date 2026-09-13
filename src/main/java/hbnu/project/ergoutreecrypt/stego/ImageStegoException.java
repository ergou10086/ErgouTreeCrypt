package hbnu.project.ergoutreecrypt.stego;

import hbnu.project.ergoutreecrypt.exception.CryptoException;
import hbnu.project.ergoutreecrypt.exception.ErrorKind;

/**
 * 图像隐写异常。
 *
 * <p>用于报告隐写操作中的各类错误：容量不足、格式不支持、魔数不匹配、密码错误等。
 * 默认归类为 {@link ErrorKind#INTERNAL_ERROR}，抛点可按语义覆盖。
 *
 * @author ErgouTree
 */
public final class ImageStegoException extends CryptoException {

    /**
     * 构造带消息的异常。
     *
     * @param message 错误描述
     */
    public ImageStegoException(final String message) {
        super(ErrorKind.INTERNAL_ERROR, message);
    }

    /**
     * 构造带消息和原因的异常。
     *
     * @param message 错误描述
     * @param cause   原始异常
     */
    public ImageStegoException(final String message, final Throwable cause) {
        super(ErrorKind.INTERNAL_ERROR, message, cause);
    }
}
