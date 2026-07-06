package hbnu.project.ergoutreecrypt.stego;

/**
 * 图像隐写异常。
 *
 * <p>用于报告隐写操作中的各类错误：容量不足、格式不支持、魔数不匹配、密码错误等。
 *
 * @author ErgouTree
 */
public final class ImageStegoException extends Exception {

    /**
     * 构造带消息的异常。
     *
     * @param message 错误描述
     */
    public ImageStegoException(final String message) {
        super(message);
    }

    /**
     * 构造带消息和原因的异常。
     *
     * @param message 错误描述
     * @param cause   原始异常
     */
    public ImageStegoException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
