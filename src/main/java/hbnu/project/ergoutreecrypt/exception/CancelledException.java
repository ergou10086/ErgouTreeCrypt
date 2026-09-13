package hbnu.project.ergoutreecrypt.exception;

/**
 * 用户主动取消加解密时抛出。
 *
 * <p>固定映射到 {@link ErrorKind#CANCELLED}。统一替代历史代码中散落的
 * {@code InterruptedException("cancelled")} 与 {@code MediaCryptCancelledException}，
 * 前端通过 {@link ExceptionMapper#isCancellation(Throwable)} 一次识别「取消」，从而
 * 不弹出错误提示。
 *
 * @author ErgouTree
 * @since 2026/9/13
 */
public class CancelledException extends CryptoException {

    /**
     * 构造取消异常。
     */
    public CancelledException() {
        super(ErrorKind.CANCELLED, "操作已取消");
    }

    /**
     * 构造带诊断消息的取消异常。
     *
     * @param message 诊断消息
     */
    public CancelledException(String message) {
        super(ErrorKind.CANCELLED, message);
    }
}
