package hbnu.project.ergoutreecrypt.mediacrypt;

/**
 * 音视频加密子系统的受检异常基类。
 *
 * <p>用于区分"格式解析/加解密流程"中的可预期错误（如非法容器、密码错误、不支持的变体），
 * 便于 UI 层捕获并展示友好提示，而不与运行时编程错误混淆。
 *
 * @author ErgouTree
 */
public class MediaCryptException extends Exception {

    public MediaCryptException(String message) {
        super(message);
    }

    public MediaCryptException(String message, Throwable cause) {
        super(message, cause);
    }
}
