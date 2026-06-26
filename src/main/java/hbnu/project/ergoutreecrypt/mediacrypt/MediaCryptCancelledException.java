package hbnu.project.ergoutreecrypt.mediacrypt;

/**
 * 用户主动取消加解密时抛出。
 *
 * <p>继承自 {@link MediaCryptException}，便于上层统一捕获；UI 可据此类型与"真正的错误"区分处理
 * （取消通常不需要弹错误提示）。
 *
 * @author ErgouTree
 */
public final class MediaCryptCancelledException extends MediaCryptException {

    public MediaCryptCancelledException() {
        super("操作已取消");
    }
}
