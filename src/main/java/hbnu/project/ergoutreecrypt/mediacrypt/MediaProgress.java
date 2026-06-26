package hbnu.project.ergoutreecrypt.mediacrypt;

/**
 * 音视频加解密的进度与取消回调。
 *
 * <p>由 UI 层实现并传入 {@link MediaCryptCodec}，加解密过程中会按块回调进度；
 * 加解密循环也会在每块检查 {@link #isCancelled()} 以支持中途取消。
 *
 * <p>所有方法都可能在<b>后台线程</b>被调用，UI 实现需自行切回 FX 线程更新界面。
 *
 * @author ErgouTree
 */
public interface MediaProgress {

    /** 不做任何事的空实现。 */
    MediaProgress NONE = new MediaProgress() {
        @Override
        public void onProgress(long processed, long total) {
        }

        @Override
        public boolean isCancelled() {
            return false;
        }
    };

    /**
     * 进度回调。
     *
     * @param processed 已处理的 payload 字节数
     * @param total     待处理 payload 总字节数（可能为 0）
     */
    void onProgress(long processed, long total);

    /**
     * 是否已请求取消。加解密循环每块检查；返回 true 时会尽快中止并抛出
     * {@link MediaCryptCancelledException}。
     */
    boolean isCancelled();
}
