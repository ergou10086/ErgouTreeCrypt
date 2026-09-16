package hbnu.project.ergoutreecrypt.imagecrypt;

/**
 * 图片加解密的阶段、进度与取消回调。
 *
 * <p>由 UI 层实现并传入图片加解密门面，核心在阶段切换与每块处理完成后回调。
 * 同时承载阶段、已处理字节、总字节与取消状态，避免 UI 维护第二份流程状态。
 *
 * <p>所有方法都可能在后<b>台线程</b>被调用，UI 实现需自行切回界面线程更新视图。
 *
 * @author ErgouTree
 * @since 2026/9/15
 */
public interface ImageCryptProgress {

    /**
     * 不做任何事、永不取消的空实现（桌面端与测试的默认值）。
     */
    ImageCryptProgress NONE = new ImageCryptProgress() {

        @Override
        public void onPhase(final ImageCryptPhase phase) {
        }

        @Override
        public void onBytes(final long processed, final long total) {
        }

        @Override
        public boolean isCancelled() {
            return false;
        }
    };

    /**
     * 进入新阶段时回调一次。
     *
     * @param phase 新阶段
     */
    void onPhase(ImageCryptPhase phase);

    /**
     * 处理进度回调。
     *
     * @param processed 已处理的载荷字节数
     * @param total     待处理载荷总字节数（未知时为 0）
     */
    void onBytes(long processed, long total);

    /**
     * 密码模式的 Argon2id pass 进度回调。
     *
     * <p>专门与 {@link #onBytes(long, long)} 分开，避免 UI 把 pass 计数当成字节数显示。
     * KDF 阶段没有线性字节进度，界面应呈现为不定进度或 {@code 已完成 pass / 总 pass}。
     * 公开恢复模式不执行 Argon2，因此永远不会收到该回调。
     *
     * @param completedPasses 已完成的 pass 数，从 1 开始
     * @param totalPasses     总 pass 数
     */
    default void onKdfPass(int completedPasses, int totalPasses) {
    }

    /**
     * 是否已请求取消。
     *
     * <p>核心在 I/O 循环中每块检查一次（间隔不超过 1 MiB），返回 true 时尽快中止并抛出
     * {@code CancelledException}，同时删除尚未提交的临时文件。
     *
     * @return true 表示应尽快中止
     */
    boolean isCancelled();
}
