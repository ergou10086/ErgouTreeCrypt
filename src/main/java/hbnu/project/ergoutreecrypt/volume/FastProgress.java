package hbnu.project.ergoutreecrypt.volume;

import hbnu.project.ergoutreecrypt.crypto.KdfProgress;
import hbnu.project.ergoutreecrypt.exception.CancelledException;

/** 将两类取消回调合并，并限制载荷进度刷新频率。 */
final class FastProgress implements KdfProgress {
    private final ProgressReporter reporter;
    private final KdfProgress kdf;
    private long lastUpdate;

    /**
     * 保存本次请求的回调快照。
     *
     * @param reporter 任务回调
     * @param kdf KDF 回调
     */
    FastProgress(ProgressReporter reporter, KdfProgress kdf) {
        this.reporter = reporter;
        this.kdf = kdf;
    }

    /** @return 任一回调或线程是否取消 */
    @Override
    public boolean isCancelled() {
        return Thread.currentThread().isInterrupted()
                || reporter != null && reporter.isCancelled()
                || kdf != null && kdf.isCancelled();
    }

    /** @throws CancelledException 任务已取消 */
    void checkCancelled() throws CancelledException {
        if (isCancelled()) throw new CancelledException();
    }

    /**
     * 转发 KDF 整轮进度。
     *
     * @param pass 已完成轮次
     * @param total 总轮次
     */
    @Override
    public void onProgress(int pass, int total) {
        if (kdf != null) kdf.onProgress(pass, total);
    }

    /**
     * 转发已有 KDF 实现提供的细粒度进度。
     *
     * @param done 已完成片数
     * @param total 总片数
     */
    @Override
    public void onSliceProgress(int done, int total) {
        if (kdf != null) kdf.onSliceProgress(done, total);
    }

    /**
     * 发送状态并立即检查取消。
     *
     * @param text 本地化状态
     * @throws CancelledException 任务已取消
     */
    void status(String text) throws CancelledException {
        checkCancelled();
        if (reporter != null) {
            reporter.setStatus(text);
            reporter.update();
        }
        checkCancelled();
    }

    /**
     * 每 100 毫秒更新一次载荷进度，完成状态单独发送。
     *
     * @param done 已处理字节
     * @param total 总字节
     * @throws CancelledException 任务已取消
     */
    void update(long done, long total) throws CancelledException {
        checkCancelled();
        long now = System.nanoTime();
        if (reporter != null && now - lastUpdate >= 100_000_000L) {
            reporter.setProgress(total == 0 ? 0 : Math.min(0.99f, (float) done / total), "");
            lastUpdate = now;
        }
        checkCancelled();
    }

    /** @throws CancelledException 最终提交前任务已取消 */
    void finish() throws CancelledException {
        checkCancelled();
        if (reporter != null) reporter.setProgress(1, "");
        checkCancelled();
    }
}
