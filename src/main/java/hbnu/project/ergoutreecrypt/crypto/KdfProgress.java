package hbnu.project.ergoutreecrypt.crypto;

/**
 * Argon2 密钥派生的进度与取消回调。
 *
 * <p>移动端解密桌面端 1 GiB 参数文件时，离堆派生可能持续数分钟，通过本接口把
 * 派生进度（pass 粒度）与取消信号回传 UI，避免"卡在 0% 不动"或无法中止。
 * 桌面端不传（{@code null}），派生行为与既有版本完全一致。
 *
 * @author ErgouTree
 * @since 2026/8/28
 */
public interface KdfProgress {

    /**
     * 每完成一个 pass 后回调一次。
     *
     * @param pass        已完成（含当前）的 pass 序号，从 1 开始
     * @param totalPasses 总 pass 数
     */
    void onProgress(int pass, int totalPasses);

    /**
     * 每完成一个 slice（一个 pass 的 1/4）回调一次，供更细粒度进度展示。
     *
     * <p>默认空实现，既有只关心 pass 粒度的实现无需改动即可编译。
     *
     * @param doneSlices  已完成（含当前）的 slice 序号，从 1 开始
     * @param totalSlices 总 slice 数（passes × 4）
     */
    default void onSliceProgress(int doneSlices, int totalSlices) {
    }

    /**
     * 是否请求取消派生。
     *
     * @return true 表示应尽快中止派生
     */
    boolean isCancelled();
}
