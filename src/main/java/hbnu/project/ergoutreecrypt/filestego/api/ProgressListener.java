package hbnu.project.ergoutreecrypt.filestego.api;

/**
 * 文件隐写进度监听器——接收处理过程中按实际已处理字节比例计算的进度回调。
 *
 * <p>回调在调用 {@code FileStegoCodec.hide/extract} 的工作线程上执行，
 * 频率约为每处理 1 MiB 数据一次；实现应保证回调本身轻量且线程安全，
 * 界面层应自行将进度转发到 UI 线程（如 StateFlow / Platform.runLater）。
 *
 * @author ErgouTree
 * @since 2026/8/14
 */
@FunctionalInterface
public interface ProgressListener {

    /**
     * 进度更新回调。
     *
     * @param fraction 总体完成比例（0.0~1.0，随处理推进单调不减）
     */
    void onProgress(double fraction);
}
