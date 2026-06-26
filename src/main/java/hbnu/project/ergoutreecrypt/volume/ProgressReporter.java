package hbnu.project.ergoutreecrypt.volume;

/**
 * 进度回调接口，对应 Go {@code internal/volume/context.go} 的 ProgressReporter。
 * 实现须线程安全。
 *
 * @author ErgouTree
 * @since 2026/6/17
 */
public interface ProgressReporter {

    void setStatus(String text);

    void setProgress(float fraction, String info);

    void setCanCancel(boolean can);

    default void update() {}

    boolean isCancelled();
}
