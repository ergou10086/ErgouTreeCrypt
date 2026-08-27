package hbnu.project.ergoutreecrypt.ui.support;

import hbnu.project.ergoutreecrypt.log.JvmDiagnostics;

import java.nio.file.Path;

/**
 * 桌面端 JVM 底层日志的开关胶水。
 *
 * <p>协调 {@link JvmDiagnostics} 与 {@link Slf4jJvmLog} 的启动顺序：先打开 Logback 文件，再安装诊断采集，关闭时相反。
 *
 * @author ErgouTree
 * @since 2026/8/27
 */
public final class JvmLogSupport {

    /** 镜像到 Logback 的接收器，进程内单例。 */
    private static final Slf4jJvmLog SLF4J_SINK = new Slf4jJvmLog();

    private JvmLogSupport() {
    }

    /**
     * 绑定日志目录。应在注册 {@link hbnu.project.ergoutreecrypt.log.LogService} 之前或同时调用。
     *
     * @param logsDir 日志目录
     * @return 可并入 {@link hbnu.project.ergoutreecrypt.log.CompositeLogSink} 的 SLF4J 接收器
     */
    public static Slf4jJvmLog bind(Path logsDir) {
        Slf4jJvmLog.bindDirectory(logsDir);
        return SLF4J_SINK;
    }

    /**
     * 按设置开启或关闭 JVM 底层日志。
     *
     * @param enabled true 开启
     */
    public static void apply(boolean enabled) {
        if (enabled) {
            Slf4jJvmLog.start();
            JvmDiagnostics.start();
        } else {
            JvmDiagnostics.stop();
            Slf4jJvmLog.stop();
        }
    }
}
