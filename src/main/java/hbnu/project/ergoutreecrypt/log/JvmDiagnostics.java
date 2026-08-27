package hbnu.project.ergoutreecrypt.log;

import java.lang.reflect.Method;
import java.util.List;

/**
 * JVM 层诊断采集。
 *
 * <p>默认关闭。开启后记录堆快照、GC 累计次数/耗时，并把未捕获异常写入 {@link LogService}。
 * 实现仅依赖 JDK 反射探测 MXBean，Android 上缺失 {@code java.management} 时自动降级为
 * {@link Runtime} 堆信息，不引入 SLF4J / Logback（桌面端由独立模块接入）。
 *
 * @author ErgouTree
 * @since 2026/8/27
 */
public final class JvmDiagnostics {

    /** 当前是否已开启。 */
    private static volatile boolean enabled;

    /** 开启前的默认未捕获异常处理器，关闭时还原。 */
    private static volatile Thread.UncaughtExceptionHandler previousHandler;

    private JvmDiagnostics() {
    }

    /**
     * 诊断是否处于开启状态。
     *
     * @return 已开启时返回 {@code true}
     */
    public static boolean isEnabled() {
        return enabled;
    }

    /**
     * 开启 JVM 诊断：安装未捕获异常处理器并写入环境与堆快照。
     *
     * <p>重复调用是空操作。
     */
    public static synchronized void start() {
        if (enabled) {
            return;
        }
        enabled = true;
        previousHandler = Thread.getDefaultUncaughtExceptionHandler();
        Thread.setDefaultUncaughtExceptionHandler((thread, error) -> {
            try {
                String name = thread == null ? "?" : thread.getName();
                LogService.error("JVM", "uncaught in " + name, error);
            } catch (Throwable ignored) {
                // 诊断日志失败不得覆盖原始错误
            }
            Thread.UncaughtExceptionHandler previous = previousHandler;
            if (previous != null) {
                previous.uncaughtException(thread, error);
            }
        });
        LogService.info("JVM", environmentLine());
        logSnapshot("diagnostics on");
    }

    /**
     * 关闭 JVM 诊断并还原未捕获异常处理器。
     *
     * <p>未开启时是空操作。
     */
    public static synchronized void stop() {
        if (!enabled) {
            return;
        }
        logSnapshot("diagnostics off");
        enabled = false;
        Thread.setDefaultUncaughtExceptionHandler(previousHandler);
        previousHandler = null;
    }

    /**
     * 安静关闭：不写日志。供测试复位使用。
     */
    public static synchronized void stopQuiet() {
        if (!enabled) {
            return;
        }
        enabled = false;
        Thread.setDefaultUncaughtExceptionHandler(previousHandler);
        previousHandler = null;
    }

    /**
     * 在会话边界写入一条堆/GC 快照。未开启时忽略。
     *
     * @param phase 阶段标签，如 {@code session-begin}
     */
    public static void logSnapshot(String phase) {
        if (!enabled) {
            return;
        }
        String label = (phase == null || phase.isBlank()) ? "snapshot" : phase;
        LogService.info("JVM", label + " | " + snapshot());
    }

    /**
     * 当前堆与 GC 快照（开启状态无关，始终可调用）。
     *
     * @return 适合单行阅读的快照文本
     */
    public static String snapshot() {
        Runtime rt = Runtime.getRuntime();
        long max = rt.maxMemory();
        long committed = rt.totalMemory();
        long used = committed - rt.freeMemory();
        int pct = max > 0 ? (int) (used * 100L / max) : 0;
        StringBuilder sb = new StringBuilder(192);
        sb.append("heap used=").append(LogService.humanSize(used));
        sb.append(" committed=").append(LogService.humanSize(committed));
        sb.append(" max=").append(LogService.humanSize(max));
        sb.append(" (").append(pct).append("% of max)");
        sb.append(" processors=").append(rt.availableProcessors());
        sb.append(" threads~=").append(Thread.activeCount());
        appendGc(sb);
        return sb.toString();
    }

    /**
     * JVM / OS 环境一行摘要。
     *
     * @return 环境文本
     */
    public static String environmentLine() {
        return "java=" + System.getProperty("java.version", "?")
                + " vm=" + System.getProperty("java.vm.name", "?")
                + " os=" + System.getProperty("os.name", "?")
                + "/" + System.getProperty("os.arch", "?");
    }

    /**
     * 通过反射追加各 GC 器的累计次数与耗时。平台不支持时跳过。
     *
     * @param sb 正在构建的快照
     */
    private static void appendGc(StringBuilder sb) {
        try {
            Class<?> factory = Class.forName("java.lang.management.ManagementFactory");
            Class<?> gcMx = Class.forName("java.lang.management.GarbageCollectorMXBean");
            Method getBeans = factory.getMethod("getGarbageCollectorMXBeans");
            Method getName = gcMx.getMethod("getName");
            Method getCount = gcMx.getMethod("getCollectionCount");
            Method getTime = gcMx.getMethod("getCollectionTime");
            List<?> beans = (List<?>) getBeans.invoke(null);
            if (beans == null || beans.isEmpty()) {
                return;
            }
            for (Object bean : beans) {
                String name = String.valueOf(getName.invoke(bean));
                long count = ((Number) getCount.invoke(bean)).longValue();
                long time = ((Number) getTime.invoke(bean)).longValue();
                if (count < 0) {
                    continue;
                }
                sb.append(" gc[").append(shortGcName(name)).append("]=")
                        .append(count).append('/').append(time).append("ms");
            }
        } catch (Throwable ignored) {
            // Android 或精简运行时没有 MXBean
        }
    }

    /**
     * 缩短 GC 名称，避免快照过长。
     *
     * @param name MXBean 名称
     * @return 短名
     */
    private static String shortGcName(String name) {
        if (name == null || name.isBlank()) {
            return "?";
        }
        int lastSpace = name.lastIndexOf(' ');
        return lastSpace >= 0 ? name.substring(lastSpace + 1) : name;
    }
}
