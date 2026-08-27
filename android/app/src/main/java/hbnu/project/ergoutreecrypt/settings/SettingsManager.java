package hbnu.project.ergoutreecrypt.settings;

import hbnu.project.ergoutreecrypt.log.LogLevel;

/**
 * Android 端设置管理器。
 *
 * <p>桌面端使用 {@code java.util.prefs.Preferences}，Android 端使用 Jetpack DataStore
 * （通过 {@code AndroidSettings} 访问）。本类提供同步的静态方法签名供共享核心代码引用，
 * 内部通过 in-memory 字段桥接 DataStore 的异步读写。
 *
 * <p>AndroidSettings 在初始化时调用 {@link #initFromBridge} 将 DataStore 中的值同步到本类；
 * 之后每次 DataStore 变更时通过各 setter 同步更新。
 *
 * <p>共享核心中的 {@code ArchivePacker} 和 {@code CryptoThreadPool} 直接引用本类的静态方法，
 * 因此本类必须保持同步可用的语义。
 *
 * @author ErgouTree
 * @since 2026/8/11
 */
public final class SettingsManager {

    // ---- 默认值（与桌面端 SettingsManager 保持一致） ----
    private static final boolean DEF_AUTO_DECOMPRESS = true;
    private static final boolean DEF_CONFIRM_OVERWRITE = true;
    private static final String DEF_COMPRESS_FORMAT = "ZIP";
    private static final boolean DEF_PARANOID = false;
    private static final boolean DEF_RS = false;
    private static final boolean DEF_PASSWORDLESS = false;
    private static final int DEF_SPLIT_SIZE = 100;
    private static final boolean DEF_REMEMBER_OUTDIR = true;
    private static final boolean DEF_AUTO_CLEAR_PWD = false;
    private static final String DEF_THEME_MODE = "SYSTEM";
    private static final int DEF_THREAD_COUNT = 4;
    private static final int DEF_BATCH_SERIAL_GIB = 10;
    private static final boolean DEF_ARCHIVE_PWD_FALLBACK = false;
    private static final boolean DEF_ARCHIVE_CUSTOM_ENC = false;
    private static final String DEF_LOG_LEVEL = "INFO";
    private static final boolean DEF_LOG_CLEAR_ON_NEW_OP = true;
    private static final boolean DEF_LOG_JVM_DIAGNOSTICS = false;

    // ---- 可写字段（in-memory，由 AndroidSettings 同步写入） ----

    private static volatile boolean autoDecompress = DEF_AUTO_DECOMPRESS;
    private static volatile boolean confirmOverwrite = DEF_CONFIRM_OVERWRITE;
    private static volatile String compressFormat = DEF_COMPRESS_FORMAT;
    private static volatile boolean defaultParanoid = DEF_PARANOID;
    private static volatile boolean defaultReedSolomon = DEF_RS;
    private static volatile boolean defaultPasswordless = DEF_PASSWORDLESS;
    private static volatile int splitSize = DEF_SPLIT_SIZE;
    private static volatile boolean rememberOutputDir = DEF_REMEMBER_OUTDIR;
    private static volatile boolean autoClearPassword = DEF_AUTO_CLEAR_PWD;
    private static volatile String lastOutputDir = "";
    private static volatile String themeMode = DEF_THEME_MODE;
    private static volatile boolean archivePasswordFallback = DEF_ARCHIVE_PWD_FALLBACK;
    private static volatile boolean archiveCustomEncryption = DEF_ARCHIVE_CUSTOM_ENC;

    private static volatile int threadCount = DEF_THREAD_COUNT;
    private static volatile int batchSerialThresholdGiB = DEF_BATCH_SERIAL_GIB;
    private static volatile LogLevel logLevel = LogLevel.INFO;
    private static volatile boolean logClearOnNewOp = DEF_LOG_CLEAR_ON_NEW_OP;
    private static volatile boolean logJvmDiagnostics = DEF_LOG_JVM_DIAGNOSTICS;
    private static final int MIN_THREAD_COUNT = 1;
    private static final int MAX_THREAD_COUNT = 16;
    private static final int MIN_BATCH_SERIAL_GIB = 1;
    private static final int MAX_BATCH_SERIAL_GIB = 100;

    private SettingsManager() {
    }

    // ---- Getters ----

    /** 解密后是否自动解压。 */
    public static boolean isAutoDecompressDecrypt() {
        return autoDecompress;
    }

    /** 覆盖文件前是否确认。 */
    public static boolean isConfirmOverwrite() {
        return confirmOverwrite;
    }

    /** 默认归档格式。 */
    public static String getDefaultCompressFormat() {
        return compressFormat;
    }

    /** 新建加密任务时默认是否开启偏执模式。 */
    public static boolean isDefaultParanoid() {
        return defaultParanoid;
    }

    /** 新建加密任务时默认是否开启 Reed-Solomon 纠错。 */
    public static boolean isDefaultReedSolomon() {
        return defaultReedSolomon;
    }

    /** 新建加密任务时默认是否使用无密码模式。 */
    public static boolean isDefaultPasswordless() {
        return defaultPasswordless;
    }

    /** 默认分卷大小（MiB）。 */
    public static int getDefaultSplitSize() {
        return splitSize;
    }

    /** 是否记住上次输出目录。 */
    public static boolean isRememberOutputDir() {
        return rememberOutputDir;
    }

    /** 完成后是否自动清除密码字段。 */
    public static boolean isAutoClearPassword() {
        return autoClearPassword;
    }

    /** 上次使用的输出目录路径。 */
    public static String getLastOutputDir() {
        return lastOutputDir;
    }

    /** 主题模式（SYSTEM / LIGHT / DARK）。 */
    public static String getThemeMode() {
        return themeMode;
    }

    /** 是否允许归档密码回退到加密密码。 */
    public static boolean isArchivePasswordFallback() {
        return archivePasswordFallback;
    }

    /** 是否允许自定义加密格式的归档。 */
    public static boolean isArchiveCustomEncryption() {
        return archiveCustomEncryption;
    }

    /** 并行工作线程数。 */
    public static int getThreadCount() {
        return threadCount;
    }

    /**
     * 批处理切换为单线程的总大小阈值（GiB）。
     *
     * @return 阈值 GiB，默认 10
     */
    public static int getBatchSerialThresholdGiB() {
        return batchSerialThresholdGiB;
    }

    /**
     * 获取应用日志级别。
     *
     * @return {@link LogLevel#INFO}（默认）或 {@link LogLevel#TRACE}
     */
    public static LogLevel getLogLevel() {
        return logLevel;
    }

    /**
     * 新加解密等操作开始时是否清空内存日志。
     *
     * @return true 表示每次新操作清空（默认）
     */
    public static boolean isLogClearOnNewOp() {
        return logClearOnNewOp;
    }

    /**
     * 是否开启 JVM 底层诊断日志。
     *
     * @return true 表示已开启
     */
    public static boolean isJvmDiagnostics() {
        return logJvmDiagnostics;
    }

    // ---- Setters（由 AndroidSettings DataStore 变更时调用） ----

    public static void setAutoDecompressDecrypt(boolean v) {
        autoDecompress = v;
    }

    public static void setConfirmOverwrite(boolean v) {
        confirmOverwrite = v;
    }

    public static void setDefaultCompressFormat(String v) {
        if (v != null) {
            compressFormat = v;
        }
    }

    public static void setDefaultParanoid(boolean v) {
        defaultParanoid = v;
    }

    public static void setDefaultReedSolomon(boolean v) {
        defaultReedSolomon = v;
    }

    public static void setDefaultPasswordless(boolean v) {
        defaultPasswordless = v;
    }

    public static void setDefaultSplitSize(int v) {
        if (v > 0) {
            splitSize = v;
        }
    }

    public static void setRememberOutputDir(boolean v) {
        rememberOutputDir = v;
    }

    public static void setAutoClearPassword(boolean v) {
        autoClearPassword = v;
    }

    public static void setLastOutputDir(String v) {
        lastOutputDir = (v != null) ? v : "";
    }

    public static void setThemeMode(String v) {
        if (v != null) {
            themeMode = v;
        }
    }

    public static void setArchivePasswordFallback(boolean v) {
        archivePasswordFallback = v;
    }

    public static void setArchiveCustomEncryption(boolean v) {
        archiveCustomEncryption = v;
    }

    /**
     * 设置并行线程数，自动钳位到合理范围。
     *
     * @param v 线程数（1-16）
     */
    public static void setThreadCount(int v) {
        if (v < MIN_THREAD_COUNT) {
            v = MIN_THREAD_COUNT;
        } else if (v > MAX_THREAD_COUNT) {
            v = MAX_THREAD_COUNT;
        }
        threadCount = v;
    }

    /**
     * 设置批处理单线程阈值（GiB），自动钳位到 1–100。
     *
     * @param v 阈值 GiB
     */
    public static void setBatchSerialThresholdGiB(int v) {
        if (v < MIN_BATCH_SERIAL_GIB) {
            v = MIN_BATCH_SERIAL_GIB;
        } else if (v > MAX_BATCH_SERIAL_GIB) {
            v = MAX_BATCH_SERIAL_GIB;
        }
        batchSerialThresholdGiB = v;
    }

    /**
     * 设置应用日志级别。
     *
     * @param v 级别；null 或非 TRACE 均视为 INFO
     */
    public static void setLogLevel(LogLevel v) {
        logLevel = v == LogLevel.TRACE ? LogLevel.TRACE : LogLevel.INFO;
    }

    /**
     * 设置新操作开始时是否清空内存日志。
     *
     * @param v true 清空；false 一直留存
     */
    public static void setLogClearOnNewOp(boolean v) {
        logClearOnNewOp = v;
    }

    /**
     * 设置 JVM 底层诊断日志开关。
     *
     * @param v true 开启
     */
    public static void setJvmDiagnostics(boolean v) {
        logJvmDiagnostics = v;
    }

    /**
     * 从 AndroidSettings DataStore 批量同步初始值。
     *
     * <p>由 {@code ErgouApp.onCreate()} 在 DataStore 首次读取完成后调用。
     * 后续单独的 setter 调用由 AndroidSettings 在各个 Flow 的 collect 中触发。
     *
     * @param bridge 包含 DataStore 当前值的桥接对象
     */
    public static void initFromBridge(SettingsBridge bridge) {
        autoDecompress = bridge.autoDecompress;
        confirmOverwrite = bridge.confirmOverwrite;
        compressFormat = bridge.compressFormat;
        defaultParanoid = bridge.defaultParanoid;
        defaultReedSolomon = bridge.defaultReedSolomon;
        defaultPasswordless = bridge.defaultPasswordless;
        splitSize = bridge.splitSize;
        rememberOutputDir = bridge.rememberOutputDir;
        autoClearPassword = bridge.autoClearPassword;
        lastOutputDir = bridge.lastOutputDir;
        themeMode = bridge.themeMode;
        archivePasswordFallback = bridge.archivePasswordFallback;
        archiveCustomEncryption = bridge.archiveCustomEncryption;
        threadCount = bridge.threadCount;
        batchSerialThresholdGiB = bridge.batchSerialThresholdGiB;
        logLevel = LogLevel.fromName(bridge.logLevel);
        logClearOnNewOp = bridge.logClearOnNewOp;
        logJvmDiagnostics = bridge.logJvmDiagnostics;
    }

    /**
     * AndroidSettings → SettingsManager 批量同步用的数据桥接对象。
     *
     * <p>每个字段对应 DataStore 中的一个 key，由 AndroidSettings 在读取完成后填充。
     */
    public static class SettingsBridge {
        public boolean autoDecompress = DEF_AUTO_DECOMPRESS;
        public boolean confirmOverwrite = DEF_CONFIRM_OVERWRITE;
        public String compressFormat = DEF_COMPRESS_FORMAT;
        public boolean defaultParanoid = DEF_PARANOID;
        public boolean defaultReedSolomon = DEF_RS;
        public boolean defaultPasswordless = DEF_PASSWORDLESS;
        public int splitSize = DEF_SPLIT_SIZE;
        public boolean rememberOutputDir = DEF_REMEMBER_OUTDIR;
        public boolean autoClearPassword = DEF_AUTO_CLEAR_PWD;
        public String lastOutputDir = "";
        public String themeMode = DEF_THEME_MODE;
        public boolean archivePasswordFallback = DEF_ARCHIVE_PWD_FALLBACK;
        public boolean archiveCustomEncryption = DEF_ARCHIVE_CUSTOM_ENC;
        public int threadCount = DEF_THREAD_COUNT;
        public int batchSerialThresholdGiB = DEF_BATCH_SERIAL_GIB;
        public String logLevel = DEF_LOG_LEVEL;
        public boolean logClearOnNewOp = DEF_LOG_CLEAR_ON_NEW_OP;
        public boolean logJvmDiagnostics = DEF_LOG_JVM_DIAGNOSTICS;
    }
}
