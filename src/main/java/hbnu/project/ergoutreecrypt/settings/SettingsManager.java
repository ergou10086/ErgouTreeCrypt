package hbnu.project.ergoutreecrypt.settings;

import java.util.prefs.Preferences;

/**
 * 应用设置持久化管理器，基于 Java Preferences API。
 *
 * @author ErgouTree
 * @since 2026/6/23
 */
public final class SettingsManager {

    private static final Preferences PREFS = Preferences.userNodeForPackage(SettingsManager.class);

    // ---- 设置键 ----
    private static final String KEY_AUTO_DECOMPRESS     = "auto.decompress.decrypt";
    private static final String KEY_CONFIRM_OVERWRITE   = "confirm.overwrite";
    private static final String KEY_DEFAULT_COMPRESS    = "default.compress.format";
    private static final String KEY_DEFAULT_PARANOID    = "default.paranoid";
    private static final String KEY_DEFAULT_RS          = "default.reedSolomon";
    private static final String KEY_DEFAULT_PASSWORDLESS = "default.passwordless";
    private static final String KEY_DEFAULT_SPLIT_SIZE  = "default.split.size";
    private static final String KEY_REMEMBER_OUTPUT_DIR = "remember.output.dir";
    private static final String KEY_AUTO_CLEAR_PASSWORD = "auto.clear.password";
    private static final String KEY_LAST_OUTPUT_DIR     = "last.output.dir";
    private static final String KEY_THEME_MODE          = "theme.mode";
    private static final String KEY_THREAD_COUNT        = "thread.count";
    private static final String KEY_ARCHIVE_PWD_FALLBACK = "archive.password.fallback";
    private static final String KEY_ARCHIVE_CUSTOM_ENC  = "archive.custom.encryption";

    // ---- 默认值 ----
    private static final boolean DEF_AUTO_DECOMPRESS  = true;
    private static final boolean DEF_CONFIRM_OVERWRITE = true;
    private static final String  DEF_COMPRESS_FORMAT  = "ZIP";
    private static final boolean DEF_PARANOID         = false;
    private static final boolean DEF_RS               = false;
    private static final boolean DEF_PASSWORDLESS     = false;
    private static final int     DEF_SPLIT_SIZE       = 100;
    private static final boolean DEF_REMEMBER_OUTDIR  = true;
    private static final boolean DEF_AUTO_CLEAR_PWD   = false;
    private static final String  DEF_THEME_MODE       = "SYSTEM";
    private static final int     DEF_THREAD_COUNT     = 4;
    private static final boolean DEF_ARCHIVE_PWD_FALLBACK = false;
    private static final boolean DEF_ARCHIVE_CUSTOM_ENC = false;
    private static final int     MIN_THREAD_COUNT     = 1;
    private static final int     MAX_THREAD_COUNT     = 16;

    private SettingsManager() {}

    public static boolean isAutoDecompressDecrypt()  { return PREFS.getBoolean(KEY_AUTO_DECOMPRESS, DEF_AUTO_DECOMPRESS); }
    public static void setAutoDecompressDecrypt(boolean v) { PREFS.putBoolean(KEY_AUTO_DECOMPRESS, v); }

    public static boolean isConfirmOverwrite()        { return PREFS.getBoolean(KEY_CONFIRM_OVERWRITE, DEF_CONFIRM_OVERWRITE); }
    public static void setConfirmOverwrite(boolean v)  { PREFS.putBoolean(KEY_CONFIRM_OVERWRITE, v); }

    public static String getDefaultCompressFormat()   { return PREFS.get(KEY_DEFAULT_COMPRESS, DEF_COMPRESS_FORMAT); }
    public static void setDefaultCompressFormat(String v) { PREFS.put(KEY_DEFAULT_COMPRESS, v); }

    public static boolean isDefaultParanoid()         { return PREFS.getBoolean(KEY_DEFAULT_PARANOID, DEF_PARANOID); }
    public static void setDefaultParanoid(boolean v)   { PREFS.putBoolean(KEY_DEFAULT_PARANOID, v); }

    public static boolean isDefaultReedSolomon()      { return PREFS.getBoolean(KEY_DEFAULT_RS, DEF_RS); }
    public static void setDefaultReedSolomon(boolean v) { PREFS.putBoolean(KEY_DEFAULT_RS, v); }

    public static boolean isDefaultPasswordless()     { return PREFS.getBoolean(KEY_DEFAULT_PASSWORDLESS, DEF_PASSWORDLESS); }
    public static void setDefaultPasswordless(boolean v) { PREFS.putBoolean(KEY_DEFAULT_PASSWORDLESS, v); }

    public static int getDefaultSplitSize()           { return PREFS.getInt(KEY_DEFAULT_SPLIT_SIZE, DEF_SPLIT_SIZE); }
    public static void setDefaultSplitSize(int v)      { PREFS.putInt(KEY_DEFAULT_SPLIT_SIZE, v); }

    public static boolean isRememberOutputDir()       { return PREFS.getBoolean(KEY_REMEMBER_OUTPUT_DIR, DEF_REMEMBER_OUTDIR); }
    public static void setRememberOutputDir(boolean v) { PREFS.putBoolean(KEY_REMEMBER_OUTPUT_DIR, v); }

    public static boolean isAutoClearPassword()       { return PREFS.getBoolean(KEY_AUTO_CLEAR_PASSWORD, DEF_AUTO_CLEAR_PWD); }
    public static void setAutoClearPassword(boolean v) { PREFS.putBoolean(KEY_AUTO_CLEAR_PASSWORD, v); }

    public static String getLastOutputDir()            { return PREFS.get(KEY_LAST_OUTPUT_DIR, ""); }
    public static void setLastOutputDir(String v)       { PREFS.put(KEY_LAST_OUTPUT_DIR, v == null ? "" : v); }

    /**
     * 获取主题模式。
     *
     * @return "SYSTEM" (跟随系统), "LIGHT" (始终浅色), 或 "DARK" (始终深色)
     */
    public static String getThemeMode()                 { return PREFS.get(KEY_THEME_MODE, DEF_THEME_MODE); }

    /**
     * 设置主题模式。
     *
     * @param v "SYSTEM", "LIGHT", 或 "DARK"
     */
    public static void setThemeMode(String v)            { PREFS.put(KEY_THEME_MODE, v == null ? DEF_THEME_MODE : v); }

    /**
     * 获取加解密时使用的线程池大小。
     *
     * <p>返回值自动钳制在 [{@value #MIN_THREAD_COUNT}, {@value #MAX_THREAD_COUNT}] 范围内。
     *
     * @return 线程数，默认 {@value #DEF_THREAD_COUNT}
     */
    public static int getThreadCount() {
        int v = PREFS.getInt(KEY_THREAD_COUNT, DEF_THREAD_COUNT);
        if (v < MIN_THREAD_COUNT) {
            return MIN_THREAD_COUNT;
        }
        if (v > MAX_THREAD_COUNT) {
            return MAX_THREAD_COUNT;
        }
        return v;
    }

    /**
     * 设置加解密时使用的线程池大小。
     *
     * @param v 线程数，超出 [{@value #MIN_THREAD_COUNT}, {@value #MAX_THREAD_COUNT}] 范围的值将被钳制
     */
    public static void setThreadCount(int v) {
        if (v < MIN_THREAD_COUNT) {
            v = MIN_THREAD_COUNT;
        } else if (v > MAX_THREAD_COUNT) {
            v = MAX_THREAD_COUNT;
        }
        PREFS.putInt(KEY_THREAD_COUNT, v);
    }

    /**
     * 归档密码为空时，是否回退使用文件加密密码保护压缩包。
     *
     * <p>关闭（默认）时：归档密码留空 = 生成无密码明文归档。
     * 开启时：归档密码留空则使用加密密码做 ZIP/7Z 原生保护或 GZ 包裹。
     *
     * @return true 表示启用回退
     */
    public static boolean isArchivePasswordFallback() {
        return PREFS.getBoolean(KEY_ARCHIVE_PWD_FALLBACK, DEF_ARCHIVE_PWD_FALLBACK);
    }

    /**
     * 设置归档密码回退到加密密码的开关。
     *
     * @param v true 启用回退
     */
    public static void setArchivePasswordFallback(boolean v) {
        PREFS.putBoolean(KEY_ARCHIVE_PWD_FALLBACK, v);
    }

    /**
     * 是否为非 ZIP 格式（GZ / TAR.GZ / 7Z）启用本工具特有的压缩包加密方式。
     *
     * <p>本工具特有加密采用整体 AES-256-CTR 包裹（MAGIC 头），仅能由本工具解密。
     * 关闭（默认）时：GZ / TAR.GZ / 7Z 不支持密码，始终生成明文归档。
     * 开启时：这三种格式可使用密码进行 MAGIC 包裹加密。ZIP 始终走原生 AES，不受此开关影响。
     *
     * @return true 表示启用非 ZIP 格式的工具特有加密
     */
    public static boolean isArchiveCustomEncryption() {
        return PREFS.getBoolean(KEY_ARCHIVE_CUSTOM_ENC, DEF_ARCHIVE_CUSTOM_ENC);
    }

    /**
     * 设置非 ZIP 格式工具特有加密开关。
     *
     * @param v true 启用
     */
    public static void setArchiveCustomEncryption(boolean v) {
        PREFS.putBoolean(KEY_ARCHIVE_CUSTOM_ENC, v);
    }
}
