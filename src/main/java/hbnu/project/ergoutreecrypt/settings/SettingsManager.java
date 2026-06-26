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
    private static final String  DEF_THEME_MODE        = "SYSTEM";

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
}
