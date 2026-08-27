package hbnu.project.ergoutreecrypt.android.platform

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import hbnu.project.ergoutreecrypt.log.JvmDiagnostics
import hbnu.project.ergoutreecrypt.log.LogLevel
import hbnu.project.ergoutreecrypt.log.LogService
import hbnu.project.ergoutreecrypt.settings.SettingsManager
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map

/**
 * Android 平台设置持久化管理器。
 *
 * <p>使用 Jetpack DataStore 替代桌面端的 {@code java.util.prefs.Preferences}。
 * 配置键名与桌面端 SettingsManager 保持一致，确保逻辑兼容。
 *
 * <p>每次 DataStore 值变更时，除了更新自身的 Flow 外，还会同步调用
 * {@link SettingsManager} 的 setter，确保共享核心代码（如 {@code ArchivePacker}、
 * {@code CryptoThreadPool}）能够读取到最新设置。
 *
 * @author ErgouTree
 * @since 2026/8/11
 */

/** DataStore 单例扩展属性 */
private val Context.dataStore: DataStore<Preferences> by preferencesDataStore(name = "ergou_settings")

class AndroidSettings(context: Context) {

    private val dataStore = context.dataStore

    // ==================== 桌面端兼容键 ====================

    val isAutoDecompress: Flow<Boolean> = dataStore.data.map {
        it[KEY_AUTO_DECOMPRESS] ?: DEF_AUTO_DECOMPRESS
    }

    val isConfirmOverwrite: Flow<Boolean> = dataStore.data.map {
        it[KEY_CONFIRM_OVERWRITE] ?: DEF_CONFIRM_OVERWRITE
    }

    val isDefaultParanoid: Flow<Boolean> = dataStore.data.map {
        it[KEY_DEFAULT_PARANOID] ?: DEF_PARANOID
    }

    val isDefaultReedSolomon: Flow<Boolean> = dataStore.data.map {
        it[KEY_DEFAULT_RS] ?: DEF_RS
    }

    val isDefaultPasswordless: Flow<Boolean> = dataStore.data.map {
        it[KEY_DEFAULT_PASSWORDLESS] ?: DEF_PASSWORDLESS
    }

    val threadCount: Flow<Int> = dataStore.data.map {
        it[KEY_THREAD_COUNT] ?: DEF_THREAD_COUNT
    }

    val batchSerialThresholdGiB: Flow<Int> = dataStore.data.map {
        it[KEY_BATCH_SERIAL_GIB] ?: DEF_BATCH_SERIAL_GIB
    }

    val themeMode: Flow<String> = dataStore.data.map {
        it[KEY_THEME_MODE] ?: DEF_THEME_MODE
    }

    val defaultSplitSize: Flow<Int> = dataStore.data.map {
        it[KEY_DEFAULT_SPLIT_SIZE] ?: DEF_SPLIT_SIZE
    }

    val defaultCompressFormat: Flow<String> = dataStore.data.map {
        it[KEY_DEFAULT_COMPRESS_FORMAT] ?: DEF_COMPRESS_FORMAT
    }

    val isArchivePasswordFallback: Flow<Boolean> = dataStore.data.map {
        it[KEY_ARCHIVE_PWD_FALLBACK] ?: DEF_ARCHIVE_PWD_FALLBACK
    }

    val isArchiveCustomEncryption: Flow<Boolean> = dataStore.data.map {
        it[KEY_ARCHIVE_CUSTOM_ENC] ?: DEF_ARCHIVE_CUSTOM_ENC
    }

    val logLevel: Flow<String> = dataStore.data.map {
        it[KEY_LOG_LEVEL] ?: DEF_LOG_LEVEL
    }

    val isLogClearOnNewOp: Flow<Boolean> = dataStore.data.map {
        it[KEY_LOG_CLEAR_ON_NEW_OP] ?: DEF_LOG_CLEAR_ON_NEW_OP
    }

    val isJvmDiagnostics: Flow<Boolean> = dataStore.data.map {
        it[KEY_LOG_JVM_DIAGNOSTICS] ?: DEF_LOG_JVM_DIAGNOSTICS
    }

    // ==================== Android 专属键 ====================

    val argon2MobileMode: Flow<String> = dataStore.data.map {
        it[KEY_ARGON2_MODE] ?: "BALANCED"
    }

    val useBiometric: Flow<Boolean> = dataStore.data.map {
        it[KEY_USE_BIOMETRIC] ?: false
    }

    // ==================== 背景图片设置 ====================

    /** 背景图片 URI（content:// 格式），为 null 表示未设置 */
    val backgroundImageUri: Flow<String?> = dataStore.data.map {
        it[KEY_BG_IMAGE_URI]
    }

    /** 背景图片透明度（0-100），默认 30 */
    val backgroundOpacity: Flow<Int> = dataStore.data.map {
        it[KEY_BG_OPACITY] ?: 30
    }

    /** 界面语言代码（"zh_CN" 或 "en"），默认中文 */
    val languageCode: Flow<String> = dataStore.data.map {
        it[KEY_LANGUAGE] ?: "zh_CN"
    }

    /** 是否在加解密操作页面显示低调的内存使用指示器，默认开启 */
    val showMemoryIndicator: Flow<Boolean> = dataStore.data.map {
        it[KEY_MEMORY_INDICATOR] ?: true
    }

    // ==================== 初始化：将 DataStore 值同步到 SettingsManager ====================

    /**
     * 从 DataStore 读取所有当前值并同步到 SettingsManager。
     *
     * <p>应在 Application.onCreate() 中调用，确保共享核心在第一次使用设置前已获得正确值。
     * 后续每次 DataStore 写入时，对应的 setter 也会同步调用 SettingsManager。
     */
    suspend fun syncToSettingsManager() {
        // 读取所有 DataStore 当前值
        val prefs = dataStore.data.first()
        val bridge = SettingsManager.SettingsBridge().apply {
            autoDecompress = prefs[KEY_AUTO_DECOMPRESS] ?: DEF_AUTO_DECOMPRESS
            confirmOverwrite = prefs[KEY_CONFIRM_OVERWRITE] ?: DEF_CONFIRM_OVERWRITE
            compressFormat = prefs[KEY_DEFAULT_COMPRESS_FORMAT] ?: DEF_COMPRESS_FORMAT
            defaultParanoid = prefs[KEY_DEFAULT_PARANOID] ?: DEF_PARANOID
            defaultReedSolomon = prefs[KEY_DEFAULT_RS] ?: DEF_RS
            defaultPasswordless = prefs[KEY_DEFAULT_PASSWORDLESS] ?: DEF_PASSWORDLESS
            splitSize = prefs[KEY_DEFAULT_SPLIT_SIZE] ?: DEF_SPLIT_SIZE
            archivePasswordFallback = prefs[KEY_ARCHIVE_PWD_FALLBACK] ?: DEF_ARCHIVE_PWD_FALLBACK
            archiveCustomEncryption = prefs[KEY_ARCHIVE_CUSTOM_ENC] ?: DEF_ARCHIVE_CUSTOM_ENC
            themeMode = prefs[KEY_THEME_MODE] ?: DEF_THEME_MODE
            threadCount = prefs[KEY_THREAD_COUNT] ?: DEF_THREAD_COUNT
            batchSerialThresholdGiB = prefs[KEY_BATCH_SERIAL_GIB] ?: DEF_BATCH_SERIAL_GIB
            logLevel = prefs[KEY_LOG_LEVEL] ?: DEF_LOG_LEVEL
            logClearOnNewOp = prefs[KEY_LOG_CLEAR_ON_NEW_OP] ?: DEF_LOG_CLEAR_ON_NEW_OP
            logJvmDiagnostics = prefs[KEY_LOG_JVM_DIAGNOSTICS] ?: DEF_LOG_JVM_DIAGNOSTICS
        }
        SettingsManager.initFromBridge(bridge)
    }

    // ==================== 写入方法（同时更新 SettingsManager） ====================

    suspend fun setDefaultParanoid(v: Boolean) {
        dataStore.edit { it[KEY_DEFAULT_PARANOID] = v }
        SettingsManager.setDefaultParanoid(v)
    }

    suspend fun setDefaultReedSolomon(v: Boolean) {
        dataStore.edit { it[KEY_DEFAULT_RS] = v }
        SettingsManager.setDefaultReedSolomon(v)
    }

    suspend fun setDefaultPasswordless(v: Boolean) {
        dataStore.edit { it[KEY_DEFAULT_PASSWORDLESS] = v }
        SettingsManager.setDefaultPasswordless(v)
    }

    suspend fun setThreadCount(v: Int) {
        val clamped = v.coerceIn(MIN_THREAD_COUNT, MAX_THREAD_COUNT)
        dataStore.edit { it[KEY_THREAD_COUNT] = clamped }
        SettingsManager.setThreadCount(clamped)
    }

    /**
     * 设置批处理单线程阈值（GiB）。
     *
     * @param v 阈值，钳制在 1–100
     */
    suspend fun setBatchSerialThresholdGiB(v: Int) {
        val clamped = v.coerceIn(MIN_BATCH_SERIAL_GIB, MAX_BATCH_SERIAL_GIB)
        dataStore.edit { it[KEY_BATCH_SERIAL_GIB] = clamped }
        SettingsManager.setBatchSerialThresholdGiB(clamped)
    }

    suspend fun setAutoDecompress(v: Boolean) {
        dataStore.edit { it[KEY_AUTO_DECOMPRESS] = v }
        SettingsManager.setAutoDecompressDecrypt(v)
    }

    suspend fun setConfirmOverwrite(v: Boolean) {
        dataStore.edit { it[KEY_CONFIRM_OVERWRITE] = v }
        SettingsManager.setConfirmOverwrite(v)
    }

    suspend fun setThemeMode(v: String) {
        dataStore.edit { it[KEY_THEME_MODE] = v }
        SettingsManager.setThemeMode(v)
    }

    suspend fun setArgon2MobileMode(v: String) {
        dataStore.edit { it[KEY_ARGON2_MODE] = v }
    }

    suspend fun setUseBiometric(v: Boolean) {
        dataStore.edit { it[KEY_USE_BIOMETRIC] = v }
    }

    /**
     * 设置背景图片 URI。
     *
     * @param uri 图片 content URI，传入 null 表示移除背景图片
     */
    suspend fun setBackgroundImageUri(uri: String?) {
        dataStore.edit { prefs ->
            if (uri != null) {
                prefs[KEY_BG_IMAGE_URI] = uri
            } else {
                prefs.remove(KEY_BG_IMAGE_URI)
            }
        }
    }

    /**
     * 设置背景图片透明度。
     *
     * @param opacity 透明度百分比（0-100），0 为完全透明，100 为完全不透明
     */
    suspend fun setBackgroundOpacity(opacity: Int) {
        val clamped = opacity.coerceIn(0, 100)
        dataStore.edit { it[KEY_BG_OPACITY] = clamped }
    }

    /**
     * 设置界面语言。
     *
     * @param code 语言代码（"zh_CN" / "en"）
     */
    suspend fun setLanguageCode(code: String) {
        dataStore.edit { it[KEY_LANGUAGE] = code }
    }

    /**
     * 设置是否在加解密操作页面显示内存使用指示器。
     *
     * @param v true 显示，false 隐藏
     */
    suspend fun setShowMemoryIndicator(v: Boolean) {
        dataStore.edit { it[KEY_MEMORY_INDICATOR] = v }
    }

    suspend fun setDefaultSplitSize(v: Int) {
        dataStore.edit { it[KEY_DEFAULT_SPLIT_SIZE] = v.coerceIn(1, 4096) }
        SettingsManager.setDefaultSplitSize(v)
    }

    suspend fun setDefaultCompressFormat(v: String) {
        dataStore.edit { it[KEY_DEFAULT_COMPRESS_FORMAT] = v }
        SettingsManager.setDefaultCompressFormat(v)
    }

    suspend fun setArchivePasswordFallback(v: Boolean) {
        dataStore.edit { it[KEY_ARCHIVE_PWD_FALLBACK] = v }
        SettingsManager.setArchivePasswordFallback(v)
    }

    suspend fun setArchiveCustomEncryption(v: Boolean) {
        dataStore.edit { it[KEY_ARCHIVE_CUSTOM_ENC] = v }
        SettingsManager.setArchiveCustomEncryption(v)
    }

    /**
     * 设置应用日志级别。
     *
     * @param v {@code INFO} 或 {@code TRACE}；其它值视为 INFO
     */
    suspend fun setLogLevel(v: String) {
        val normalized = if (v.equals("TRACE", ignoreCase = true)) "TRACE" else DEF_LOG_LEVEL
        dataStore.edit { it[KEY_LOG_LEVEL] = normalized }
        val level = LogLevel.fromName(normalized)
        SettingsManager.setLogLevel(level)
        LogService.setLevel(level)
    }

    /**
     * 设置新操作开始时是否清空内存日志。
     *
     * @param v true 清空；false 一直留存
     */
    suspend fun setLogClearOnNewOp(v: Boolean) {
        dataStore.edit { it[KEY_LOG_CLEAR_ON_NEW_OP] = v }
        SettingsManager.setLogClearOnNewOp(v)
        LogService.setClearOnNewOperation(v)
    }

    /**
     * 设置 JVM 底层诊断日志开关。
     *
     * @param v true 开启堆快照、GC 累计与完整异常堆栈
     */
    suspend fun setJvmDiagnostics(v: Boolean) {
        dataStore.edit { it[KEY_LOG_JVM_DIAGNOSTICS] = v }
        SettingsManager.setJvmDiagnostics(v)
        if (v) {
            JvmDiagnostics.start()
        } else {
            JvmDiagnostics.stop()
        }
    }

    // ==================== 键定义与默认值 ====================

    companion object {
        // --- 桌面端兼容键 ---
        private val KEY_AUTO_DECOMPRESS = booleanPreferencesKey("auto.decompress.decrypt")
        private val KEY_CONFIRM_OVERWRITE = booleanPreferencesKey("confirm.overwrite")
        private val KEY_DEFAULT_PARANOID = booleanPreferencesKey("default.paranoid")
        private val KEY_DEFAULT_RS = booleanPreferencesKey("default.reedSolomon")
        private val KEY_DEFAULT_PASSWORDLESS = booleanPreferencesKey("default.passwordless")
        private val KEY_THREAD_COUNT = intPreferencesKey("thread.count")
        private val KEY_BATCH_SERIAL_GIB = intPreferencesKey("batch.serial.threshold.gib")
        private val KEY_THEME_MODE = stringPreferencesKey("theme.mode")
        private val KEY_DEFAULT_SPLIT_SIZE = intPreferencesKey("default.split.size")
        private val KEY_DEFAULT_COMPRESS_FORMAT = stringPreferencesKey("default.compress.format")
        private val KEY_ARCHIVE_PWD_FALLBACK = booleanPreferencesKey("archive.password.fallback")
        private val KEY_ARCHIVE_CUSTOM_ENC = booleanPreferencesKey("archive.custom.encryption")
        private val KEY_LOG_LEVEL = stringPreferencesKey("log.level")
        private val KEY_LOG_CLEAR_ON_NEW_OP = booleanPreferencesKey("log.clearOnNewOp")
        private val KEY_LOG_JVM_DIAGNOSTICS = booleanPreferencesKey("log.jvmDiagnostics")

        // --- Android 专属键 ---
        private val KEY_ARGON2_MODE = stringPreferencesKey("mobile.argon2.mode")
        private val KEY_USE_BIOMETRIC = booleanPreferencesKey("security.biometric")

        // --- 背景图片键 ---
        private val KEY_BG_IMAGE_URI = stringPreferencesKey("ui.background.image.uri")
        private val KEY_BG_OPACITY = intPreferencesKey("ui.background.opacity")

        // --- 语言键 ---
        private val KEY_LANGUAGE = stringPreferencesKey("ui.language")

        // --- 内存指示器键 ---
        private val KEY_MEMORY_INDICATOR = booleanPreferencesKey("ui.memory.indicator")

        // --- 默认值 ---
        private const val DEF_AUTO_DECOMPRESS = true
        private const val DEF_CONFIRM_OVERWRITE = true
        private const val DEF_PARANOID = false
        private const val DEF_RS = false
        private const val DEF_PASSWORDLESS = false
        private const val DEF_THREAD_COUNT = 4
        private const val DEF_BATCH_SERIAL_GIB = 10
        private const val DEF_THEME_MODE = "SYSTEM"
        private const val DEF_SPLIT_SIZE = 100
        private const val DEF_COMPRESS_FORMAT = "ZIP"
        private const val DEF_ARCHIVE_PWD_FALLBACK = false
        private const val DEF_ARCHIVE_CUSTOM_ENC = false
        private const val DEF_LOG_LEVEL = "INFO"
        private const val DEF_LOG_CLEAR_ON_NEW_OP = true
        private const val DEF_LOG_JVM_DIAGNOSTICS = false
        private const val MIN_THREAD_COUNT = 1
        private const val MAX_THREAD_COUNT = 16
        private const val MIN_BATCH_SERIAL_GIB = 1
        private const val MAX_BATCH_SERIAL_GIB = 100
    }
}
