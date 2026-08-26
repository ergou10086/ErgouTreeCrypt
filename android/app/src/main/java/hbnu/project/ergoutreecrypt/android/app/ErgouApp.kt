package hbnu.project.ergoutreecrypt.android.app

import android.app.Application
import hbnu.project.ergoutreecrypt.android.platform.AndroidSettings
import hbnu.project.ergoutreecrypt.android.platform.NotificationHelper
import hbnu.project.ergoutreecrypt.history.FileHistoryStore
import hbnu.project.ergoutreecrypt.history.HistoryService
import hbnu.project.ergoutreecrypt.i18n.Messages
import hbnu.project.ergoutreecrypt.log.FileLogSink
import hbnu.project.ergoutreecrypt.log.LogService
import hbnu.project.ergoutreecrypt.log.MemoryLogBuffer
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.Security
import java.util.Locale

/**
 * ErgouTreeCrypt Android Application。
 *
 * <p>负责全局初始化：
 * <ol>
 *   <li>注册 BouncyCastle 安全提供者（与桌面端 PicocryptApplication 一致）</li>
 *   <li>初始化 AndroidSettings 并同步到共享核心的 SettingsManager</li>
 *   <li>启动全局协程监听关键设置变更，实时同步到 SettingsManager</li>
 * </ol>
 *
 * @author ErgouTree
 * @since 2026/8/11
 */
class ErgouApp : Application() {

    /** 应用级协程作用域，使用 SupervisorJob 确保单个协程失败不影响其他。 */
    private val appScope = CoroutineScope(SupervisorJob() + Dispatchers.Main)

    override fun onCreate() {
        super.onCreate()
        instance = this

        // 0. 初始化语言（在 UI 构建前设置，确保 Messages.get() 返回正确语言）
        val settings = AndroidSettings(this)
        appScope.launch {
            val langCode = settings.languageCode.first()
            val locale = when (langCode) {
                "en" -> Locale.ENGLISH
                else -> Locale.SIMPLIFIED_CHINESE
            }
            Messages.setLocale(locale)
        }

        // 1. 注册 BouncyCastle 安全提供者
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.insertProviderAt(BouncyCastleProvider(), 1)
        }

        // 2. 创建通知渠道（前台 Service 依赖）
        NotificationHelper.createChannel(this)

        // 3. 注册操作历史存储（应用私有 filesDir 下），供全应用记录加解密历史
        HistoryService.register(FileHistoryStore(filesDir.resolve("history").toPath()))

        // 4. 注册日志：内存缓冲供页内实时展示，文件落盘便于崩溃后排查
        LogService.register(
            MemoryLogBuffer(),
            FileLogSink(filesDir.resolve("logs").toPath())
        )

        // 5. 同步设置到共享核心并持续监听关键变更
        appScope.launch {
            // 首次批量同步
            settings.syncToSettingsManager()
            LogService.setLevel(hbnu.project.ergoutreecrypt.settings.SettingsManager.getLogLevel())
            LogService.setClearOnNewOperation(
                hbnu.project.ergoutreecrypt.settings.SettingsManager.isLogClearOnNewOp()
            )

            // 持续监听共享核心依赖的关键设置变更
            launch {
                settings.threadCount.collectLatest { v ->
                    hbnu.project.ergoutreecrypt.settings.SettingsManager.setThreadCount(v)
                }
            }
            launch {
                settings.isArchiveCustomEncryption.collectLatest { v ->
                    hbnu.project.ergoutreecrypt.settings.SettingsManager.setArchiveCustomEncryption(v)
                }
            }
            launch {
                settings.isArchivePasswordFallback.collectLatest { v ->
                    hbnu.project.ergoutreecrypt.settings.SettingsManager.setArchivePasswordFallback(v)
                }
            }
            launch {
                settings.logLevel.collectLatest { v ->
                    val level = hbnu.project.ergoutreecrypt.log.LogLevel.fromName(v)
                    hbnu.project.ergoutreecrypt.settings.SettingsManager.setLogLevel(level)
                    LogService.setLevel(level)
                }
            }
            launch {
                settings.isLogClearOnNewOp.collectLatest { v ->
                    hbnu.project.ergoutreecrypt.settings.SettingsManager.setLogClearOnNewOp(v)
                    LogService.setClearOnNewOperation(v)
                }
            }
        }
    }

    companion object {
        /** 全局 Application 实例，供平台适配层获取 Context。 */
        lateinit var instance: ErgouApp
            private set
    }
}
