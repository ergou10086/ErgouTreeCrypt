package hbnu.project.ergoutreecrypt.android.viewmodel

import android.content.Context
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import hbnu.project.ergoutreecrypt.android.platform.DeviceMemory
import hbnu.project.ergoutreecrypt.android.platform.LoggingProgressListener
import hbnu.project.ergoutreecrypt.android.platform.describeError
import hbnu.project.ergoutreecrypt.android.platform.logElapsedMillis
import hbnu.project.ergoutreecrypt.android.platform.logFileName
import hbnu.project.ergoutreecrypt.crypto.BruteForceGuard
import hbnu.project.ergoutreecrypt.filestego.FileStegoCodec
import hbnu.project.ergoutreecrypt.filestego.api.FileStegoOptions
import hbnu.project.ergoutreecrypt.filestego.api.ProgressListener
import hbnu.project.ergoutreecrypt.log.LogService
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import java.nio.file.Paths

/**
 * 隐写操作 ViewModel。
 *
 * <p>桥接共享核心 {@link FileStegoCodec} 与 Compose UI，提供隐写（hide）和
 * 隐写提取（extract）两个核心操作。操作在 IO 协程中执行，进度通过
 * {@link ProgressState} 回传至 UI。
 *
 * <p>初始化时会调用 {@link BruteForceGuard#init(Path)} 设置暴力破解防护的
 * 侧车数据库目录，确保提取操作中的密码验证限速正常工作。
 *
 * @author ErgouTree
 * @since 2026/8/12
 */
class StegoViewModel(private val appContext: Context) : ViewModel() {

    /** 文件隐写编解码器（线程安全，单例复用） */
    private val codec = FileStegoCodec()

    /** 进度状态流 */
    private val _progress = MutableStateFlow(ProgressState())
    val progress: StateFlow<ProgressState> = _progress.asStateFlow()

    /** 当前正在运行的隐写协程，用于取消操作。 */
    private var currentJob: Job? = null

    /** 当前操作的全局协调器释放令牌（取消后用于立即归还操作权）。 */
    private var opToken: Long? = null

    init {
        // 初始化 BruteForceGuard：侧车数据库存储在 app 私有目录
        val guardDir = Paths.get(appContext.filesDir.absolutePath, ".ergou")
        BruteForceGuard.getInstance().init(guardDir)
    }

    /**
     * 创建进度监听器：将核心库按已处理字节数回调的进度写入 StateFlow。
     *
     * <p>回调在工作线程（Dispatchers.IO）执行，{@link MutableStateFlow#update}
     * 本身线程安全，无需额外切换调度器。
     *
     * @return 进度监听器
     */
    private fun createProgressListener(): ProgressListener = ProgressListener { fraction ->
        _progress.update {
            it.copy(
                state = ProgressState.State.RUNNING,
                progress = fraction.toFloat().coerceIn(0f, 1f)
            )
        }
    }

    /**
     * 将文件加密后嵌入到载体文件中。
     *
     * @param carrierPath 载体文件路径（PNG/ZIP/PDF/WAV/FLAC/MP4 等）
     * @param secretPath  待隐藏的文件路径
     * @param outputPath  输出文件路径
     * @param password    密码（可为空，使用默认密码）
     * @param options     文件隐写选项
     */
    fun hide(
        carrierPath: String,
        secretPath: String,
        outputPath: String,
        password: String,
        options: FileStegoOptions
    ) {
        // 全局操作权占用失败：已有其他 Tab 的操作在运行
        val token = OperationCoordinator.tryAcquire() ?: return
        opToken = token
        // 如果本 VM 仍有上一次任务在收尾，先取消
        currentJob?.cancel()
        _progress.update { it.copy(state = ProgressState.State.RUNNING) }

        currentJob = viewModelScope.launch(Dispatchers.IO) {
            LogService.beginSession("STEGO_ENCODE", logFileName(secretPath))
            val t0 = System.nanoTime()
            var success = false
            var cancelled = false
            try {
                val carrierFile = Paths.get(carrierPath)
                val secretFile = Paths.get(secretPath)
                val output = Paths.get(outputPath)
                val pwdBytes = if (password.isNotEmpty()) {
                    password.toByteArray(Charsets.UTF_8)
                } else {
                    ByteArray(0)
                }

                codec.hide(carrierFile, secretFile, output, pwdBytes, options,
                    LoggingProgressListener(createProgressListener(), "FileStego"))

                success = true
                _progress.update {
                    it.copy(state = ProgressState.State.DONE, progress = 1f)
                }
            } catch (e: CancellationException) {
                cancelled = true
                _progress.update { it.copy(state = ProgressState.State.CANCELLED) }
            } catch (e: OutOfMemoryError) {
                LogService.error("STEGO_ENCODE", "内存不足", e)
                _progress.update {
                    it.copy(
                        state = ProgressState.State.ERROR,
                        error = "内存不足：操作所需内存超过设备可用堆，请降低 Argon2 档位后重试。"
                    )
                }
            } catch (e: Exception) {
                LogService.error("STEGO_ENCODE", "任务失败", e)
                _progress.update {
                    it.copy(
                        state = ProgressState.State.ERROR,
                        error = describeError(e)
                    )
                }
            } finally {
                // 无条件归还操作权，避免 busy 悬挂导致后续操作按钮永久置灰
                OperationCoordinator.release(token)
                val elapsed = logElapsedMillis(t0)
                try {
                    when {
                        cancelled -> LogService.endSessionCancelled(elapsed)
                        success -> LogService.endSession(true, elapsed)
                        else -> LogService.endSession(false, elapsed)
                    }
                } catch (_: Throwable) {
                    // 日志收尾失败不影响操作权释放
                }
            }
        }
        // 兜底释放：协程无论以何种方式结束（含 setup 抛异常/作用域销毁）都归还操作权，防止 busy 悬挂导致按钮永久置灰
        currentJob?.invokeOnCompletion { OperationCoordinator.release(token) }
    }

    /**
     * 从载体文件中提取并解密隐藏的文件。
     *
     * @param stegoPath 隐写载体文件路径
     * @param outputDir 输出目录路径
     * @param password  密码（可为空）
     */
    fun extract(
        stegoPath: String,
        outputDir: String,
        password: String
    ) {
        // 全局操作权占用失败：已有其他 Tab 的操作在运行
        val token = OperationCoordinator.tryAcquire() ?: return
        opToken = token
        // 如果本 VM 仍有上一次任务在收尾，先取消
        currentJob?.cancel()
        _progress.update { it.copy(state = ProgressState.State.RUNNING) }

        currentJob = viewModelScope.launch(Dispatchers.IO) {
            LogService.beginSession("STEGO_EXTRACT", logFileName(stegoPath))
            val t0 = System.nanoTime()
            var success = false
            var cancelled = false
            try {
                val stegoFile = Paths.get(stegoPath)
                val outDir = Paths.get(outputDir)
                val pwdBytes = if (password.isNotEmpty()) {
                    password.toByteArray(Charsets.UTF_8)
                } else {
                    ByteArray(0)
                }

                val opts = FileStegoOptions.builder()
                    .lowMemoryMode(true)
                    .lowMemoryThresholdBytes(DeviceMemory.lowMemoryThresholdBytes())
                    .build()
                val resultFile = codec.extract(stegoFile, outDir, pwdBytes, opts,
                    LoggingProgressListener(createProgressListener(), "FileStego"))

                success = true
                _progress.update {
                    it.copy(
                        state = ProgressState.State.DONE,
                        progress = 1f,
                        info = resultFile.fileName.toString()
                    )
                }
            } catch (e: CancellationException) {
                cancelled = true
                _progress.update { it.copy(state = ProgressState.State.CANCELLED) }
            } catch (e: OutOfMemoryError) {
                LogService.error("STEGO_EXTRACT", "内存不足", e)
                _progress.update {
                    it.copy(
                        state = ProgressState.State.ERROR,
                        error = "内存不足：提取所需内存超过设备可用堆。" +
                                "该文件的 Argon2 参数在创建时已固定，与当前档位设置无关；" +
                                "请改用桌面端提取。"
                    )
                }
            } catch (e: Exception) {
                LogService.error("STEGO_EXTRACT", "任务失败", e)
                _progress.update {
                    it.copy(
                        state = ProgressState.State.ERROR,
                        error = describeError(e)
                    )
                }
            } finally {
                // 无条件归还操作权，避免 busy 悬挂导致后续操作按钮永久置灰
                OperationCoordinator.release(token)
                val elapsed = logElapsedMillis(t0)
                try {
                    when {
                        cancelled -> LogService.endSessionCancelled(elapsed)
                        success -> LogService.endSession(true, elapsed)
                        else -> LogService.endSession(false, elapsed)
                    }
                } catch (_: Throwable) {
                    // 日志收尾失败不影响操作权释放
                }
            }
        }
        // 兜底释放：协程无论以何种方式结束（含 setup 抛异常/作用域销毁）都归还操作权，防止 busy 悬挂导致按钮永久置灰
        currentJob?.invokeOnCompletion { OperationCoordinator.release(token) }
    }

    /**
     * 取消正在进行的隐写操作。
     *
     * <p>仅取消当前任务，不销毁 ViewModel 作用域。操作权由任务退出时的
     * 释放回调归还；无任务时立即归还，避免忙标记悬挂。
     */
    fun cancel() {
        currentJob?.cancel()
        currentJob = null
        _progress.update { it.copy(state = ProgressState.State.CANCELLED) }
        OperationCoordinator.release(opToken)
        opToken = null
    }

    /**
     * 消费终态结果：回到 IDLE，防止页面重建或切回 Tab 后过期结果重复触发。
     *
     * <p>仅终态（DONE/ERROR/CANCELLED）被重置；RUNNING 状态保留，
     * 避免"取消后立刻重新启动"时旧终态回调冲掉新任务的状态。
     */
    fun reset() {
        _progress.update { p ->
            if (p.state == ProgressState.State.IDLE || p.state == ProgressState.State.RUNNING) p
            else ProgressState()
        }
    }
}
