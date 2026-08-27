package hbnu.project.ergoutreecrypt.android.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import hbnu.project.ergoutreecrypt.android.platform.LoggingProgressReporter
import hbnu.project.ergoutreecrypt.android.platform.logElapsedMillis
import hbnu.project.ergoutreecrypt.android.platform.logFileName
import hbnu.project.ergoutreecrypt.log.LogService
import hbnu.project.ergoutreecrypt.volume.EncryptRequest
import hbnu.project.ergoutreecrypt.volume.ProgressReporter
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

/**
 * 加密进度状态。
 *
 * @property statusText   当前阶段状态文案
 * @property progress     进度 0.0-1.0
 * @property info         附加信息（速度等）
 * @property canCancel    是否可取消
 * @property state        整体状态
 * @property error        错误信息
 * @property detail       批处理汇总详情（部分失败列表等）
 */
data class ProgressState(
    val statusText: String = "",
    val progress: Float = 0f,
    val info: String = "",
    val canCancel: Boolean = false,
    val state: State = State.IDLE,
    val error: String? = null,
    val detail: String? = null
) {
    enum class State { IDLE, RUNNING, DONE, ERROR, CANCELLED }
}

/**
 * 文件加密 ViewModel。
 *
 * <p>桥接共享核心 Encryptor 与 Compose UI：
 * <ol>
 *   <li>UI 构建 EncryptRequest DTO</li>
 *   <li>在 IO 协程中调用 Encryptor.encrypt()</li>
 *   <li>通过 ProgressReporter 接口将进度回传到 StateFlow</li>
 * </ol>
 *
 * @author ErgouTree
 * @since 2026/8/11
 */
class EncryptViewModel : ViewModel() {

    private val _progress = MutableStateFlow(ProgressState())
    val progress: StateFlow<ProgressState> = _progress.asStateFlow()

    /** 当前正在运行的加密协程，用于取消操作。 */
    private var currentJob: Job? = null

    /** 当前操作的全局协调器释放令牌（取消后用于立即归还操作权）。 */
    private var opToken: Long? = null

    /**
     * 开始加密。
     *
     * <p>全局已有其他操作运行时拒绝启动（防跨 Tab 并发冲突）。
     *
     * @param request 加密请求 DTO（UI 层构造）
     */
    fun startEncrypt(request: EncryptRequest) {
        // 全局操作权占用失败：已有其他 Tab 的操作在运行
        val token = OperationCoordinator.tryAcquire() ?: return
        opToken = token
        // 如果本 VM 仍有上一次任务在收尾，先取消
        currentJob?.cancel()
        _progress.update { it.copy(state = ProgressState.State.RUNNING) }

        currentJob = viewModelScope.launch(Dispatchers.IO) {
            val reporter = LoggingProgressReporter(createProgressReporter(), "Volume")
            request.reporter = reporter
            LogService.beginSession("GENERIC_ENCRYPT", logFileName(request.inputFile))
            val t0 = System.nanoTime()
            var success = false
            var cancelled = false

            try {
                hbnu.project.ergoutreecrypt.volume.Encryptor.encrypt(request)
                success = true
                _progress.update {
                    it.copy(state = ProgressState.State.DONE, progress = 1f)
                }
            } catch (e: CancellationException) {
                cancelled = true
                _progress.update {
                    it.copy(state = ProgressState.State.CANCELLED)
                }
            } catch (e: InterruptedException) {
                cancelled = true
                _progress.update {
                    it.copy(state = ProgressState.State.CANCELLED)
                }
            } catch (e: Exception) {
                LogService.error("GENERIC_ENCRYPT", "任务失败", e)
                _progress.update {
                    it.copy(
                        state = ProgressState.State.ERROR,
                        error = e.localizedMessage ?: e.javaClass.simpleName
                    )
                }
            } catch (e: OutOfMemoryError) {
                LogService.error("GENERIC_ENCRYPT", "内存不足", e)
                _progress.update {
                    it.copy(
                        state = ProgressState.State.ERROR,
                        error = e.toString()
                    )
                }
            } finally {
                val elapsed = logElapsedMillis(t0)
                when {
                    cancelled -> LogService.endSessionCancelled(elapsed)
                    success -> LogService.endSession(true, elapsed)
                    else -> LogService.endSession(false, elapsed)
                }
                // 令牌校验释放：过期任务的释放不会误清新任务
                OperationCoordinator.release(token)
            }
        }
    }

    /**
     * 取消正在进行的加密操作。
     *
     * <p>仅取消当前加密任务，不销毁 ViewModel 作用域。操作权由任务退出时的
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

    /**
     * 创建进度回调实现。
     *
     * <p>将共享核心的 ProgressReporter 回调桥接到 Compose StateFlow，
     * 确保线程安全（ProgressReporter 从后台线程回调）。
     */
    private fun createProgressReporter(): ProgressReporter {
        return object : ProgressReporter {
            override fun setStatus(text: String) {
                _progress.update { it.copy(statusText = text) }
            }

            override fun setProgress(fraction: Float, info: String) {
                _progress.update { it.copy(progress = fraction, info = info) }
            }

            override fun setCanCancel(can: Boolean) {
                _progress.update { it.copy(canCancel = can) }
            }

            override fun isCancelled(): Boolean =
                _progress.value.state == ProgressState.State.CANCELLED
        }
    }
}
