package hbnu.project.ergoutreecrypt.android.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import hbnu.project.ergoutreecrypt.volume.DecryptRequest
import hbnu.project.ergoutreecrypt.volume.ProgressReporter
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

/**
 * 文件解密 ViewModel。
 *
 * <p>桥接共享核心 Decryptor 与 Compose UI：
 * <ol>
 *   <li>UI 构建 DecryptRequest DTO</li>
 *   <li>在 IO 协程中调用 Decryptor.decrypt()</li>
 *   <li>通过 ProgressReporter 接口将进度回传到 StateFlow</li>
 * </ol>
 *
 * @author ErgouTree
 * @since 2026/8/11
 */
class DecryptViewModel : ViewModel() {

    private val _progress = MutableStateFlow(ProgressState())
    val progress: StateFlow<ProgressState> = _progress.asStateFlow()

    /** 当前正在运行的解密协程，用于取消操作。 */
    private var currentJob: Job? = null

    /**
     * 开始解密。
     *
     * @param request 解密请求 DTO（UI 层构造）
     */
    fun startDecrypt(request: DecryptRequest) {
        // 如果已有正在运行的操作，先取消
        currentJob?.cancel()
        _progress.update { it.copy(state = ProgressState.State.RUNNING) }

        currentJob = viewModelScope.launch(Dispatchers.IO) {
            val reporter = createProgressReporter()

            request.reporter = reporter

            try {
                hbnu.project.ergoutreecrypt.volume.Decryptor.decrypt(request)
                _progress.update {
                    it.copy(state = ProgressState.State.DONE, progress = 1f)
                }
            } catch (e: InterruptedException) {
                _progress.update {
                    it.copy(state = ProgressState.State.CANCELLED)
                }
            } catch (e: Exception) {
                _progress.update {
                    it.copy(
                        state = ProgressState.State.ERROR,
                        error = e.localizedMessage ?: e.javaClass.simpleName
                    )
                }
            }
        }
    }

    /**
     * 取消正在进行的解密操作。
     *
     * <p>仅取消当前解密任务，不销毁 ViewModel 作用域。
     */
    fun cancel() {
        currentJob?.cancel()
        currentJob = null
        _progress.update { it.copy(state = ProgressState.State.CANCELLED) }
    }

    /**
     * 创建进度回调实现。
     *
     * <p>将共享核心的 ProgressReporter 回调桥接到 Compose StateFlow。
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
