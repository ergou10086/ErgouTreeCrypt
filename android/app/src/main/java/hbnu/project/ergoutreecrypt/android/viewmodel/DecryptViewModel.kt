package hbnu.project.ergoutreecrypt.android.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import hbnu.project.ergoutreecrypt.encoding.RsCodecs
import hbnu.project.ergoutreecrypt.volume.DecryptRequest
import hbnu.project.ergoutreecrypt.volume.FolderCrypt
import hbnu.project.ergoutreecrypt.volume.ProgressReporter
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import java.nio.file.Paths

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
            } catch (e: OutOfMemoryError) {
                _progress.update {
                    it.copy(
                        state = ProgressState.State.ERROR,
                        error = e.toString()
                    )
                }
            }
        }
    }

    /**
     * 自动解密入口：对压缩包 / 文件夹 / 分卷碎片先流式解压再逐文件解密。
     *
     * <p>与桌面端 {@code MainController.startAutoDecrypt} 对齐，桥接共享核心
     * {@link FolderCrypt#decryptAuto}，避免把归档文件误当作单卷送入 {@link hbnu.project.ergoutreecrypt.volume.Decryptor}。
     *
     * @param input            输入路径（归档 / 目录 / 分卷碎片）
     * @param outputDir        输出目录
     * @param password         加密密码
     * @param archivePassword  归档密码（可为 null/空）
     * @param forceDecrypt     是否强制解密
     * @param recursiveExtract 是否递归解压嵌套压缩包
     * @param keyfiles         密钥文件路径列表
     */
    fun startAutoDecrypt(
        input: String,
        outputDir: String,
        password: String,
        archivePassword: String?,
        forceDecrypt: Boolean,
        recursiveExtract: Boolean,
        keyfiles: List<String>
    ) {
        currentJob?.cancel()
        _progress.update { it.copy(state = ProgressState.State.RUNNING) }

        currentJob = viewModelScope.launch(Dispatchers.IO) {
            val reporter = createProgressReporter()
            val opts = FolderCrypt.DecryptOptions()
            opts.password = password
            opts.archivePassword = archivePassword
            opts.forceDecrypt = forceDecrypt
            opts.recursiveExtract = recursiveExtract
            opts.autoUnzip = true
            opts.rsCodecs = RsCodecs()
            if (keyfiles.isNotEmpty()) {
                opts.keyfiles = keyfiles
            }
            opts.reporter = reporter
            opts.threadCount = 1

            try {
                FolderCrypt.decryptAuto(Paths.get(input), Paths.get(outputDir), opts)
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
            } catch (e: OutOfMemoryError) {
                _progress.update {
                    it.copy(
                        state = ProgressState.State.ERROR,
                        error = e.toString()
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
