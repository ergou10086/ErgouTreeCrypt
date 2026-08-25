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

    /** 当前操作的全局协调器释放令牌（取消后用于立即归还操作权）。 */
    private var opToken: Long? = null

    /**
     * 开始解密。
     *
     * <p>全局已有其他操作运行时拒绝启动（防跨 Tab 并发冲突）。
     *
     * @param request 解密请求 DTO（UI 层构造）
     */
    fun startDecrypt(request: DecryptRequest) {
        // 全局操作权占用失败：已有其他 Tab 的操作在运行
        val token = OperationCoordinator.tryAcquire() ?: return
        opToken = token
        // 如果本 VM 仍有上一次任务在收尾，先取消
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
            } finally {
                // 令牌校验释放：过期任务的释放不会误清新任务
                OperationCoordinator.release(token)
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
        // 全局操作权占用失败：已有其他 Tab 的操作在运行
        val token = OperationCoordinator.tryAcquire() ?: return
        opToken = token
        // 如果本 VM 仍有上一次任务在收尾，先取消
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
            } finally {
                // 令牌校验释放：过期任务的释放不会误清新任务
                OperationCoordinator.release(token)
            }
        }
    }

    /**
     * 取消正在进行的解密操作。
     *
     * <p>仅取消当前解密任务，不销毁 ViewModel 作用域。操作权由任务退出时的
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
