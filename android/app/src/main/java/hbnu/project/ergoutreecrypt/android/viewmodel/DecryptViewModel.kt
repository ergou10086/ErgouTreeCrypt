package hbnu.project.ergoutreecrypt.android.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import hbnu.project.ergoutreecrypt.android.platform.LoggingProgressReporter
import hbnu.project.ergoutreecrypt.android.platform.describeError
import hbnu.project.ergoutreecrypt.android.platform.logElapsedMillis
import hbnu.project.ergoutreecrypt.android.platform.logFileName
import hbnu.project.ergoutreecrypt.encoding.RsCodecs
import hbnu.project.ergoutreecrypt.log.LogService
import hbnu.project.ergoutreecrypt.fileops.ArchivePasswordProvider
import hbnu.project.ergoutreecrypt.fileops.ArchivePostExtract
import hbnu.project.ergoutreecrypt.volume.DecryptRequest
import hbnu.project.ergoutreecrypt.volume.FolderCrypt
import hbnu.project.ergoutreecrypt.volume.ProgressReporter
import hbnu.project.ergoutreecrypt.volume.Verifier
import hbnu.project.ergoutreecrypt.volume.VerifyRequest
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
            val reporter = LoggingProgressReporter(createProgressReporter(), "Volume")
            request.reporter = reporter
            request.kdfProgress = createKdfProgress()
            LogService.beginSession("GENERIC_DECRYPT", logFileName(request.inputFile))
            val t0 = System.nanoTime()
            var success = false
            var cancelled = false

            try {
                hbnu.project.ergoutreecrypt.volume.Decryptor.decrypt(request)
                if (request.isDecryptThenExtract) {
                    val out = request.outputFile?.let { java.nio.file.Paths.get(it) }
                    if (out != null) {
                        ArchivePostExtract.extractIfArchive(
                            out,
                            ArchivePostExtract.maxDepth(request.isRecursiveExtract),
                            reporter,
                            request.archivePasswordProvider
                        )
                    }
                }
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
                LogService.error("GENERIC_DECRYPT", "任务失败", e)
                _progress.update {
                    it.copy(
                        state = ProgressState.State.ERROR,
                        error = describeError(e)
                    )
                }
            } catch (e: OutOfMemoryError) {
                LogService.error("GENERIC_DECRYPT", "内存不足", e)
                _progress.update {
                    it.copy(
                        state = ProgressState.State.ERROR,
                        error = e.toString()
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
     * 校验单个加密文件的完整性（只读校验，不产生明文输出）。
     *
     * <p>对应「校验完整性」模式：仅调用 {@link Verifier#verify} 比对密文 MAC 与 header 认证标签，
     * 不做解密。校验通过表示文件未被篡改；密码错误或数据损坏时抛出异常。
     *
     * @param input        待校验的加密文件路径（.ergou/.pcv 或分卷碎片）
     * @param password     解密密码
     * @param forceDecrypt 是否强制校验（忽略损坏继续）
     * @param recombine    输入是否为分卷碎片需先合并
     * @param keyfiles     密钥文件路径列表
     */
    fun startVerify(
        input: String,
        password: String,
        forceDecrypt: Boolean,
        recombine: Boolean,
        keyfiles: List<String>
    ) {
        // 全局操作权占用失败：已有其他 Tab 的操作在运行
        val token = OperationCoordinator.tryAcquire() ?: return
        opToken = token
        // 如果本 VM 仍有上一次任务在收尾，先取消
        currentJob?.cancel()
        _progress.update { it.copy(state = ProgressState.State.RUNNING) }

        currentJob = viewModelScope.launch(Dispatchers.IO) {
            val reporter = LoggingProgressReporter(createProgressReporter(), "Volume")
            LogService.beginSession("VERIFY", logFileName(input))
            val t0 = System.nanoTime()
            var success = false
            var cancelled = false

            try {
                val req = VerifyRequest()
                req.inputFile = input
                req.password = password
                req.setForceDecrypt(forceDecrypt)
                req.setRecombine(recombine)
                req.setDeniability(false)
                if (keyfiles.isNotEmpty()) {
                    req.keyfiles = keyfiles
                }
                req.rsCodecs = RsCodecs()
                req.reporter = reporter

                Verifier.verify(req)

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
                LogService.error("VERIFY", "任务失败", e)
                _progress.update {
                    it.copy(
                        state = ProgressState.State.ERROR,
                        error = describeError(e)
                    )
                }
            } catch (e: OutOfMemoryError) {
                LogService.error("VERIFY", "内存不足", e)
                _progress.update {
                    it.copy(
                        state = ProgressState.State.ERROR,
                        error = e.toString()
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
     * 自动解密入口：对压缩包 / 文件夹 / 分卷碎片先流式解压再逐文件解密。
     *
     * <p>与桌面端 {@code MainController.startAutoDecrypt} 对齐，桥接共享核心
     * {@link FolderCrypt#decryptAuto}，避免把归档文件误当作单卷送入 {@link hbnu.project.ergoutreecrypt.volume.Decryptor}。
     *
     * @param input                  输入路径（归档 / 目录 / 分卷碎片）
     * @param outputDir              输出目录
     * @param password               加密密码
     * @param archivePassword        归档密码（可为 null/空）
     * @param archivePasswordProvider 归档密码提供者（弹窗询问），可为 null
     * @param forceDecrypt           是否强制解密
     * @param recursiveExtract       是否加深嵌套压缩包处理层数（2 → 5）
     * @param extractThenDecrypt     是否解压后解密（明文压缩包先解压再解密）
     * @param decryptThenExtract     是否解密后解压（加密归档解密后再解压到同名文件夹）
     * @param keyfiles               密钥文件路径列表
     */
    fun startAutoDecrypt(
        input: String,
        outputDir: String,
        password: String,
        archivePassword: String?,
        archivePasswordProvider: ArchivePasswordProvider?,
        forceDecrypt: Boolean,
        recursiveExtract: Boolean,
        extractThenDecrypt: Boolean,
        decryptThenExtract: Boolean,
        keyfiles: List<String>
    ) {
        // 全局操作权占用失败：已有其他 Tab 的操作在运行
        val token = OperationCoordinator.tryAcquire() ?: return
        opToken = token
        // 如果本 VM 仍有上一次任务在收尾，先取消
        currentJob?.cancel()
        _progress.update { it.copy(state = ProgressState.State.RUNNING) }

        currentJob = viewModelScope.launch(Dispatchers.IO) {
            val reporter = LoggingProgressReporter(createProgressReporter(), "Volume")
            val opts = FolderCrypt.DecryptOptions()
            opts.password = password
            opts.archivePassword = archivePassword
            opts.archivePasswordProvider = archivePasswordProvider
            opts.forceDecrypt = forceDecrypt
            opts.recursiveExtract = recursiveExtract
            opts.extractThenDecrypt = extractThenDecrypt
            opts.decryptThenExtract = decryptThenExtract
            opts.rsCodecs = RsCodecs()
            if (keyfiles.isNotEmpty()) {
                opts.keyfiles = keyfiles
            }
            opts.reporter = reporter
            opts.threadCount = 1
            LogService.beginSession("GENERIC_DECRYPT", logFileName(input))
            val t0 = System.nanoTime()
            var success = false
            var cancelled = false

            try {
                FolderCrypt.decryptAuto(Paths.get(input), Paths.get(outputDir), opts)
                val batch = opts.batchResult
                val summary = batch?.formatSummary()
                val detail = batch?.formatDetail()?.ifBlank { null }
                val partial = batch != null && batch.hasFailures() && batch.hasSuccesses()
                _progress.update {
                    it.copy(
                        state = ProgressState.State.DONE,
                        progress = 1f,
                        statusText = summary ?: it.statusText,
                        detail = detail,
                        error = if (partial) summary else null
                    )
                }
                success = true
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
                LogService.error("GENERIC_DECRYPT", "任务失败", e)
                val batch = opts.batchResult
                _progress.update {
                    it.copy(
                        state = ProgressState.State.ERROR,
                        error = describeError(e),
                        detail = batch?.formatDetail()?.ifBlank { null },
                        statusText = batch?.formatSummary() ?: it.statusText
                    )
                }
            } catch (e: OutOfMemoryError) {
                LogService.error("GENERIC_DECRYPT", "内存不足", e)
                val batch = opts.batchResult
                _progress.update {
                    it.copy(
                        state = ProgressState.State.ERROR,
                        error = e.toString(),
                        detail = batch?.formatDetail()?.ifBlank { null }
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
     * 创建 Argon2 密钥派生的进度/取消回调。
     *
     * <p>移动端解密桌面端 1 GiB 文件时离堆派生可能持续数分钟，此回调把 pass 粒度
     * 进度写入状态文案，避免"卡在 0%"；取消信号与协程取消一致。
     *
     * @return KDF 进度回调
     */
    private fun createKdfProgress(): hbnu.project.ergoutreecrypt.crypto.KdfProgress {
        return object : hbnu.project.ergoutreecrypt.crypto.KdfProgress {
            override fun onProgress(pass: Int, totalPasses: Int) {
                _progress.update { it.copy(statusText = "密钥派生中… 第 $pass/$totalPasses 轮") }
            }

            override fun isCancelled(): Boolean =
                _progress.value.state == ProgressState.State.CANCELLED
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
