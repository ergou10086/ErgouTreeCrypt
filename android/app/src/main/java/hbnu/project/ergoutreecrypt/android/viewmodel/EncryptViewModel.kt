package hbnu.project.ergoutreecrypt.android.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import hbnu.project.ergoutreecrypt.android.platform.LoggingProgressReporter
import hbnu.project.ergoutreecrypt.android.platform.describeError
import hbnu.project.ergoutreecrypt.android.platform.logElapsedMillis
import hbnu.project.ergoutreecrypt.android.platform.logFileName
import hbnu.project.ergoutreecrypt.encoding.RsCodecs
import hbnu.project.ergoutreecrypt.fileops.ArchivePacker
import hbnu.project.ergoutreecrypt.log.LogService
import hbnu.project.ergoutreecrypt.volume.EncryptRequest
import hbnu.project.ergoutreecrypt.volume.Encryptor
import hbnu.project.ergoutreecrypt.volume.ProgressReporter
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlin.streams.toList
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths

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
            request.kdfProgress = createKdfProgress()
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
                        error = describeError(e)
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
     * 开始加密一个文件夹。
     *
     * <p>移动端文件夹加密固定串行、逐文件处理：在输出目录创建「文件夹名_result」目录，
     * 递归收集全部常规文件后，一次只加密一个文件，加密结果按相对路径镜像写入结果目录，
     * 处理完一个再处理下一个，避免多线程叠加与深目录打包造成的内存峰值与闪退。
     * 不使用迭代深度，也不启用 Zstandard 加密前压缩。
     * 若启用「加密后压缩」，全部文件加密完成后把整个结果目录打包为单个归档并删除结果目录。
     *
     * @param inputDir        输入文件夹路径
     * @param outputDir       输出目录（结果文件夹将创建于其下）
     * @param password        加密密码
     * @param reedSolomon     Reed-Solomon 纠错
     * @param deniability     可否认加密
     * @param split           分卷输出
     * @param chunkSize       每卷大小（MiB）
     * @param comments        备注
     * @param archiveFormat   加密后压缩的归档格式（null 或空表示不打包）
     * @param archivePassword 归档密码（仅 ZIP 使用，可为 null）
     * @param keyfiles        密钥文件路径列表
     * @param keyfileOrdered  密钥文件是否有序
     * @param argon2MemoryKib Argon2 内存参数（KiB）
     * @param argon2Passes    Argon2 迭代次数
     * @param argon2Threads   Argon2 并行度
     */
    fun startEncryptFolder(
        inputDir: String,
        outputDir: String,
        password: String,
        reedSolomon: Boolean,
        deniability: Boolean,
        split: Boolean,
        chunkSize: Int,
        comments: String,
        archiveFormat: String?,
        archivePassword: String?,
        keyfiles: List<String>,
        keyfileOrdered: Boolean,
        argon2MemoryKib: Int,
        argon2Passes: Int,
        argon2Threads: Int
    ) {
        // 全局操作权占用失败：已有其他 Tab 的操作在运行
        val token = OperationCoordinator.tryAcquire() ?: return
        opToken = token
        // 如果本 VM 仍有上一次任务在收尾，先取消
        currentJob?.cancel()
        _progress.update { it.copy(state = ProgressState.State.RUNNING) }

        currentJob = viewModelScope.launch(Dispatchers.IO) {
            val reporter = LoggingProgressReporter(createProgressReporter(), "Volume")
            val kdfProgress = createKdfProgress()
            LogService.beginSession("GENERIC_ENCRYPT", logFileName(inputDir))
            val t0 = System.nanoTime()
            var success = false
            var cancelled = false

            try {
                val root = Paths.get(inputDir)
                val folderName = root.fileName?.toString() ?: "folder"
                val resultDir = Paths.get(outputDir).resolve("${folderName}_result")
                Files.createDirectories(resultDir)

                // 递归收集全部常规文件，按路径排序保证稳定顺序
                val files: List<Path> = Files.walk(root).use { stream ->
                    stream.filter { Files.isRegularFile(it) }.sorted().toList()
                }
                if (files.isEmpty()) {
                    throw java.io.IOException("文件夹为空：$inputDir")
                }

                val total = files.size
                var done = 0
                for (file in files) {
                    if (_progress.value.state == ProgressState.State.CANCELLED) {
                        throw InterruptedException("cancelled")
                    }
                    val rel = root.relativize(file)
                    val destEnc = resultDir.resolve(rel.toString() + ".ergou")
                    Files.createDirectories(destEnc.parent)

                    val req = EncryptRequest()
                    req.inputFile = file.toString()
                    req.outputFile = destEnc.toString()
                    req.password = password
                    req.setReedSolomon(reedSolomon)
                    req.setDeniability(deniability)
                    req.setCompress(false)
                    req.setSplit(split)
                    req.chunkSize = chunkSize
                    req.comments = comments
                    req.argon2MemoryKib = argon2MemoryKib
                    req.argon2Passes = argon2Passes
                    req.argon2Threads = argon2Threads
                    req.setArchiveFormat(null)
                    if (keyfiles.isNotEmpty()) {
                        req.keyfiles = keyfiles
                        req.setKeyfileOrdered(keyfileOrdered)
                    }
                    req.rsCodecs = RsCodecs()
                    req.reporter = reporter
                    req.kdfProgress = kdfProgress

                    Encryptor.encrypt(req)

                    done++
                    _progress.update {
                        it.copy(
                            progress = done.toFloat() / total,
                            statusText = "加密中 $done/$total"
                        )
                    }
                }

                // 若启用「加密后压缩」：把整个结果目录打成单个归档，再删除结果目录
                if (!archiveFormat.isNullOrBlank()) {
                    val fmt = ArchivePacker.parseFormat(archiveFormat)
                    val archivePath = Paths.get(outputDir)
                        .resolve("${folderName}_result${ArchivePacker.extOf(fmt)}")
                    val entries: List<Path> = Files.walk(resultDir).use { stream ->
                        stream.filter { Files.isRegularFile(it) }.sorted().toList()
                    }
                    if (entries.isNotEmpty()) {
                        val archPwd = ArchivePacker.resolveArchivePassword(
                            archivePassword, password, fmt
                        )
                        ArchivePacker.packEntries(
                            archivePath, resultDir, entries, fmt, archPwd, reporter
                        )
                    }
                    resultDir.toFile().deleteRecursively()
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
                LogService.error("GENERIC_ENCRYPT", "任务失败", e)
                _progress.update {
                    it.copy(
                        state = ProgressState.State.ERROR,
                        error = describeError(e)
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
     * 创建 Argon2 密钥派生的进度/取消回调。
     *
     * <p>离堆派生（移动端解密桌面端 1 GiB 文件）可能持续数分钟，此回调把
     * pass 粒度进度写入状态文案，让 UI 不再"卡在 0%"；取消信号与协程取消一致。
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
