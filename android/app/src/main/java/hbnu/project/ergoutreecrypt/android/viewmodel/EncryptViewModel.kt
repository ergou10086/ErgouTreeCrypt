package hbnu.project.ergoutreecrypt.android.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import hbnu.project.ergoutreecrypt.android.platform.FileNameSanitizer
import hbnu.project.ergoutreecrypt.android.platform.LoggingProgressReporter
import hbnu.project.ergoutreecrypt.android.platform.errorKind
import hbnu.project.ergoutreecrypt.android.platform.friendlyError
import hbnu.project.ergoutreecrypt.android.platform.logElapsedMillis
import hbnu.project.ergoutreecrypt.android.platform.logFileName
import hbnu.project.ergoutreecrypt.encoding.RsCodecs
import hbnu.project.ergoutreecrypt.exception.CancelledException
import hbnu.project.ergoutreecrypt.exception.ErrorKind
import hbnu.project.ergoutreecrypt.fileops.ArchivePacker
import hbnu.project.ergoutreecrypt.log.LogService
import hbnu.project.ergoutreecrypt.volume.BatchResult
import hbnu.project.ergoutreecrypt.volume.EncryptRequest
import hbnu.project.ergoutreecrypt.volume.Encryptor
import hbnu.project.ergoutreecrypt.volume.FolderCrypt
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
    val kind: ErrorKind? = null,
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

    private companion object {
        /**
         * 移动端文件夹加密使用的迭代深度上限。
         *
         * <p>取上限等价于「逐文件加密、永不触发深目录整体打包」，与移动端既有的
         * 串行、低内存峰值策略一致。
         */
        const val MAX_FOLDER_DEPTH = 32
    }

    /**
     * 开始加密。
     *
     * <p>全局已有其他操作运行时拒绝启动（防跨 Tab 并发冲突）。
     *
     * @param request 加密请求 DTO（UI 层构造）
     */
    fun startEncrypt(request: EncryptRequest) {
        launchVolumeJob("GENERIC_ENCRYPT", logFileName(request.inputFile)) {
            val reporter = LoggingProgressReporter(createProgressReporter(), "Volume")
            request.reporter = reporter
            request.kdfProgress = createKdfProgress()
            Encryptor.encrypt(request)
        }
    }

    /**
     * 加密一批独立文件（视为「同一个文件夹里的多个文件」）。
     *
     * <p>移动端固定单线程并由共享核心负责进度与「不可处理条目跳过」：
     * 失败项计入 {@link FolderCrypt.EncryptOptions} 的批结果，由界面在结束弹窗中汇报。
     *
     * @param inputFiles      待加密文件路径列表
     * @param outputDir       输出目录
     * @param batchName       虚拟文件夹名（产物为 该名/ 目录或 该名.扩展名 压缩包）
     * @param password        加密密码
     * @param reedSolomon     Reed-Solomon 纠错
     * @param deniability     可否认加密
     * @param split           分卷输出
     * @param chunkSize       每卷大小（MiB）
     * @param comments        备注
     * @param preArchiveFormat   压缩后加密的归档格式（null 或空表示不先打包）
     * @param preArchivePassword 压缩后加密的归档密码（仅 ZIP 使用，可为 null）
     * @param archiveFormat   加密后压缩的归档格式（null 或空表示不打包）
     * @param archivePassword 归档密码（仅 ZIP 使用，可为 null）
     * @param keyfiles        密钥文件路径列表
     * @param keyfileOrdered  密钥文件是否有序
     * @param argon2MemoryKib Argon2 内存参数（KiB）
     * @param argon2Passes    Argon2 迭代次数
     * @param argon2Threads   Argon2 并行度
     * @param compress        Zstandard 加密前压缩
     * @param compressionLevel Zstandard 档位
     * @return 批处理汇总对象，调用方可在结束后读取成功/失败/跳过统计
     */
    fun startEncryptBatch(
        inputFiles: List<String>,
        outputDir: String,
        batchName: String,
        password: String,
        reedSolomon: Boolean,
        deniability: Boolean,
        split: Boolean,
        chunkSize: Int,
        comments: String,
        preArchiveFormat: String?,
        preArchivePassword: String?,
        archiveFormat: String?,
        archivePassword: String?,
        keyfiles: List<String>,
        keyfileOrdered: Boolean,
        argon2MemoryKib: Int,
        argon2Passes: Int,
        argon2Threads: Int,
        compress: Boolean,
        compressionLevel: Int
    ): BatchResult {
        val opts = buildFolderOptions(
            outputDir = outputDir,
            password = password,
            reedSolomon = reedSolomon,
            deniability = deniability,
            split = split,
            chunkSize = chunkSize,
            comments = comments,
            preArchiveFormat = preArchiveFormat,
            preArchivePassword = preArchivePassword,
            archiveFormat = archiveFormat,
            archivePassword = archivePassword,
            keyfiles = keyfiles,
            keyfileOrdered = keyfileOrdered,
            argon2MemoryKib = argon2MemoryKib,
            argon2Passes = argon2Passes,
            argon2Threads = argon2Threads,
            compress = compress,
            compressionLevel = compressionLevel
        )
        opts.batchName = batchName
        val paths = inputFiles.map { Paths.get(it) }
        launchVolumeJob("GENERIC_ENCRYPT", batchName) {
            // 进度与取消都要经 reporter 回传，批处理下由核心 FILE 级驱动
            val reporter = LoggingProgressReporter(createProgressReporter(), "Volume")
            opts.reporter = reporter
            opts.kdfProgress = createKdfProgress()
            FolderCrypt.encryptFiles(paths, Paths.get(outputDir), opts)
        }
        return opts.batchResult
    }

    /**
     * 构造文件夹 / 多文件批处理共用的加密选项。
     *
     * <p>移动端固定单线程（{@code threadCount = 1}），并把迭代深度设为最大值，
     * 等价于「逐文件加密、不做深目录打包」，与移动端既有的内存友好策略一致。
     */
    private fun buildFolderOptions(
        outputDir: String,
        password: String,
        reedSolomon: Boolean,
        deniability: Boolean,
        split: Boolean,
        chunkSize: Int,
        comments: String,
        preArchiveFormat: String?,
        preArchivePassword: String?,
        archiveFormat: String?,
        archivePassword: String?,
        keyfiles: List<String>,
        keyfileOrdered: Boolean,
        argon2MemoryKib: Int,
        argon2Passes: Int,
        argon2Threads: Int,
        compress: Boolean = false,
        compressionLevel: Int = 3
    ): FolderCrypt.EncryptOptions {
        val opts = FolderCrypt.EncryptOptions()
        opts.password = password
        opts.comments = comments
        opts.reedSolomon = reedSolomon
        opts.deniability = deniability
        opts.split = split
        opts.chunkSize = chunkSize
        opts.compress = compress
        opts.compressionLevel = compressionLevel
        opts.archiveFormat = if (archiveFormat.isNullOrBlank()) null else archiveFormat
        opts.archivePassword = archivePassword
        opts.preArchiveFormat = if (preArchiveFormat.isNullOrBlank()) null else preArchiveFormat
        opts.preArchivePassword = preArchivePassword
        opts.rsCodecs = RsCodecs()
        if (keyfiles.isNotEmpty()) {
            opts.keyfiles = keyfiles
            opts.keyfileOrdered = keyfileOrdered
        }
        opts.threadCount = 1
        opts.argon2MemoryKib = argon2MemoryKib
        opts.argon2Passes = argon2Passes
        opts.argon2Threads = argon2Threads
        // 深度取上限：移动端不做深目录整体打包，避免一次性读入整个子目录造成内存峰值
        opts.encryptDepth = MAX_FOLDER_DEPTH
        return opts
    }

    /**
     * 统一的卷级任务外壳：占用全局操作权、桥接进度、归拢终态与日志，
     * 保证单文件 / 文件夹 / 多文件三条路径的取消与资源释放行为完全一致。
     *
     * @param opName   操作名（日志与历史用）
     * @param logName  日志中显示的输入名
     * @param onFinally 收尾清理，参数为「本次是否成功」；始终执行
     * @param body     实际工作体
     */
    private fun launchVolumeJob(
        opName: String,
        logName: String?,
        onFinally: (Boolean) -> Unit = {},
        body: suspend () -> Unit
    ) {
        // 全局操作权占用失败：已有其他 Tab 的操作在运行
        val token = OperationCoordinator.tryAcquire() ?: return
        opToken = token
        // 如果本 VM 仍有上一次任务在收尾，先取消
        currentJob?.cancel()
        _progress.update { it.copy(state = ProgressState.State.RUNNING) }

        currentJob = viewModelScope.launch(Dispatchers.IO) {
            LogService.beginSession(opName, logName)
            val t0 = System.nanoTime()
            var success = false
            var cancelled = false

            try {
                body()
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
            } catch (e: CancelledException) {
                cancelled = true
                _progress.update {
                    it.copy(state = ProgressState.State.CANCELLED)
                }
            } catch (e: Exception) {
                LogService.error(opName, "任务失败", e)
                _progress.update {
                    it.copy(
                        state = ProgressState.State.ERROR,
                        error = friendlyError(e),
                        kind = errorKind(e)
                    )
                }
            } catch (e: OutOfMemoryError) {
                LogService.error(opName, "内存不足", e)
                _progress.update {
                    it.copy(
                        state = ProgressState.State.ERROR,
                        error = friendlyError(e),
                        kind = ErrorKind.OUT_OF_MEMORY
                    )
                }
            } finally {
                try {
                    onFinally(success)
                } catch (_: Exception) {
                    // 清理失败不影响操作权释放
                }
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
        argon2Threads: Int,
        preArchiveFormat: String? = null,
        preArchivePassword: String? = null
    ): BatchResult {
        val opts = buildFolderOptions(
            outputDir = outputDir,
            password = password,
            reedSolomon = reedSolomon,
            deniability = deniability,
            split = split,
            chunkSize = chunkSize,
            comments = comments,
            preArchiveFormat = preArchiveFormat,
            preArchivePassword = preArchivePassword,
            archiveFormat = archiveFormat,
            archivePassword = archivePassword,
            keyfiles = keyfiles,
            keyfileOrdered = keyfileOrdered,
            argon2MemoryKib = argon2MemoryKib,
            argon2Passes = argon2Passes,
            argon2Threads = argon2Threads
        )
        val root = Paths.get(inputDir)
        val folderName = FileNameSanitizer.sanitize(root.fileName?.toString() ?: "folder")
        // 结果目录（失败/取消时用于清理半成品）
        var resultDirForCleanup: Path? = null

        launchVolumeJob("GENERIC_ENCRYPT", logFileName(inputDir), onFinally = { success ->
            // 取消/失败时删除结果目录半成品，避免残留（成功路径已在打包后自行删除或保留为产出）
            if (!success) {
                resultDirForCleanup?.toFile()?.deleteRecursively()
            }
        }) {
            val reporter = LoggingProgressReporter(createProgressReporter(), "Volume")
            val kdfProgress = createKdfProgress()
            // 核心的批处理辅助（归档进度等）同样经这两个回调上报
            opts.reporter = reporter
            opts.kdfProgress = kdfProgress

            // 压缩后加密：整体打包成单个归档再加密，天然单文件、内存友好
            if (!preArchiveFormat.isNullOrBlank()) {
                val fmt = ArchivePacker.parseFormat(preArchiveFormat)
                val destEnc = Paths.get(outputDir)
                    .resolve("$folderName${ArchivePacker.extOf(fmt)}.ergou")
                val entries: List<Path> = Files.walk(root).use { stream ->
                    stream.filter { Files.isRegularFile(it) }.sorted().toList()
                }
                if (entries.isEmpty()) {
                    throw java.io.IOException("文件夹为空：$inputDir")
                }
                val tempArchive = Files.createTempFile("ergou-pre-", ArchivePacker.extOf(fmt))
                try {
                    ArchivePacker.packEntries(
                        tempArchive, root, entries, fmt,
                        ArchivePacker.resolveArchivePassword(preArchivePassword, null, fmt),
                        reporter
                    )
                    val req = EncryptRequest()
                    req.inputFile = tempArchive.toString()
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
                } finally {
                    try {
                        Files.deleteIfExists(tempArchive)
                    } catch (_: Exception) {
                        // 临时归档清理失败不影响产物
                    }
                }
                return@launchVolumeJob
            }

            val resultDir = Paths.get(outputDir).resolve("${folderName}_result")
            resultDirForCleanup = resultDir
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
                val destEnc = resultDir.resolve(FileNameSanitizer.sanitizePathSegments(rel.toString()) + ".ergou")
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
                resultDirForCleanup = null
            }
        }
        return opts.batchResult
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

            override fun onSliceProgress(doneSlices: Int, totalSlices: Int) {
                _progress.update { it.copy(statusText = "密钥派生中… 第 $doneSlices/$totalSlices 片") }
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
