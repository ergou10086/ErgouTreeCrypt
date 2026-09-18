package hbnu.project.ergoutreecrypt.android.viewmodel

import android.app.Application
import android.content.Intent
import android.net.Uri
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import hbnu.project.ergoutreecrypt.android.platform.AndroidFileOps
import hbnu.project.ergoutreecrypt.android.platform.AndroidSettings
import hbnu.project.ergoutreecrypt.android.platform.ImageKdfAssessment
import hbnu.project.ergoutreecrypt.android.platform.KdfPreflight
import hbnu.project.ergoutreecrypt.android.platform.MaterializedImageInput
import hbnu.project.ergoutreecrypt.android.platform.MediaStoreCollection
import hbnu.project.ergoutreecrypt.android.platform.OutputDirResolver
import hbnu.project.ergoutreecrypt.android.platform.PendingOutput
import hbnu.project.ergoutreecrypt.android.platform.errorKind
import hbnu.project.ergoutreecrypt.android.platform.friendlyError
import hbnu.project.ergoutreecrypt.android.platform.logElapsedMillis
import hbnu.project.ergoutreecrypt.filetypes.FileInputGuard
import hbnu.project.ergoutreecrypt.filetypes.OutputNaming
import hbnu.project.ergoutreecrypt.history.HistoryService
import hbnu.project.ergoutreecrypt.history.OperationType
import hbnu.project.ergoutreecrypt.i18n.Messages
import hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptCodec
import hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptMetadata
import hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptMode
import hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptOptions
import hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptPassword
import hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptPhase
import hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptProgress
import hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptRobustness
import hbnu.project.ergoutreecrypt.imagecrypt.ImageProbe
import hbnu.project.ergoutreecrypt.log.LogService
import hbnu.project.ergoutreecrypt.exception.CancelledException
import hbnu.project.ergoutreecrypt.exception.ErrorKind
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import java.io.File
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.atomic.AtomicBoolean

/**
 * 图片页面的操作方向。
 */
enum class ImageCryptDirection {
    /** 把普通图片封装为 EGTC-IMG PNG。 */
    ENCRYPT,

    /** 认证并逐字节还原 EGTC-IMG PNG。 */
    RESTORE
}

/**
 * 一次图片操作成功后的可展示结果。
 *
 * @property title 结果标题
 * @property message 结果说明
 * @property outputName 最终输出文件名
 * @property sharePath 可分享的私有或公开 PNG 路径；还原操作为 {@code null}
 */
data class ImageCryptResultInfo(
    val title: String,
    val message: String,
    val outputName: String,
    val sharePath: String? = null
)

/**
 * 图片页面的完整表单与任务状态。
 *
 * @property direction 当前加密/还原分段
 * @property mode 新建密文的保护模式
 * @property password 密码输入
 * @property confirmPassword 加密时的密码确认
 * @property errorCorrection 是否使用抗图片重编码纠错载体
 * @property robustness 抗图片重编码强度
 * @property bestEffort 是否允许提交认证失败的有损恢复结果
 * @property inputName 输入显示名
 * @property inputBytes 输入字节数
 * @property inputDescription 格式、尺寸或协议元数据描述
 * @property inputPreviewPath 私有输入副本的有界预览路径
 * @property metadata 还原输入的有界协议元数据
 * @property selecting 是否正在从 URI 流式物化输入
 * @property outputTreeUri 用户选择的 SAF 输出目录 URI 字符串
 * @property outputTarget 输出位置说明
 * @property kdfAssessment 固定 64 MiB KDF 的设备资源快照
 * @property progress 任务进度
 * @property result 成功结果
 * @property resultPreviewPath 最近一次当前方向处理结果的预览路径
 * @property resultPreviewTitle 结果预览标题
 * @property formError 表单或选择错误
 */
data class ImageCryptUiState(
    val direction: ImageCryptDirection = ImageCryptDirection.ENCRYPT,
    val mode: ImageCryptMode = ImageCryptMode.PUBLIC_RECOVERY,
    val password: String = "",
    val confirmPassword: String = "",
    val errorCorrection: Boolean = false,
    val robustness: ImageCryptRobustness = ImageCryptRobustness.BALANCED,
    val bestEffort: Boolean = false,
    val inputName: String? = null,
    val inputBytes: Long = 0L,
    val inputDescription: String = "",
    val inputPreviewPath: String? = null,
    val metadata: ImageCryptMetadata? = null,
    val selecting: Boolean = false,
    val outputTreeUri: String? = null,
    val outputTarget: String = "",
    val kdfAssessment: ImageKdfAssessment? = null,
    val progress: ProgressState = ProgressState(),
    val result: ImageCryptResultInfo? = null,
    val resultPreviewPath: String? = null,
    val resultPreviewTitle: String? = null,
    val formError: String? = null
)

/**
 * EGTC-IMG Android 工作流 ViewModel。
 *
 * <p>ViewModel 处于 Activity 作用域，页面切换与旋转不会清空表单或中断任务。所有图片字节
 * 都以流式文件形式交给共享 {@link ImageCryptCodec}，不创建原图 Bitmap。输出在 SAF 或
 * MediaStore 场景下一律先写应用私有目录；还原只有在共享核心完成 MAC 校验并提交最终文件后，
 * 才复制到公共位置。
 *
 * @param application Android Application
 */
class ImageCryptViewModel(application: Application) : AndroidViewModel(application) {

    /** 共享图片编解码门面。 */
    private val codec = ImageCryptCodec()

    /** Android URI、暂存、提交与分享适配器。 */
    private val fileOps = AndroidFileOps(application.applicationContext)

    /** Android 设置存储。 */
    private val settings = AndroidSettings(application.applicationContext)

    /** Compose 可观察页面状态。 */
    private val _uiState = MutableStateFlow(ImageCryptUiState())

    /** Compose 只读页面状态。 */
    val uiState: StateFlow<ImageCryptUiState> = _uiState.asStateFlow()

    /** 当前物化输入，生命周期由本 ViewModel 精确管理。 */
    private var selectedInput: MaterializedImageInput? = null

    /** 当前工作协程。 */
    private var currentJob: Job? = null

    /** 核心 I/O 循环读取的取消标记。 */
    private val cancelRequested = AtomicBoolean(false)

    /** 当前全局操作协调器令牌。 */
    private var operationToken: Long? = null

    /** 为结果预览或分享保留的成功任务临时目录；下次输入或任务时清理。 */
    private var retainedResultDir: File? = null

    init {
        viewModelScope.launch(Dispatchers.IO) {
            val defaultMode = settings.imageCryptDefaultMode.first()
            val assessment = KdfPreflight.assessImageKdf(getApplication())
            val target = describeDefaultTarget()
            _uiState.update { state ->
                state.copy(
                    mode = if (defaultMode == ImageCryptMode.PASSWORD.name) {
                        ImageCryptMode.PASSWORD
                    } else {
                        ImageCryptMode.PUBLIC_RECOVERY
                    },
                    kdfAssessment = assessment,
                    outputTarget = target
                )
            }
        }
    }

    /**
     * 切换加密或还原方向。
     *
     * <p>运行期间不允许切换。空闲切换会清除旧方向的输入副本，避免把普通图片误送入还原流程。
     *
     * @param direction 新方向
     */
    fun setDirection(direction: ImageCryptDirection) {
        if (isRunning() || direction == _uiState.value.direction) {
            return
        }
        cleanupSelectedInput()
        cleanupRetainedResult()
        _uiState.update {
            it.copy(
                direction = direction,
                inputName = null,
                inputBytes = 0L,
                inputDescription = "",
                inputPreviewPath = null,
                metadata = null,
                password = "",
                confirmPassword = "",
                formError = null,
                result = null,
                resultPreviewPath = null,
                resultPreviewTitle = null
            )
        }
    }

    /**
     * 设置新建密文的保护模式并持久化为下次默认值。
     *
     * @param mode 公开恢复或密码保护
     */
    fun setMode(mode: ImageCryptMode) {
        if (isRunning()) {
            return
        }
        _uiState.update { it.copy(mode = mode, formError = null) }
        viewModelScope.launch(Dispatchers.IO) {
            settings.setImageCryptDefaultMode(mode.name)
        }
    }

    /**
     * 设置加密时是否启用抗重编码纠错载体。
     *
     * @param enabled true 表示启用纠错载体
     */
    fun setErrorCorrection(enabled: Boolean) {
        if (!isRunning()) {
            _uiState.update { it.copy(errorCorrection = enabled, formError = null) }
        }
    }

    /**
     * 设置抗图片重编码纠错强度。
     *
     * @param robustness 均衡、增强或极强档
     */
    fun setRobustness(robustness: ImageCryptRobustness) {
        if (!isRunning() && robustness.enabled()) {
            _uiState.update { it.copy(robustness = robustness, formError = null) }
        }
    }

    /**
     * 设置解密时是否允许尽力恢复损坏图片。
     *
     * @param enabled true 表示允许忽略最终认证失败
     */
    fun setBestEffort(enabled: Boolean) {
        if (!isRunning()) {
            _uiState.update { it.copy(bestEffort = enabled, formError = null) }
        }
    }

    /**
     * 更新密码文本。
     *
     * @param password 新密码
     */
    fun setPassword(password: String) {
        if (!isRunning()) {
            _uiState.update { it.copy(password = password, formError = null) }
        }
    }

    /**
     * 更新加密密码确认文本。
     *
     * @param password 新确认密码
     */
    fun setConfirmPassword(password: String) {
        if (!isRunning()) {
            _uiState.update { it.copy(confirmPassword = password, formError = null) }
        }
    }

    /**
     * 从 {@code OpenDocument} URI 流式物化并预检输入。
     *
     * <p>加密方向使用 {@link ImageProbe} 二次验证真实魔数；还原方向读取有界 EGTC-IMG 元数据。
     * 选择器给出的图片 MIME 通配范围只作为第一层过滤，不作为格式身份依据。
     *
     * @param uri 文件选择器返回的 URI
     */
    fun selectInput(uri: Uri) {
        if (isRunning()) {
            return
        }
        cleanupRetainedResult()
        _uiState.update {
            it.copy(
                selecting = true,
                formError = null,
                result = null,
                resultPreviewPath = null,
                resultPreviewTitle = null
            )
        }
        viewModelScope.launch(Dispatchers.IO) {
            var candidate: MaterializedImageInput? = null
            try {
                candidate = fileOps.materializeImageInput(uri)
                    ?: throw IllegalStateException("无法读取所选图片，请重新授权后再试")
                val direction = _uiState.value.direction
                val feature = if (direction == ImageCryptDirection.ENCRYPT) {
                    FileInputGuard.Feature.IMAGE_CRYPT_ENCRYPT
                } else {
                    FileInputGuard.Feature.IMAGE_CRYPT_DECRYPT
                }
                val guard = FileInputGuard.check(
                    feature,
                    FileInputGuard.Options.none(),
                    candidate.file.toPath()
                )
                if (guard.rejected()) {
                    throw IllegalArgumentException(guard.message())
                }

                val path = candidate.file.toPath()
                val size = Files.size(path)
                val metadata: ImageCryptMetadata?
                val description: String
                if (direction == ImageCryptDirection.ENCRYPT) {
                    val probe = ImageProbe.probe(path)
                    if (!probe.recognized()) {
                        throw IllegalArgumentException("仅支持 PNG/APNG、JPEG、GIF、BMP 与 WebP")
                    }
                    metadata = null
                    val dimensions = if (probe.hasSizeHint()) {
                        " · ${probe.width()}×${probe.height()}"
                    } else {
                        ""
                    }
                    description = "${probe.format().name}$dimensions · ${humanSize(size)}"
                } else {
                    metadata = KdfPreflight.peekImageMetadata(path)
                        ?: throw IllegalArgumentException("未检测到有效的 EGTC-IMG 协议头")
                    val protection = if (metadata.requiresPassword()) "密码保护" else "公开恢复"
                    description = "EGTC-IMG v${metadata.protocolVersion()} · $protection · " +
                        "画布 ${metadata.canvasWidth()}×${metadata.canvasHeight()} · " +
                        "预计恢复 ≤ ${humanSize(metadata.maxRestoredBytes())}"
                }

                val previous = selectedInput
                selectedInput = candidate
                candidate = null
                fileOps.cleanupImageInput(previous)
                _uiState.update {
                    it.copy(
                        selecting = false,
                        inputName = selectedInput?.displayName,
                        inputBytes = size,
                        inputDescription = description,
                        inputPreviewPath = selectedInput?.file?.absolutePath,
                        metadata = metadata,
                        password = "",
                        confirmPassword = "",
                        formError = null
                    )
                }
            } catch (e: Exception) {
                fileOps.cleanupImageInput(candidate)
                _uiState.update {
                    it.copy(selecting = false, formError = friendlySelectionError(e))
                }
            }
        }
    }

    /**
     * 清空当前输入、结果弹窗和两类预览。
     */
    fun clearInput() {
        if (isRunning()) {
            return
        }
        cleanupSelectedInput()
        cleanupRetainedResult()
        _uiState.update {
            it.copy(
                inputName = null,
                inputBytes = 0L,
                inputDescription = "",
                inputPreviewPath = null,
                metadata = null,
                password = "",
                confirmPassword = "",
                result = null,
                resultPreviewPath = null,
                resultPreviewTitle = null,
                formError = null
            )
        }
    }

    /**
     * 设置或清除用户选择的 SAF 输出目录。
     *
     * @param uri 目录树 URI；为 {@code null} 时恢复默认输出位置
     */
    fun setOutputTree(uri: Uri?) {
        if (isRunning()) {
            return
        }
        if (uri != null) {
            try {
                getApplication<Application>().contentResolver.takePersistableUriPermission(
                    uri,
                    Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION
                )
            } catch (_: Exception) {
                // 个别文档提供者只提供临时授权，当前 Activity 生命周期内仍可使用。
            }
            _uiState.update {
                it.copy(outputTreeUri = uri.toString(), outputTarget = "所选文件夹（SAF）")
            }
        } else {
            viewModelScope.launch(Dispatchers.IO) {
                val target = describeDefaultTarget()
                _uiState.update { it.copy(outputTreeUri = null, outputTarget = target) }
            }
        }
    }

    /**
     * 启动当前图片加密或还原任务。
     */
    fun start() {
        if (isRunning()) {
            return
        }
        val snapshot = _uiState.value
        val input = selectedInput
        val validation = validate(snapshot, input)
        if (validation != null) {
            _uiState.update { it.copy(formError = validation) }
            return
        }
        val token = OperationCoordinator.tryAcquire()
        if (token == null) {
            _uiState.update { it.copy(formError = "已有其他加解密任务正在运行") }
            return
        }
        operationToken = token
        cancelRequested.set(false)
        cleanupRetainedResult()
        _uiState.update {
            it.copy(
                progress = ProgressState(
                    statusText = "准备图片任务…",
                    state = ProgressState.State.RUNNING,
                    canCancel = true
                ),
                result = null,
                resultPreviewPath = null,
                resultPreviewTitle = null,
                formError = null
            )
        }

        currentJob = viewModelScope.launch(Dispatchers.IO) {
            execute(snapshot, requireNotNull(input), token)
        }
        currentJob?.invokeOnCompletion { OperationCoordinator.release(token) }
    }

    /**
     * 请求取消当前任务。
     *
     * <p>不直接销毁执行协程，而是设置共享核心每个不超过 1 MiB I/O 块都会读取的标记，
     * 让核心先关闭流并删除 {@code .part} 后再进入取消终态。
     */
    fun cancel() {
        if (!isRunning()) {
            return
        }
        cancelRequested.set(true)
        _uiState.update {
            it.copy(progress = it.progress.copy(statusText = "正在取消并清理临时文件…", canCancel = false))
        }
    }

    /**
     * 分享最近一次加密成功的 PNG。
     *
     * @return 是否成功拉起系统分享面板
     */
    fun shareResult(): Boolean {
        val path = _uiState.value.result?.sharePath ?: return false
        return fileOps.shareEncryptedPng(File(path))
    }

    /**
     * 关闭结果弹窗，并保留下方结果预览直到输入、方向或任务发生变化。
     */
    fun dismissResult() {
        _uiState.update { it.copy(result = null) }
    }

    /**
     * 执行一次完整工作流。
     *
     * @param snapshot 启动瞬间冻结的表单状态
     * @param input 已物化输入
     * @param token 全局操作令牌
     */
    private suspend fun execute(
        snapshot: ImageCryptUiState,
        input: MaterializedImageInput,
        token: Long
    ) {
        val operationName = if (snapshot.direction == ImageCryptDirection.ENCRYPT) {
            "IMAGE_ENCRYPT"
        } else {
            "IMAGE_DECRYPT"
        }
        LogService.beginSession(operationName, input.displayName)
        val started = System.nanoTime()
        var plan: OutputPlan? = null
        var passwordBytes: ByteArray? = null
        var success = false
        var cancelled = false
        try {
            plan = prepareOutput(snapshot.outputTreeUri)
            passwordBytes = passwordBytes(snapshot)
            val progress = createProgress()
            val resultPath: Path
            if (snapshot.direction == ImageCryptDirection.ENCRYPT) {
                val outputName = OutputNaming.imageCryptOutputName(input.file.name)
                resultPath = plan.directory.resolve(outputName)
                codec.encrypt(
                    input.file.toPath(),
                    resultPath,
                    passwordBytes,
                    ImageCryptOptions(
                        snapshot.mode,
                        false,
                        if (snapshot.errorCorrection) {
                            snapshot.robustness
                        } else {
                            ImageCryptRobustness.NONE
                        }
                    ),
                    progress
                )
            } else {
                resultPath = codec.decrypt(
                    input.file.toPath(),
                    plan.directory,
                    passwordBytes,
                    false,
                    snapshot.bestEffort,
                    progress
                )
            }
            if (cancelRequested.get()) {
                throw CancelledException()
            }
            if (plan.pending != null && !fileOps.commitOutput(plan.pending)) {
                throw IllegalStateException("处理已完成，但提交到目标目录失败，请检查目录权限")
            }
            if (plan.scanAfterCommit) {
                fileOps.scanImageFile(resultPath.toFile())
            }

            val outputName = resultPath.fileName.toString()
            val publicPath = if (plan.pending == null) {
                resultPath.toString()
            } else {
                File(plan.historyDirectory, outputName).absolutePath
            }
            val type = if (snapshot.direction == ImageCryptDirection.ENCRYPT) {
                OperationType.IMAGE_ENCRYPT
            } else {
                OperationType.IMAGE_DECRYPT
            }
            HistoryService.record(type, outputName, publicPath, plan.outputTreeUri)

            if (plan.pending != null) {
                retainedResultDir = plan.pending.tempDir
            }
            val sharePath = if (snapshot.direction == ImageCryptDirection.ENCRYPT) {
                resultPath.toString()
            } else {
                null
            }
            success = true
            _uiState.update {
                it.copy(
                    password = "",
                    confirmPassword = "",
                    progress = it.progress.copy(
                        statusText = "完成",
                        progress = 1f,
                        canCancel = false,
                        state = ProgressState.State.DONE
                    ),
                    result = ImageCryptResultInfo(
                        title = if (snapshot.direction == ImageCryptDirection.ENCRYPT) {
                            "图片加密完成"
                        } else {
                            "图片还原完成"
                        },
                        message = "已保存到 ${plan.historyDirectory}\n输出文件：$outputName",
                        outputName = outputName,
                        sharePath = sharePath
                    ),
                    resultPreviewPath = resultPath.toString(),
                    resultPreviewTitle = if (snapshot.direction == ImageCryptDirection.ENCRYPT) {
                        "加密结果预览"
                    } else {
                        "解密还原结果预览"
                    }
                )
            }
        } catch (e: CancelledException) {
            cancelled = true
            cleanupPending(plan)
            _uiState.update {
                it.copy(
                    password = "",
                    confirmPassword = "",
                    progress = it.progress.copy(
                        statusText = "已取消",
                        canCancel = false,
                        state = ProgressState.State.CANCELLED
                    )
                )
            }
        } catch (e: CancellationException) {
            cancelled = true
            cleanupPending(plan)
            _uiState.update {
                it.copy(progress = it.progress.copy(state = ProgressState.State.CANCELLED, canCancel = false))
            }
        } catch (e: Exception) {
            cleanupPending(plan)
            LogService.error(operationName, "任务失败", e)
            _uiState.update {
                it.copy(
                    password = "",
                    confirmPassword = "",
                    progress = it.progress.copy(
                        statusText = "操作失败",
                        canCancel = false,
                        state = ProgressState.State.ERROR,
                        error = friendlyError(e),
                        kind = errorKind(e)
                    )
                )
            }
        } catch (e: OutOfMemoryError) {
            cleanupPending(plan)
            LogService.error(operationName, "内存不足", e)
            _uiState.update {
                it.copy(
                    password = "",
                    confirmPassword = "",
                    progress = it.progress.copy(
                        statusText = "设备内存不足",
                        canCancel = false,
                        state = ProgressState.State.ERROR,
                        error = "EGTC-IMG v1 密码模式固定需要 64 MiB Argon2 内存，请关闭其它应用后重试",
                        kind = ErrorKind.OUT_OF_MEMORY
                    )
                )
            }
        } finally {
            passwordBytes?.fill(0)
            OperationCoordinator.release(token)
            operationToken = null
            currentJob = null
            val elapsed = logElapsedMillis(started)
            try {
                when {
                    cancelled -> LogService.endSessionCancelled(elapsed)
                    success -> LogService.endSession(true, elapsed)
                    else -> LogService.endSession(false, elapsed)
                }
            } catch (_: Throwable) {
                // 日志收尾失败不改变图片任务结果。
            }
        }
    }

    /**
     * 创建共享核心进度回调。
     *
     * @return 线程安全的 StateFlow 桥接回调
     */
    private fun createProgress(): ImageCryptProgress {
        return object : ImageCryptProgress {
            /** {@inheritDoc} */
            override fun onPhase(phase: ImageCryptPhase) {
                val text = try {
                    Messages.get(phase.i18nKey())
                } catch (_: Exception) {
                    phase.name
                }
                _uiState.update { it.copy(progress = it.progress.copy(statusText = text)) }
            }

            /** {@inheritDoc} */
            override fun onBytes(processed: Long, total: Long) {
                val fraction = if (total > 0L) {
                    (processed.toDouble() / total.toDouble()).toFloat().coerceIn(0f, 1f)
                } else {
                    0f
                }
                val info = if (total > 0L) {
                    "${humanSize(processed)} / ${humanSize(total)}"
                } else {
                    humanSize(processed)
                }
                _uiState.update {
                    it.copy(progress = it.progress.copy(progress = fraction, info = info))
                }
            }

            /** {@inheritDoc} */
            override fun onKdfPass(completedPasses: Int, totalPasses: Int) {
                _uiState.update {
                    it.copy(
                        progress = it.progress.copy(
                            progress = 0f,
                            info = "Argon2id $completedPasses / $totalPasses passes"
                        )
                    )
                }
            }

            /** {@inheritDoc} */
            override fun isCancelled(): Boolean =
                cancelRequested.get() || Thread.currentThread().isInterrupted
        }
    }

    /**
     * 依据当前平台能力准备直接或暂存输出。
     *
     * @param outputTreeUri 用户选择的 SAF 目录 URI 字符串
     * @return 输出计划
     */
    private fun prepareOutput(outputTreeUri: String?): OutputPlan {
        if (!outputTreeUri.isNullOrBlank()) {
            val uri = Uri.parse(outputTreeUri)
            val temp = fileOps.createOutputTempDir()
            val historyDir = fileOps.resolveTreeUriToPath(uri) ?: "所选文件夹"
            return OutputPlan(
                directory = temp.toPath(),
                pending = PendingOutput.Saf(uri, temp),
                historyDirectory = historyDir,
                outputTreeUri = outputTreeUri,
                scanAfterCommit = false
            )
        }
        return when (val resolved = OutputDirResolver.resolveImage(getApplication())) {
            is OutputDirResolver.Resolved.Direct -> OutputPlan(
                File(resolved.path).toPath(),
                null,
                resolved.path,
                null,
                true
            )
            is OutputDirResolver.Resolved.AppExternal -> OutputPlan(
                File(resolved.path).toPath(),
                null,
                resolved.path,
                null,
                false
            )
            is OutputDirResolver.Resolved.MediaStore -> {
                val temp = fileOps.createOutputTempDir()
                OutputPlan(
                    temp.toPath(),
                    PendingOutput.MediaStore(
                        resolved.relativePath,
                        temp,
                        MediaStoreCollection.IMAGES
                    ),
                    OutputDirResolver.publicPicturesPath(),
                    null,
                    false
                )
            }
        }
    }

    /**
     * 根据协议模式生成规范化密码字节。
     *
     * @param state 启动表单
     * @return 密码模式的 NFC UTF-8 字节；公开模式为 {@code null}
     */
    private fun passwordBytes(state: ImageCryptUiState): ByteArray? {
        val requiresPassword = if (state.direction == ImageCryptDirection.ENCRYPT) {
            state.mode == ImageCryptMode.PASSWORD
        } else {
            state.metadata?.requiresPassword() == true
        }
        return if (requiresPassword) ImageCryptPassword.encodeForV1(state.password) else null
    }

    /**
     * 校验任务表单。
     *
     * @param state 当前表单
     * @param input 当前物化输入
     * @return 错误文案；校验通过返回 {@code null}
     */
    private fun validate(
        state: ImageCryptUiState,
        input: MaterializedImageInput?
    ): String? {
        if (input == null) {
            return "请先选择图片文件"
        }
        val requiresPassword = if (state.direction == ImageCryptDirection.ENCRYPT) {
            state.mode == ImageCryptMode.PASSWORD
        } else {
            state.metadata?.requiresPassword() == true
        }
        if (requiresPassword && state.password.isEmpty()) {
            return "密码保护模式必须输入密码"
        }
        if (state.direction == ImageCryptDirection.ENCRYPT && requiresPassword &&
            state.password != state.confirmPassword
        ) {
            return "两次输入的密码不一致"
        }
        if (requiresPassword && state.kdfAssessment?.likelyFeasible == false) {
            return "当前系统可用内存不足以可靠执行固定 64 MiB Argon2id，请释放内存后重试"
        }
        return null
    }

    /**
     * 返回默认输出位置的人类可读说明。
     *
     * @return 输出位置
     */
    private fun describeDefaultTarget(): String {
        return when (val target = OutputDirResolver.resolveImage(getApplication())) {
            is OutputDirResolver.Resolved.Direct -> target.path
            is OutputDirResolver.Resolved.AppExternal -> target.path
            is OutputDirResolver.Resolved.MediaStore ->
                "相册/Pictures/${OutputDirResolver.FOLDER_NAME}"
        }
    }

    /**
     * 清理失败或取消操作的私有输出。
     *
     * @param plan 输出计划，可为 {@code null}
     */
    private fun cleanupPending(plan: OutputPlan?) {
        plan?.pending?.tempDir?.deleteRecursively()
    }

    /** 清理当前物化输入。 */
    private fun cleanupSelectedInput() {
        val input = selectedInput
        selectedInput = null
        fileOps.cleanupImageInput(input)
    }

    /** 清理为结果预览或系统分享保留的私有输出目录。 */
    private fun cleanupRetainedResult() {
        retainedResultDir?.deleteRecursively()
        retainedResultDir = null
    }

    /**
     * 判断当前任务是否运行。
     *
     * @return true 表示共享核心仍在执行或清理
     */
    private fun isRunning(): Boolean =
        _uiState.value.progress.state == ProgressState.State.RUNNING

    /**
     * 把选择阶段异常压缩为适合表单展示的文案。
     *
     * @param error 异常
     * @return 友好文案
     */
    private fun friendlySelectionError(error: Exception): String {
        return when (error) {
            is IllegalArgumentException, is IllegalStateException ->
                error.localizedMessage ?: "无法读取所选图片"
            else -> friendlyError(error)
        }
    }

    /**
     * 格式化字节数。
     *
     * @param bytes 字节数
     * @return 简短的人类可读大小
     */
    private fun humanSize(bytes: Long): String = LogService.humanSize(bytes.coerceAtLeast(0L))

    /**
     * ViewModel 销毁时请求取消并清理其拥有的私有文件。
     */
    override fun onCleared() {
        cancelRequested.set(true)
        currentJob?.cancel()
        cleanupSelectedInput()
        cleanupRetainedResult()
        OperationCoordinator.release(operationToken)
        super.onCleared()
    }

    /**
     * 一次任务的输出策略。
     *
     * @property directory 共享核心实际写入目录
     * @property pending SAF/MediaStore 提交描述；直接输出时为 {@code null}
     * @property historyDirectory 历史和结果展示使用的目标目录
     * @property outputTreeUri SAF 目录 URI 字符串
     * @property scanAfterCommit 是否在直接写入后请求系统相册扫描
     */
    private data class OutputPlan(
        val directory: Path,
        val pending: PendingOutput?,
        val historyDirectory: String,
        val outputTreeUri: String?,
        val scanAfterCommit: Boolean
    )
}
