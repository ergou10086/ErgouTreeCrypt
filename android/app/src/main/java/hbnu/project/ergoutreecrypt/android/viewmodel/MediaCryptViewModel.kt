package hbnu.project.ergoutreecrypt.android.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import hbnu.project.ergoutreecrypt.mediacrypt.MediaCryptCodec
import hbnu.project.ergoutreecrypt.mediacrypt.MediaCryptOptions
import hbnu.project.ergoutreecrypt.mediacrypt.MediaCryptProfile
import hbnu.project.ergoutreecrypt.mediacrypt.MediaProgress
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import java.nio.file.Paths
import java.nio.charset.StandardCharsets

/**
 * 音视频格式保持加密 ViewModel。
 *
 * <p>桥接共享核心 {@link MediaCryptCodec} 与 Compose UI：
 * <ol>
 *   <li>支持 MP3 / MP4 / WAV 三种格式</li>
 *   <li>加密：通过 {@link MediaCryptCodec#encrypt} 格式保持加密</li>
 *   <li>解密：通过 {@link MediaCryptCodec#decrypt} 还原原始文件</li>
 *   <li>进度通过 {@link MediaProgress} 回调桥接到 Compose StateFlow</li>
 * </ol>
 *
 * @author ErgouTree
 * @since 2026/8/11
 */
class MediaCryptViewModel : ViewModel() {

    private val codec = MediaCryptCodec()

    private val _progress = MutableStateFlow(ProgressState())
    val progress: StateFlow<ProgressState> = _progress.asStateFlow()

    /** 当前正在运行的协程，用于取消操作。 */
    private var currentJob: Job? = null

    /** 当前操作的全局协调器释放令牌（取消后用于立即归还操作权）。 */
    private var opToken: Long? = null

    /**
     * 执行格式保持加密。
     *
     * @param input     输入媒体文件路径
     * @param output    输出加密文件路径
     * @param password  明文密码（UTF-8 编码后传入 codec）
     * @param profile   加密档位，null 表示按格式取默认安全档
     * @param paranoid  是否使用偏执模式
     * @param storeIntegrity 是否存储完整性校验 MAC
     */
    fun startEncrypt(
        input: String,
        output: String,
        password: String,
        profile: MediaCryptProfile? = null,
        paranoid: Boolean = false,
        storeIntegrity: Boolean = true
    ) {
        // 全局操作权占用失败：已有其他 Tab 的操作在运行
        val token = OperationCoordinator.tryAcquire() ?: return
        opToken = token
        // 如果本 VM 仍有上一次任务在收尾，先取消
        currentJob?.cancel()
        _progress.update { it.copy(state = ProgressState.State.RUNNING) }
        currentJob = viewModelScope.launch(Dispatchers.IO) {
            try {
                val options = MediaCryptOptions.builder()
                    .profile(profile)
                    .paranoid(paranoid)
                    .storeIntegrity(storeIntegrity)
                    .build()
                val pwdBytes = password.toByteArray(StandardCharsets.UTF_8)
                val progressCallback = createMediaProgress()

                codec.encrypt(Paths.get(input), Paths.get(output), pwdBytes, options, progressCallback)
                _progress.update { it.copy(state = ProgressState.State.DONE, progress = 1f) }
            } catch (e: hbnu.project.ergoutreecrypt.mediacrypt.MediaCryptCancelledException) {
                _progress.update { it.copy(state = ProgressState.State.CANCELLED) }
            } catch (e: Exception) {
                _progress.update {
                    it.copy(
                        state = ProgressState.State.ERROR,
                        error = e.localizedMessage ?: e.javaClass.simpleName
                    )
                }
            } finally {
                // 令牌校验释放：过期任务的释放不会误清新任务
                OperationCoordinator.release(token)
            }
        }
    }

    /**
     * 执行格式保持解密。在解密前自动进行完整性校验（若文件存储了完整性数据）。
     *
     * @param input     加密后的媒体文件路径
     * @param output    解密输出文件路径
     * @param password  明文密码
     * @param noiseCheck 是否先验证文件含有本工具的加密元数据（EGTC-AVE 魔数），
     *                  避免误把普通媒体文件当密文处理
     */
    fun startDecrypt(input: String, output: String, password: String, noiseCheck: Boolean = true) {
        // 全局操作权占用失败：已有其他 Tab 的操作在运行
        val token = OperationCoordinator.tryAcquire() ?: return
        opToken = token
        // 如果本 VM 仍有上一次任务在收尾，先取消
        currentJob?.cancel()
        _progress.update { it.copy(state = ProgressState.State.RUNNING) }
        currentJob = viewModelScope.launch(Dispatchers.IO) {
            try {
                val inputPath = Paths.get(input)
                val pwdBytes = password.toByteArray(StandardCharsets.UTF_8)
                val progressCallback = createMediaProgress()

                // 噪音文件检测：确认文件确实含有本工具的加密元数据
                if (noiseCheck && !codec.isEncrypted(inputPath)) {
                    _progress.update {
                        it.copy(
                            state = ProgressState.State.ERROR,
                            error = "该文件不包含有效的加密元数据（EGTC-AVE），可能不是本工具加密的媒体文件。\n请关闭\"噪音文件解密\"选项后重试。"
                        )
                    }
                    return@launch
                }

                // 解密前完整性校验：若文件含完整性数据则自动校验
                try {
                    val ok = codec.verifyIntegrity(inputPath, pwdBytes, MediaProgress.NONE)
                    if (!ok) {
                        // 无完整性数据存储，继续解密但给出提示
                        _progress.update { it.copy(info = "文件未存储完整性校验数据，跳过完整性验证") }
                    }
                } catch (e: Exception) {
                    // 完整性校验失败 → 密码错误或文件被篡改
                    val msg = e.localizedMessage ?: e.javaClass.simpleName
                    _progress.update {
                        it.copy(
                            state = ProgressState.State.ERROR,
                            error = "完整性校验失败：$msg\n文件可能被篡改或密码错误。"
                        )
                    }
                    return@launch
                }

                codec.decrypt(inputPath, Paths.get(output), pwdBytes, progressCallback)
                _progress.update { it.copy(state = ProgressState.State.DONE, progress = 1f, info = "") }
            } catch (e: hbnu.project.ergoutreecrypt.mediacrypt.MediaCryptCancelledException) {
                _progress.update { it.copy(state = ProgressState.State.CANCELLED) }
            } catch (e: Exception) {
                _progress.update {
                    it.copy(
                        state = ProgressState.State.ERROR,
                        error = e.localizedMessage ?: e.javaClass.simpleName
                    )
                }
            } finally {
                // 令牌校验释放：过期任务的释放不会误清新任务
                OperationCoordinator.release(token)
            }
        }
    }

    /**
     * 检测文件是否包含本工具的加密元数据（EGTC-AVE 魔数）。
     *
     * @param input 待检测的文件路径
     * @return true 若文件包含可识别的加密元数据
     */
    fun isEncrypted(input: String): Boolean {
        return try {
            codec.isEncrypted(Paths.get(input))
        } catch (_: Exception) {
            false
        }
    }

    /**
     * 取消正在进行的操作。
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

    /**
     * 创建 MediaProgress 回调桥接到 Compose StateFlow。
     */
    private fun createMediaProgress(): MediaProgress {
        return object : MediaProgress {
            override fun onProgress(processed: Long, total: Long) {
                val fraction = if (total > 0) processed.toFloat() / total else 0f
                _progress.update { it.copy(progress = fraction.coerceIn(0f, 1f)) }
            }

            override fun isCancelled(): Boolean =
                _progress.value.state == ProgressState.State.CANCELLED
        }
    }
}
