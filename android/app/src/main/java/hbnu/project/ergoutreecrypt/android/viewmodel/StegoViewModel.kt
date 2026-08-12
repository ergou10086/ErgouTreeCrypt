package hbnu.project.ergoutreecrypt.android.viewmodel

import android.content.Context
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import hbnu.project.ergoutreecrypt.crypto.BruteForceGuard
import hbnu.project.ergoutreecrypt.filestego.FileStegoCodec
import hbnu.project.ergoutreecrypt.filestego.api.FileStegoOptions
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

    init {
        // 初始化 BruteForceGuard：侧车数据库存储在 app 私有目录
        val guardDir = Paths.get(appContext.filesDir.absolutePath, ".ergou")
        BruteForceGuard.getInstance().init(guardDir)
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
        // 如果已有正在运行的操作，先取消
        currentJob?.cancel()
        _progress.update { it.copy(state = ProgressState.State.RUNNING) }

        currentJob = viewModelScope.launch(Dispatchers.IO) {
            try {
                val carrierFile = Paths.get(carrierPath)
                val secretFile = Paths.get(secretPath)
                val output = Paths.get(outputPath)
                val pwdBytes = if (password.isNotEmpty()) {
                    password.toByteArray(Charsets.UTF_8)
                } else {
                    ByteArray(0)
                }

                codec.hide(carrierFile, secretFile, output, pwdBytes, options)

                _progress.update {
                    it.copy(state = ProgressState.State.DONE, progress = 1f)
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
        // 如果已有正在运行的操作，先取消
        currentJob?.cancel()
        _progress.update { it.copy(state = ProgressState.State.RUNNING) }

        currentJob = viewModelScope.launch(Dispatchers.IO) {
            try {
                val stegoFile = Paths.get(stegoPath)
                val outDir = Paths.get(outputDir)
                val pwdBytes = if (password.isNotEmpty()) {
                    password.toByteArray(Charsets.UTF_8)
                } else {
                    ByteArray(0)
                }

                val resultFile = codec.extract(stegoFile, outDir, pwdBytes)

                _progress.update {
                    it.copy(
                        state = ProgressState.State.DONE,
                        progress = 1f,
                        info = resultFile.fileName.toString()
                    )
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
     * 取消正在进行的隐写操作。
     *
     * <p>仅取消当前任务，不销毁 ViewModel 作用域。
     */
    fun cancel() {
        currentJob?.cancel()
        currentJob = null
        _progress.update { it.copy(state = ProgressState.State.CANCELLED) }
    }
}
