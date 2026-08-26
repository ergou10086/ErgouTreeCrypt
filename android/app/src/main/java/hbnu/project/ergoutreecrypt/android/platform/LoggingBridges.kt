package hbnu.project.ergoutreecrypt.android.platform

import hbnu.project.ergoutreecrypt.filestego.api.ProgressListener
import hbnu.project.ergoutreecrypt.log.LogService
import hbnu.project.ergoutreecrypt.mediacrypt.MediaProgress
import hbnu.project.ergoutreecrypt.volume.ProgressPhase
import hbnu.project.ergoutreecrypt.volume.ProgressReporter
import java.nio.file.Paths

/**
 * 从路径提取文件名，供日志会话头使用。
 *
 * @param path 绝对或相对路径，可为 null
 * @return 文件名；路径为空或无法解析时返回 null
 */
fun logFileName(path: String?): String? {
    if (path.isNullOrBlank()) {
        return null
    }
    return try {
        Paths.get(path).fileName?.toString()?.ifBlank { null }
    } catch (_: Exception) {
        path.substringAfterLast('/').substringAfterLast('\\').ifBlank { null }
    }
}

/**
 * 计算自纳米时间起点起经过的毫秒数。
 *
 * @param startNs {@link System#nanoTime()} 起点
 * @return 耗时毫秒
 */
fun logElapsedMillis(startNs: Long): Long {
    return (System.nanoTime() - startNs) / 1_000_000L
}

/**
 * 将 {@link ProgressReporter} 的状态与进度镜像到 {@link LogService}。
 *
 * <p>状态文案以 INFO 记录；进度分数仅在 TRACE 下节流输出（约每 10% 或 500ms）。
 *
 * @param delegate 实际 UI 回调，不允许为 null
 * @param category 日志分类
 */
class LoggingProgressReporter(
    private val delegate: ProgressReporter,
    category: String?
) : ProgressReporter {

    private val categoryName = category ?: "Progress"
    private var lastStatus: String? = null
    @Volatile private var lastLoggedFraction = -1f
    @Volatile private var lastTraceNs = 0L

    override fun setStatus(text: String) {
        delegate.setStatus(text)
        logStatus(text)
    }

    override fun setStatus(text: String, phase: ProgressPhase) {
        delegate.setStatus(text, phase)
        logStatus(text)
    }

    override fun setProgress(fraction: Float, info: String) {
        delegate.setProgress(fraction, info)
        logProgress(fraction, info, null)
    }

    override fun setProgress(fraction: Float, info: String, phase: ProgressPhase) {
        delegate.setProgress(fraction, info, phase)
        logProgress(fraction, info, phase)
    }

    override fun setCanCancel(can: Boolean) {
        delegate.setCanCancel(can)
    }

    override fun update() {
        delegate.update()
    }

    override fun isCancelled(): Boolean {
        return delegate.isCancelled
    }

    /**
     * 状态变化时写一条 INFO。
     *
     * @param text 状态文案
     */
    private fun logStatus(text: String?) {
        if (text == null || text == lastStatus) {
            return
        }
        lastStatus = text
        LogService.info(categoryName, text)
    }

    /**
     * TRACE 下节流记录进度。
     *
     * @param fraction 完成比例
     * @param info     附加信息
     * @param phase    阶段，可为 null
     */
    private fun logProgress(fraction: Float, info: String?, phase: ProgressPhase?) {
        if (!LogService.isTraceEnabled()) {
            return
        }
        val now = System.nanoTime()
        val boundary = fraction <= 0f || fraction >= 1f
        val step = kotlin.math.abs(fraction - lastLoggedFraction) >= TRACE_STEP
        val enoughTime = now - lastTraceNs >= TRACE_INTERVAL_NS
        if (!boundary && !step && !enoughTime) {
            return
        }
        lastLoggedFraction = fraction
        lastTraceNs = now
        val sb = StringBuilder(48)
        sb.append("进度 ")
        if (phase != null) {
            sb.append(phase.name).append(' ')
        }
        sb.append(String.format("%.0f%%", fraction * 100f))
        if (!info.isNullOrBlank()) {
            sb.append(' ').append(info)
        }
        LogService.trace(categoryName, sb.toString())
    }

    companion object {
        /** TRACE 进度最小间隔。 */
        private const val TRACE_INTERVAL_NS = 500_000_000L

        /** TRACE 进度最小步进。 */
        private const val TRACE_STEP = 0.10f
    }
}

/**
 * 将文件隐写 {@link ProgressListener} 进度镜像到诊断日志。
 *
 * @param delegate 实际监听器，可为 null
 * @param category 日志分类
 */
class LoggingProgressListener(
    private val delegate: ProgressListener?,
    category: String?
) : ProgressListener {

    private val categoryName = category ?: "FileStego"
    @Volatile private var lastLogged = -1.0
    @Volatile private var lastTraceNs = 0L

    override fun onProgress(fraction: Double) {
        delegate?.onProgress(fraction)
        if (!LogService.isTraceEnabled()) {
            return
        }
        val now = System.nanoTime()
        val boundary = fraction <= 0 || fraction >= 1
        val step = kotlin.math.abs(fraction - lastLogged) >= 0.10
        if (!boundary && !step && now - lastTraceNs < TRACE_INTERVAL_NS) {
            return
        }
        lastLogged = fraction
        lastTraceNs = now
        LogService.trace(categoryName, "进度 " + String.format("%.0f%%", fraction * 100))
    }

    companion object {
        private const val TRACE_INTERVAL_NS = 500_000_000L
    }
}

/**
 * 将 {@link MediaProgress} 进度镜像到诊断日志。
 *
 * @param delegate 实际回调，不允许为 null
 * @param category 日志分类
 */
class LoggingMediaProgress(
    private val delegate: MediaProgress,
    category: String?
) : MediaProgress {

    private val categoryName = category ?: "MediaCrypt"
    @Volatile private var lastTraceNs = 0L
    @Volatile private var lastPercent = -1

    override fun onProgress(processed: Long, total: Long) {
        delegate.onProgress(processed, total)
        if (!LogService.isTraceEnabled()) {
            return
        }
        val pct = if (total <= 0) 0 else ((processed * 100) / total).toInt().coerceAtMost(100)
        val now = System.nanoTime()
        val boundary = processed <= 0 || (total > 0 && processed >= total)
        if (!boundary && pct / 10 == lastPercent / 10 && now - lastTraceNs < TRACE_INTERVAL_NS) {
            return
        }
        lastPercent = pct
        lastTraceNs = now
        LogService.trace(
            categoryName,
            "进度 $pct% (" + LogService.humanSize(processed) + " / " + LogService.humanSize(total) + ")"
        )
    }

    override fun isCancelled(): Boolean {
        return delegate.isCancelled
    }

    companion object {
        private const val TRACE_INTERVAL_NS = 500_000_000L
    }
}
