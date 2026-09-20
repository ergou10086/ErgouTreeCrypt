package hbnu.project.ergoutreecrypt.android.platform

import android.content.Context
import java.io.File

/**
 * 移动端缓存占用的扫描与清理。
 *
 * <p>汇总本工具在 Android 上产生的全部可回收数据，供「存储空间」页展示明细并一键清理。
 * 扫描范围：
 * <ul>
 *   <li>{@code filesDir/crypto_tmp} —— 无法直读的输入文件在应用私有的内部临时副本；</li>
 *   <li>{@code cacheDir/saf_out_*} —— SAF 目录树与 MediaStore 输出的暂存目录；</li>
 *   <li>{@code filesDir/imagecrypt_input} —— 图片加解密的输入副本；</li>
 *   <li>{@code filesDir/keyfiles} —— 密钥文件安全区副本；</li>
 *   <li>{@code filesDir/.ergou} —— 防暴力破解记录；</li>
 *   <li>{@code filesDir/logs}、{@code filesDir/history} —— 应用日志与操作历史；</li>
 *   <li>{@code cacheDir} 下的其余内容。</li>
 * </ul>
 *
 * <p>只清理本工具自有的中间产物与可再生的缓存，绝不删除用户已生成的加密/解密结果与原始文件。
 * 所有目录遍历都按「尽量返回已统计部分」处理，目录不可读时不抛异常。
 *
 * @param context 应用上下文，内部统一使用 applicationContext
 * @author ErgouTree
 * @since 2026/9/20
 */
class StorageUsage(context: Context) {

    /** 应用上下文，避免持有 Activity 引用。 */
    private val appContext = context.applicationContext

    /** 供密钥文件安全区复用的文件操作器。 */
    private val fileOps = AndroidFileOps(context)

    /**
     * 一条缓存占用明细。
     *
     * @property label 类别名称
     * @property path  该类缓存的落盘位置，用于向用户交代存放处
     * @property bytes 占用字节数
     * @property files 文件个数
     */
    data class Entry(val label: String, val path: String, val bytes: Long, val files: Long)

    /**
     * 扫描全部缓存占用明细。
     *
     * @return 按固定顺序排列的明细列表；某项不存在时其占用为 0
     */
    fun scan(): List<Entry> {
        val (staging, otherCache) = cachePartition()
        return listOf(
            entry("临时输入副本", File(appContext.filesDir, TMP_DIR_NAME)),
            aggregate("暂存输出目录", staging, appContext.cacheDir),
            entry("图片加密输入副本", File(appContext.filesDir, IMAGE_INPUT_DIR_NAME)),
            entry("密钥文件安全区", File(appContext.filesDir, KEYFILES_DIR_NAME)),
            entry("防护记录", File(appContext.filesDir, GUARD_DIR_NAME)),
            entry("应用日志", File(appContext.filesDir, LOGS_DIR_NAME)),
            entry("操作历史", File(appContext.filesDir, HISTORY_DIR_NAME)),
            aggregate("其他缓存", otherCache, appContext.cacheDir)
        )
    }

    /**
     * 清理全部缓存并返回实际释放的字节数。
     *
     * <p>清理范围与 {@link #scan()} 完全一致，因此该按钮能把当前列出的占用降到 0。
     * 密钥文件安全区先按 {@link AndroidFileOps#cleanupSecureKeyfiles()} 覆写再删除，
     * 保持与常规操作结束时相同的处理强度。
     *
     * @return 实际释放的字节数
     */
    fun clearAll(): Long {
        val before = totalBytes()

        fileOps.cleanupSecureKeyfiles()
        deleteChildren(File(appContext.filesDir, TMP_DIR_NAME))
        deleteChildren(File(appContext.filesDir, IMAGE_INPUT_DIR_NAME))
        deleteChildren(File(appContext.filesDir, KEYFILES_DIR_NAME))
        deleteChildren(File(appContext.filesDir, LOGS_DIR_NAME))
        deleteChildren(File(appContext.filesDir, HISTORY_DIR_NAME))
        deleteChildren(File(appContext.filesDir, GUARD_DIR_NAME))
        deleteChildren(appContext.cacheDir)

        return (before - totalBytes()).coerceAtLeast(0L)
    }

    /**
     * 应用启动时清扫上一进程遗留的临时产物。
     *
     * <p>进程刚启动时不存在任何进行中的操作与已选中的输入，因此可以无条件清空；
     * 日志与操作历史属于用户可见记录，不在此处清理。
     */
    fun sweepAtStartup() {
        fileOps.cleanupSecureKeyfiles()
        deleteChildren(File(appContext.filesDir, TMP_DIR_NAME))
        deleteChildren(File(appContext.filesDir, IMAGE_INPUT_DIR_NAME))
        deleteChildren(File(appContext.filesDir, KEYFILES_DIR_NAME))
        cachePartition().first.forEach { it.deleteRecursively() }
    }

    /**
     * 汇总当前全部缓存占用的字节数。
     *
     * @return 合计字节数
     */
    fun totalBytes(): Long = scan().sumOf { it.bytes }

    /**
     * 把缓存目录划分为「暂存输出目录」与「其余缓存」两部分。
     *
     * @return 第一项为 {@code saf_out_} 前缀的暂存目录，第二项为缓存目录下的其它内容
     */
    private fun cachePartition(): Pair<List<File>, List<File>> {
        val children = appContext.cacheDir.listFiles()?.toList().orEmpty()
        val staging = children.filter { it.name.startsWith(STAGING_PREFIX) }
        val others = children.filterNot { it.name.startsWith(STAGING_PREFIX) }
        return staging to others
    }

    /**
     * 按单个文件或目录统计一条明细。
     *
     * @param label 类别名称
     * @param target 目标文件或目录
     * @return 对应明细
     */
    private fun entry(label: String, target: File): Entry =
        Entry(label, target.absolutePath, sizeOf(target), countOf(target))

    /**
     * 把一个目录下的多个条目聚合为一条明细。
     *
     * @param label 类别名称
     * @param targets 待聚合的条目
     * @param displayPath 展示给用户的落盘位置
     * @return 对应明细
     */
    private fun aggregate(label: String, targets: List<File>, displayPath: File): Entry {
        var bytes = 0L
        var files = 0L
        for (target in targets) {
            bytes += sizeOf(target)
            files += countOf(target)
        }
        return Entry(label, displayPath.absolutePath, bytes, files)
    }

    /**
     * 递归统计文件或目录占用的字节数。
     *
     * @param target 目标文件或目录，可为 null
     * @return 占用字节数
     */
    private fun sizeOf(target: File?): Long {
        if (target == null || !target.exists()) {
            return 0L
        }
        if (target.isFile) {
            return target.length()
        }
        var total = 0L
        for (child in target.listFiles().orEmpty()) {
            total += sizeOf(child)
        }
        return total
    }

    /**
     * 递归统计文件或目录包含的文件个数。
     *
     * @param target 目标文件或目录，可为 null
     * @return 文件个数
     */
    private fun countOf(target: File?): Long {
        if (target == null || !target.exists()) {
            return 0L
        }
        if (target.isFile) {
            return 1L
        }
        var total = 0L
        for (child in target.listFiles().orEmpty()) {
            total += countOf(child)
        }
        return total
    }

    /**
     * 删除目录下的全部子项，保留目录本身。
     *
     * <p>目录按需重建，保留它可以避免后续写入时重复判断；删除失败的子项静默跳过。
     *
     * @param dir 目标目录，可为 null
     */
    private fun deleteChildren(dir: File?) {
        if (dir == null || !dir.isDirectory) {
            return
        }
        for (child in dir.listFiles().orEmpty()) {
            child.deleteRecursively()
        }
    }

    companion object {

        /** 输入文件内部临时副本所在目录名。 */
        private const val TMP_DIR_NAME = "crypto_tmp"

        /** 图片加解密输入副本所在目录名。 */
        private const val IMAGE_INPUT_DIR_NAME = "imagecrypt_input"

        /** 密钥文件安全区目录名。 */
        private const val KEYFILES_DIR_NAME = "keyfiles"

        /** 防暴力破解记录目录名。 */
        private const val GUARD_DIR_NAME = ".ergou"

        /** 应用日志目录名。 */
        private const val LOGS_DIR_NAME = "logs"

        /** 操作历史目录名。 */
        private const val HISTORY_DIR_NAME = "history"

        /** 暂存输出目录前缀。 */
        private const val STAGING_PREFIX = "saf_out_"
    }
}
