package hbnu.project.ergoutreecrypt.android.platform

import hbnu.project.ergoutreecrypt.encoding.RsCodecs
import hbnu.project.ergoutreecrypt.header.HeaderReader
import java.io.InputStream
import java.nio.file.Files
import java.nio.file.Path

/**
 * 移动端解密前的 KDF 元数据预检。
 *
 * <p>移动端应用堆受限，无法像桌面端一样在堆内派生 1 GiB 参数的密钥。此工具在
 * 解密<b>单文件</b>前读取卷头中的 Argon2 内存参数，供 UI 提前提示"该文件密钥
 * 派生较慢 / 建议桌面端重加密"，避免用户点击解密后长时间卡顿或内存不足闪退。
 *
 * <p>读取失败（非 .ergou 文件、损坏等）一律返回 {@code null}，由调用方按
 * "无参数 → 桌面端默认 1 GiB" 处理提示。
 *
 * @author ErgouTree
 * @since 2026/8/28
 */
object KdfPreflight {

    /**
     * 读取卷头中记录的 Argon2 内存参数（KiB）。
     *
     * @param path 待解密的单文件路径
     * @return 内存参数（KiB）；卷头无参数（桌面端旧格式）或读取失败返回 null
     */
    fun peekArgon2MemoryKib(path: Path): Int? {
        return try {
            Files.newInputStream(path).use { input: InputStream ->
                val reader = HeaderReader(input, RsCodecs())
                val header = reader.readHeader().header
                if (header.hasArgon2Params()) header.argon2MemoryKib else null
            }
        } catch (_: Exception) {
            null
        }
    }
}
