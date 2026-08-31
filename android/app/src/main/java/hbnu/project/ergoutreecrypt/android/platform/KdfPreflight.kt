package hbnu.project.ergoutreecrypt.android.platform

import hbnu.project.ergoutreecrypt.encoding.RsCodecs
import hbnu.project.ergoutreecrypt.filestego.FileStegoCodec
import hbnu.project.ergoutreecrypt.filestego.api.StegoPreflight
import hbnu.project.ergoutreecrypt.header.HeaderReader
import hbnu.project.ergoutreecrypt.mediacrypt.MediaCryptCodec
import hbnu.project.ergoutreecrypt.mediacrypt.MediaMetadata
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

    /**
     * 读取卷头中的「加密前压缩」（Zstandard）标志。
     *
     * <p>桌面端用 zstd-jni 压缩，移动端无对应 native 库无法解压此类文件；返回
     * true 表示该文件使用了加密前压缩，移动端应直接拒绝解密。
     *
     * @param path 待解密的单文件路径
     * @return 压缩标志；读取失败（非 .ergou、损坏等）返回 null
     */
    fun peekCompressed(path: Path): Boolean? {
        return try {
            Files.newInputStream(path).use { input: InputStream ->
                val reader = HeaderReader(input, RsCodecs())
                reader.readHeader().header.isCompressed
            }
        } catch (_: Exception) {
            null
        }
    }

    /**
     * 只读探测加密媒体文件内嵌的元数据
     *
     * <p>供格式保持解密前预检使用：按扩展名嗅探格式，读取 WAV/MP3/MP4 载体中内嵌的
     * {@link MediaMetadata}，据此判断 Argon2 档位。非受支持格式、非本工具加密或读取
     * 失败一律返回 {@code null}。
     *
     * @param path 待探测的媒体文件路径
     * @return 解析出的元数据；非本工具加密或读取失败返回 null
     */
    fun peekMediaMetadata(path: Path): MediaMetadata? {
        return try {
            MediaCryptCodec().peekMetadata(path)
        } catch (_: Exception) {
            null
        }
    }

    /**
     * 只读探测文件隐写载体（STEG-V2），返回 KDF 档位与「加密前压缩」标志。
     *
     * <p>供隐写提取前预检使用：只读元数据（判定 Argon2 档位，1 GiB 档提示「较慢」）
     * 与 Payload 头前 10 字节（判定是否用了「加密前压缩」，命中则移动端无法解压）。
     * 非隐写文件、读取失败或无法判定时返回 {@code null}，由调用方按「无需提示」处理。
     *
     * @param path 待探测的隐写载体文件路径
     * @return 预检结果；无法判定返回 null
     */
    fun peekStego(path: Path): StegoPreflight? {
        return try {
            val result = FileStegoCodec().preflight(path, null)
            if (result === StegoPreflight.UNKNOWN) null else result
        } catch (_: Exception) {
            null
        }
    }
}
