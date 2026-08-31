package hbnu.project.ergoutreecrypt.android.platform

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import java.nio.file.Path

/**
 * 桌面端「图像隐写」LSB 模式产物的只读探测器。
 *
 * <p>桌面端「图像隐写」标签页的 LSB 方案（{@code stego/PngLsbStego}，依赖
 * {@code java.awt}，移动端被 {@code syncCoreLibs} 排除）把元数据头（首 16 字节为
 * 固定魔数 {@code "EGTC-STEGO-IMG01"}）按 R→G→B 通道的最低有效位（LSB）逐位嵌入
 * 像素。移动端不实现 LSB 提取，故在「隐写提取」前探测该魔数以给出明确报错，
 * 而非让用户看到"未找到隐写数据"的泛化错误。
 *
 * <p>探测算法与桌面端 {@code PngLsbStego.extractFromPixels} 逐位一致：每像素取
 * R/G/B 三通道（{@code 16/8/0} 位移），每通道取 {@code lsbDepth}（1–4）个最低位，
 * 按 LSB 优先顺序装入字节流，与桌面端嵌入顺序镜像，故可正确还原首 16 字节魔数。
 *
 * <p>探测失败（非 PNG、解码失败、OOM 等）一律返回 {@code false}，由调用方回退到
 * 正常提取流程（其会给出各自的错误），本类只做"尽力而为"的精确识别。
 *
 * @author ErgouTree
 * @since 2026/8/31
 */
object LsbStegoDetector {

    /** 桌面端图像隐写 LSB 方案元数据魔数（普通模式，16 字节 ASCII）。 */
    private const val LSB_MAGIC = "EGTC-STEGO-IMG01"

    /** 魔数字节数。 */
    private const val MAGIC_LEN = 16

    /** LSB 深度合法范围（与桌面端 1–4 一致）。 */
    private const val MIN_LSB_DEPTH = 1
    private const val MAX_LSB_DEPTH = 4

    /** RGB 通道在 ARGB int 中的位移（与桌面端 chShifts={16,8,0} 一致，Alpha 不参与）。 */
    private val CHANNEL_SHIFTS = intArrayOf(16, 8, 0)

    /**
     * 探测文件是否为桌面端「图像隐写」LSB 模式的产物。
     *
     * <p>仅对 {@code .png} 载体做像素级 LSB 探测；其余格式或任意解码失败返回
     * {@code false}。对每个合法 LSB 深度（1–4）各试一次，命中魔数即返回 true。
     *
     * @param path 待探测的文件路径
     * @return true 表示检测到桌面端 LSB 图种（移动端不支持提取）
     */
    fun detectLsbStego(path: Path): Boolean {
        val name = path.fileName?.toString()?.lowercase() ?: return false
        if (!name.endsWith(".png")) {
            return false
        }
        val bitmap = try {
            BitmapFactory.decodeFile(path.toString(), BitmapFactory.Options().apply {
                inPreferredConfig = Bitmap.Config.ARGB_8888
            })
        } catch (_: Throwable) {
            null
        } ?: return false
        return try {
            checkMagic(bitmap)
        } finally {
            bitmap.recycle()
        }
    }

    /**
     * 对每个合法 LSB 深度提取首 {@link #MAGIC_LEN} 字节并比对魔数。
     */
    private fun checkMagic(bitmap: Bitmap): Boolean {
        for (depth in MIN_LSB_DEPTH..MAX_LSB_DEPTH) {
            val first = extractFirstBytes(bitmap, depth, MAGIC_LEN)
            if (String(first, Charsets.US_ASCII) == LSB_MAGIC) {
                return true
            }
        }
        return false
    }

    /**
     * 从位图顶部像素提取前 {@code numBytes} 字节的 LSB 流（与桌面端嵌入顺序镜像）。
     *
     * @param bitmap   已解码位图
     * @param lsbDepth LSB 深度（1–4）
     * @param numBytes 需要的字节数
     * @return 提取出的字节数组（不足部分为 0）
     */
    private fun extractFirstBytes(bitmap: Bitmap, lsbDepth: Int, numBytes: Int): ByteArray {
        val width = bitmap.width
        val height = bitmap.height
        // 每像素 3 通道、每通道 lsbDepth 位；取足以容纳 numBytes 字节的最少行数（留 1 行余量）
        val channelsNeeded = numBytes * 8
        val rowsNeeded = minOf(height, channelsNeeded / (3 * lsbDepth) + 2)
        val pixels = IntArray(width * rowsNeeded)
        bitmap.getPixels(pixels, 0, width, 0, 0, width, rowsNeeded)

        val mask = (1 shl lsbDepth) - 1
        val result = ByteArray(numBytes)
        var byteIdx = 0
        var bitIdx = 0
        outer@ for (px in pixels) {
            for (shift in CHANNEL_SHIFTS) {
                val channel = (px shr shift) and 0xFF
                val bits = channel and mask
                for (b in 0 until lsbDepth) {
                    val bit = (bits shr b) and 1
                    if (bit == 1) {
                        result[byteIdx] = (result[byteIdx].toInt() or (1 shl bitIdx)).toByte()
                    }
                    bitIdx++
                    if (bitIdx >= 8) {
                        bitIdx = 0
                        byteIdx++
                        if (byteIdx >= numBytes) {
                            break@outer
                        }
                    }
                }
            }
        }
        return result
    }
}
