package hbnu.project.ergoutreecrypt.android.platform

import java.util.Locale

/**
 * 文件名安全化工具。
 *
 * <p>移动端输入文件名可能是中文、日文、emoji 等各类 Unicode 字符的混合，也可能夹杂
 * {@code / \ : * ? " < > |} 等跨平台非法字符或控制字符。直接把这些字符写入输出路径，
 * 会导致文件落盘失败、被系统改名或跨平台乱码。本工具仅替换上述"危险 ASCII 字符"，
 * 完整保留所有合法 Unicode 字符（中文、日文、emoji 均不受影响），从而在保证文件名
 * 高兼容性的同时不产生乱码。
 *
 * <p>替换规则（仅作用于危险字符，绝不触碰非 ASCII 字符）：
 * <ul>
 *   <li>{@code / \ : * ? " < > |} → 下划线 {@code _}；</li>
 *   <li>控制字符（0x00–0x1F、0x7F）→ 下划线 {@code _}；</li>
 *   <li>去除首尾空格与点（Windows 会静默裁剪，导致名字与预期不符）；</li>
 *   <li>空名回退为 {@code file}；Windows 保留设备名加下划线前缀规避；</li>
 *   <li>按 UTF-8 字节数截断到 255，不拆分代理对，保证不产生乱码。</li>
 * </ul>
 *
 * @author ErgouTree
 * @since 2026/8/31
 */
object FileNameSanitizer {

    /** 跨平台（Windows / Linux / Android）文件系统不允许或易导致歧义的字符。 */
    private val ILLEGAL_CHARS = setOf('/', '\\', ':', '*', '?', '"', '<', '>', '|')

    /** Windows 保留设备名（不区分大小写，作为独立文件名会被系统拒绝）。 */
    private val RESERVED_NAMES = setOf(
        "CON", "PRN", "AUX", "NUL",
        "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"
    )

    /** 文件名最大 UTF-8 字节数（ext4 单名上限，兼顾 Windows 255 字符限制）。 */
    private const val MAX_NAME_BYTES = 255

    /**
     * 将任意文件名安全化为跨平台可用、且保留 Unicode 的文件名。
     *
     * <p>处理顺序：替换非法/控制字符 → 去除首尾空格与点 → 空名回退 →
     * 保留设备名规避 → 按 UTF-8 字节数截断。函数幂等，可重复调用。
     *
     * @param raw 原始文件名（可能包含中文、日文、emoji 或非法字符）
     * @return 安全化后的文件名；永不返回空串或含非法字符的字符串
     */
    fun sanitize(raw: String): String {
        val sb = StringBuilder(raw.length)
        for (ch in raw) {
            when {
                ch in ILLEGAL_CHARS -> sb.append('_')
                ch.code < 0x20 || ch.code == 0x7F -> sb.append('_')
                else -> sb.append(ch)
            }
        }
        var name = sb.toString().trim(' ', '.')
        if (name.isEmpty()) {
            name = "file"
        }
        val stem = name.substringBefore('.', name)
        if (stem.uppercase(Locale.ROOT) in RESERVED_NAMES) {
            name = "_$name"
        }
        return truncateToUtf8Bytes(name, MAX_NAME_BYTES)
    }

    /**
     * 将相对路径按 {@code /} 逐段安全化（保留段间分隔符）。
     *
     * <p>用于文件夹加密时镜像输出相对路径：源文件名/目录名在 Android 上可含
     * {@code : ?} 等跨平台危险字符，逐段清洗后可保证整个输出目录树也兼容
     * Windows 等目标系统。每个段内的 {@code /} 不可能存在（来自真实文件名），
     * {@code \} 等危险字符由 {@link #sanitize(String)} 统一替换。
     *
     * @param path 以 {@code /} 分隔的相对路径（如 {@code subdir/报告.docx}）
     * @return 逐段安全化后、以 {@code /} 重新拼接的路径
     */
    fun sanitizePathSegments(path: String): String {
        return path.split('/').joinToString("/") { sanitize(it) }
    }

    /**
     * 将字符串按 UTF-8 字节数截断到不超过指定上限（不拆分代理对，避免乱码）。
     *
     * @param s        待截断的字符串
     * @param maxBytes 最大 UTF-8 字节数
     * @return 截断后的字符串；原串未超限时原样返回
     */
    private fun truncateToUtf8Bytes(s: String, maxBytes: Int): String {
        if (s.toByteArray(Charsets.UTF_8).size <= maxBytes) {
            return s
        }
        val sb = StringBuilder()
        var used = 0
        var i = 0
        while (i < s.length) {
            val cp = s.codePointAt(i)
            val bytes = when {
                cp <= 0x7F -> 1
                cp <= 0x7FF -> 2
                cp <= 0xFFFF -> 3
                else -> 4
            }
            if (used + bytes > maxBytes) {
                break
            }
            sb.appendCodePoint(cp)
            used += bytes
            i += if (cp > 0xFFFF) 2 else 1
        }
        return sb.toString()
    }
}
