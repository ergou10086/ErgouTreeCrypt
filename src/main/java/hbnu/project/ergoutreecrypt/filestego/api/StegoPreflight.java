package hbnu.project.ergoutreecrypt.filestego.api;

/**
 * 文件隐写载体预检结果——移动端在提取前只读探测到的 KDF 档位与压缩标志。
 *
 * <p>用于对齐卷路径的「加密前压缩」防护策略（见移动端解密桌面端内容修复计划
 * §14.9）：提取前读取载体元数据与 Payload 头，识别两类不可/较难处理的情况：
 * <ul>
 *   <li>{@code argon2MemoryKib == null}——旧文件回落默认 1 GiB，提取较慢，提示即可；</li>
 *   <li>{@code compressed == true}——使用了「加密前压缩」（zstd-jni 无 Android ABI），
 *       移动端无法解压，应直接拒绝。</li>
 * </ul>
 *
 * @param argon2MemoryKib Argon2 内存参数（KiB）；{@code null} 表示旧文件（回落默认
 *                        1 GiB）或未记录参数
 * @param compressed      是否使用了「加密前压缩」（Zstandard）；{@code null} 表示
 *                        无法判定（Payload 头读取失败）
 * @author ErgouTree
 * @since 2026/8/31
 */
public record StegoPreflight(Integer argon2MemoryKib, Boolean compressed) {

    /** 无法预检（非隐写文件或探测失败）的占位结果。 */
    public static final StegoPreflight UNKNOWN = new StegoPreflight(null, null);
}
