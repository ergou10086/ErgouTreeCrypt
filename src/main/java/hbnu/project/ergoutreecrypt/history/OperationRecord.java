package hbnu.project.ergoutreecrypt.history;

/**
 * 一条加密操作历史记录。
 *
 * <p>记录一次成功加解密操作的简要信息：文件名、操作类型、操作时间，
 * 以及用于"打开输出文件夹"的定位信息。
 *
 * <p>设计要点：
 * <ul>
 *   <li>{@code outputPath} 为输出文件的绝对路径（桌面端与移动端非 SAF 输出时必有值）；</li>
 *   <li>{@code outputUri} 为移动端 SAF 目录树的 URI 字符串（仅 SAF 输出时有值），
 *       用于跨进程/跨重启定位输出位置；</li>
 *   <li>二者均可为 {@code null}，存储层与展示层必须容忍空值；</li>
 *   <li>新增操作类型时仅需扩展 {@link OperationType}，本结构无需变更；
 *       若未来需要携带更多信息，可在此追加组件（record 结构向后兼容序列化格式）。</li>
 * </ul>
 *
 * @param fileName            文件名（输入文件或输出文件的名称）
 * @param outputPath          输出文件/目录的绝对路径，可为 null
 * @param outputUri           移动端 SAF 输出目录树 URI 字符串，可为 null
 * @param type                操作类型
 * @param timestampEpochMillis 操作完成时间（Unix 毫秒时间戳）
 * @author ErgouTree
 * @since 2026/8/14
 */
public record OperationRecord(
        String fileName,
        String outputPath,
        String outputUri,
        OperationType type,
        long timestampEpochMillis) {
}
