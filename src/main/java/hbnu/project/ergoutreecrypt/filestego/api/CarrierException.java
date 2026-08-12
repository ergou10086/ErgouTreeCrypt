package hbnu.project.ergoutreecrypt.filestego.api;

/**
 * 载体适配器操作异常——在嵌入或提取过程中发生的与载体格式相关的错误。
 *
 * <p>涵盖以下场景：
 * <ul>
 *   <li>载体文件格式不合法（不是有效的 PNG/ZIP/PDF 等）</li>
 *   <li>载体文件中未找到隐写数据</li>
 *   <li>隐蔽模式魔数验证失败</li>
 *   <li>载体格式不合法或嵌入/提取失败</li>
 *   <li>载体文件结构损坏</li>
 * </ul>
 *
 * @author ErgouTree
 * @since 2026/8/5
 */
public class CarrierException extends Exception {

    /**
     * 创建携带错误消息的载体异常。
     *
     * @param message 错误描述
     */
    public CarrierException(final String message) {
        super(message);
    }

    /**
     * 创建携带错误消息和原因的载体异常。
     *
     * @param message 错误描述
     * @param cause   底层异常
     */
    public CarrierException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
