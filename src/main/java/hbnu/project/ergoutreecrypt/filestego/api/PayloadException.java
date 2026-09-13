package hbnu.project.ergoutreecrypt.filestego.api;

import hbnu.project.ergoutreecrypt.exception.CryptoException;
import hbnu.project.ergoutreecrypt.exception.ErrorKind;

/**
 * Payload 编解码异常——在 STEG-V2 Payload 的编码或解码过程中发生的错误。
 *
 * <p>涵盖以下场景：
 * <ul>
 *   <li>魔数不匹配（不是有效的 STEG-V2 Payload）</li>
 *   <li>版本不支持</li>
 *   <li>Header MAC 验证失败（密码错误）</li>
 *   <li>Payload MAC 验证失败（数据被篡改）</li>
 *   <li>Metadata JSON 解析失败</li>
 *   <li>数据截断或不完整</li>
 * </ul>
 *
 * <p>默认归类为 {@link ErrorKind#PAYLOAD_INVALID}。
 *
 * @author ErgouTree
 * @since 2026/8/5
 */
public class PayloadException extends CryptoException {

    /**
     * 创建携带错误消息的 Payload 异常。
     *
     * @param message 错误描述
     */
    public PayloadException(final String message) {
        super(ErrorKind.PAYLOAD_INVALID, message);
    }

    /**
     * 创建携带错误消息和原因的 Payload 异常。
     *
     * @param message 错误描述
     * @param cause   底层异常
     */
    public PayloadException(final String message, final Throwable cause) {
        super(ErrorKind.PAYLOAD_INVALID, message, cause);
    }
}
