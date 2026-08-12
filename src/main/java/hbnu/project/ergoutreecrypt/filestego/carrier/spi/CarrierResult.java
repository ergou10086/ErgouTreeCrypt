package hbnu.project.ergoutreecrypt.filestego.carrier.spi;

/**
 * 载体提取结果——包含从载体文件中提取的元数据和 Payload。
 *
 * <p>由 {@link CarrierAdapter} 的提取流程返回，供门面 {@code FileStegoCodec}
 * 获取密码学参数和 Payload 数据。
 *
 * @param metadata 载体元数据（含密码学参数）
 * @param payload  提取的 STEG-V2 Payload 字节数组
 * @author ErgouTree
 * @since 2026/8/5
 */
public record CarrierResult(CarrierMetadata metadata, byte[] payload) {
}
