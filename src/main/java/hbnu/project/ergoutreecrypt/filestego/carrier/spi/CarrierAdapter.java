package hbnu.project.ergoutreecrypt.filestego.carrier.spi;

import hbnu.project.ergoutreecrypt.filestego.api.CarrierException;
import hbnu.project.ergoutreecrypt.filestego.api.EmbedOptions;
import hbnu.project.ergoutreecrypt.filestego.api.ProgressListener;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/**
 * 载体适配器——定义将 STEG-V2 Payload 嵌入/提取到特定文件格式的接口。
 *
 * <p>每个实现类对应一种载体文件格式（PNG、ZIP、PDF、WAV、FLAC、MP4 等）。
 * 新增载体格式只需增加一个 Adapter 实现并注册到 {@link CarrierRegistry}，
 * 无需修改上层代码。
 *
 * <p>本子系统仅采用<strong>容量无关</strong>嵌入：数据写入解码器忽略区
 * （末尾追加、自定义 chunk/box、metadata block 等），任意大小文件可嵌入任意大小容器。
 *
 * <h3>实现要求</h3>
 * <ul>
 *   <li>嵌入后的载体文件必须可被原始软件正常打开/使用</li>
 *   <li>提取时必须先验证载体元数据魔数</li>
 *   <li>{@link #detect} 应尽量只读取最小必要字节（如末尾 32 字节）</li>
 * </ul>
 *
 * @author ErgouTree
 * @since 2026/8/5
 */
public interface CarrierAdapter {

    /**
     * 返回此适配器的唯一标识。
     *
     * @return 标识符（如 "png"、"zip"、"pdf"）
     */
    String id();

    /**
     * 返回此适配器的人类可读名称。
     *
     * @return 显示名称（如 "PNG 图像"、"ZIP 压缩包"）
     */
    String displayName();

    /**
     * 返回支持的文件扩展名列表（含 "." 前缀）。
     *
     * @return 扩展名列表（如 {@code [".png"]}）
     */
    List<String> supportedExtensions();

    /**
     * 将 STEG-V2 Payload 嵌入到载体文件中（容量无关，写入解码器忽略区）。
     *
     * @param carrierFile 原始载体文件路径（未嵌入前的干净文件）
     * @param payload     完整的 STEG-V2 Payload 字节数组（或门面组合块）
     * @param output      输出文件路径
     * @param password    密码（用于隐蔽模式魔数派生；普通模式可为 null）
     * @param options     嵌入选项
     * @throws CarrierException 嵌入失败（格式不合法等）
     */
    void embed(Path carrierFile, byte[] payload, Path output,
               byte[] password, EmbedOptions options) throws CarrierException;

    /**
     * 从载体文件中提取 STEG-V2 Payload。
     *
     * @param stegoFile 包含隐写数据的载体文件
     * @param password  密码（隐蔽模式需要；普通模式可为 null）
     * @return 提取的完整 STEG-V2 Payload 字节数组
     * @throws CarrierException 提取失败（不是隐写文件、密码错误等）
     */
    byte[] extract(Path stegoFile, byte[] password) throws CarrierException;

    /**
     * 快速检测文件是否包含此适配器写入的隐写数据。
     *
     * <p>实现应尽量只读取最小必要字节以提高性能（例如末尾 32 字节）。
     *
     * @param file 待检测文件
     * @return true 如果可能是此适配器的隐写产物
     */
    boolean detect(Path file);

    /**
     * 估算载体文件的最大隐写容量（字节）。
     *
     * <p>容量无关方案下默认返回 {@link Long#MAX_VALUE}（理论无限）。
     *
     * @param carrierFile 载体文件
     * @return 最大可嵌入字节数，{@link Long#MAX_VALUE} 表示理论无限
     */
    default long capacity(Path carrierFile) {
        return Long.MAX_VALUE;
    }

    /**
     * 返回嵌入后的输出文件扩展名（通常与载体一致）。
     *
     * @return 输出扩展名（含 "." 前缀）
     */
    default String outputExtension() {
        return supportedExtensions().get(0);
    }

    /**
     * 是否支持大文件流式嵌入（恒定内存）。
     *
     * <p>默认 false：{@link #embedFromFile} 回退为读入内存后调用 {@link #embed}。
     * 实现流式嵌入的适配器应覆写为 true。
     *
     * @return true 表示支持流式嵌入
     */
    default boolean supportsStreamingEmbed() {
        return false;
    }

    /**
     * 是否支持大文件流式提取（恒定内存）。
     *
     * <p>默认 false：提取回退为读入内存的 {@code extractFull}。
     * 实现流式提取的适配器应覆写为 true。
     *
     * @return true 表示支持流式提取
     */
    default boolean supportsStreamingExtract() {
        return false;
    }

    /**
     * 将 STEG-V2 Payload 文件流式嵌入到载体文件中。
     *
     * <p>默认实现回退到 {@link #embed}（重建 meta+payload 组合块并读入内存）；
     * 支持大文件的适配器应覆写为真正的流式写入。{@code meta} 为序列化后的
     * {@link CarrierMetadata} 字节（由门面层提供，与 payload 分离传递）。
     *
     * @param carrierFile 原始载体文件路径（未嵌入前的干净文件）
     * @param meta        序列化后的 CarrierMetadata 字节数组
     * @param payloadFile STEG-V2 Payload 文件路径
     * @param output      输出文件路径
     * @param password    密码（可为 null）
     * @param options     嵌入选项
     * @throws CarrierException 嵌入失败（格式不合法等）
     */
    default void embedFromFile(final Path carrierFile, final byte[] meta,
                               final Path payloadFile, final Path output,
                               final byte[] password, final EmbedOptions options)
            throws CarrierException {
        embedFromFile(carrierFile, meta, payloadFile, output, password, options, null);
    }

    /**
     * 将 STEG-V2 Payload 文件流式嵌入到载体文件中（带进度回调）。
     *
     * <p>默认实现回退到 {@link #embed}（分块读入 meta+payload 组合块后调用
     * 内存版嵌入），读取阶段按已读字节数回调进度 0~0.5，嵌入完成后回调 1.0；
     * 支持大文件的适配器应覆写为真正的流式写入并按已写字节数逐块回调。
     *
     * @param carrierFile 原始载体文件路径（未嵌入前的干净文件）
     * @param meta        序列化后的 CarrierMetadata 字节数组
     * @param payloadFile STEG-V2 Payload 文件路径
     * @param output      输出文件路径
     * @param password    密码（可为 null）
     * @param options     嵌入选项
     * @param listener    进度监听器（可为 null）
     * @throws CarrierException 嵌入失败（格式不合法等）
     */
    default void embedFromFile(final Path carrierFile, final byte[] meta,
                               final Path payloadFile, final Path output,
                               final byte[] password, final EmbedOptions options,
                               final ProgressListener listener)
            throws CarrierException {
        try {
            long payloadSize = Files.size(payloadFile);
            byte[] payloadBytes;
            try (InputStream in = Files.newInputStream(payloadFile)) {
                ByteArrayOutputStream buf = new ByteArrayOutputStream(
                        (int) Math.min(payloadSize, Integer.MAX_VALUE));
                byte[] chunk = new byte[READ_CHUNK_BYTES];
                long read = 0;
                int n;
                while ((n = in.read(chunk)) > 0) {
                    buf.write(chunk, 0, n);
                    read += n;
                    if (listener != null) {
                        listener.onProgress(0.5 * read / Math.max(payloadSize, 1L));
                    }
                }
                payloadBytes = buf.toByteArray();
            }
            byte[] combined = new byte[meta.length + payloadBytes.length];
            System.arraycopy(meta, 0, combined, 0, meta.length);
            System.arraycopy(payloadBytes, 0, combined, meta.length, payloadBytes.length);
            embed(carrierFile, combined, output, password, options);
            if (listener != null) {
                listener.onProgress(1.0);
            }
        } catch (CarrierException e) {
            throw e;
        } catch (IOException e) {
            throw new CarrierException("读取 Payload 文件失败: " + e.getMessage(), e);
        }
    }

    /** 默认回退嵌入的读入分块大小（256 KiB）。 */
    int READ_CHUNK_BYTES = 1 << 18;
}
