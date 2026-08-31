package hbnu.project.ergoutreecrypt.filestego.carrier.spi;

import hbnu.project.ergoutreecrypt.filestego.api.CarrierException;
import hbnu.project.ergoutreecrypt.filestego.api.EmbedOptions;
import hbnu.project.ergoutreecrypt.filestego.api.ProgressListener;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

/**
 * Carrier Adapter 模板基类——提供嵌入/提取的通用流程骨架。
 *
 * <p>子类只需实现三个格式相关的抽象方法：
 * <ul>
 *   <li>{@link #doEmbed}——格式特定的写入逻辑</li>
 *   <li>{@link #doExtract}——格式特定的读取逻辑</li>
 *   <li>{@link #readPayload}——从载体文件读取完整 Payload</li>
 * </ul>
 *
 * <p>模板方法 {@link #embed} 和 {@link #extract} 封装了验证载体、
 * 构建/解析元数据、错误处理等通用逻辑。
 *
 * @author ErgouTree
 * @since 2026/8/5
 */
public abstract class AbstractCarrierAdapter implements CarrierAdapter {

    /**
     * 嵌入流程骨架。
     *
     * <p>执行步骤：
     * <ol>
     *   <li>验证载体文件格式</li>
     *   <li>构建 {@link CarrierMetadata} 二进制块</li>
     *   <li>委托子类执行格式特定嵌入</li>
     * </ol>
     */
    @Override
    public final void embed(final Path carrierFile, final byte[] payload, final Path output,
                             final byte[] password, final EmbedOptions options)
            throws CarrierException {
        validateCarrier(carrierFile);
        byte[] meta = buildCarrierMetadata(payload.length, options);
        doEmbed(carrierFile, payload, meta, output, password, options);
    }

    /**
     * 提取流程骨架——仅返回 Payload 字节。
     *
     * <p>如需同时获取 {@link CarrierMetadata}（例如供 {@code PayloadCodec.decode} 使用），
     * 请改用 {@link #extractFull(Path, byte[])}。
     */
    @Override
    public final byte[] extract(final Path stegoFile, final byte[] password)
            throws CarrierException {
        return extractFull(stegoFile, password).payload();
    }

    /**
     * 提取流程骨架——返回完整的 {@link CarrierResult}（含元数据和 Payload）。
     *
     * <p>执行步骤：
     * <ol>
     *   <li>委托子类执行格式特定提取，返回 {@link CarrierMetadata}</li>
     *   <li>验证元数据魔数和 Payload 大小合理性</li>
     *   <li>委托子类读取 Payload 数据</li>
     *   <li>返回包含两者的 {@link CarrierResult}</li>
     * </ol>
     *
     * @param stegoFile 隐写载体文件
     * @param password  密码
     * @return 包含载体元数据和 Payload 的提取结果
     * @throws CarrierException 提取或解析失败
     */
    public final CarrierResult extractFull(final Path stegoFile, final byte[] password)
            throws CarrierException {
        // 步骤 1：委托子类读取格式特定的元数据
        CarrierMetadata meta = doExtract(stegoFile, password);
        // 步骤 2：验证魔数和版本（fromBytes 已经做了，这里做额外的 payloadSize 合理性检查）
        if (meta.payloadSize() <= 0) {
            throw new CarrierException("载体元数据中 Payload 大小异常: " + meta.payloadSize());
        }
        // 步骤 3：委托子类读取 Payload
        byte[] payload = readPayload(stegoFile, meta);
        return new CarrierResult(meta, payload);
    }

    /**
     * 从载体文件提取 Payload 到文件。
     *
     * <p>默认实现回退到 {@link #extractFull}（读入内存后写出）；支持大文件的
     * 适配器应覆写为按 {@code meta.payloadSize()} 精确读取并流式写入。
     *
     * @param stegoFile  隐写载体文件
     * @param password   密码（可为 null）
     * @param payloadOut Payload 输出文件路径
     * @return 解析后的载体元数据
     * @throws CarrierException 提取失败
     */
    public CarrierMetadata extractFullToFile(final Path stegoFile, final byte[] password,
                                             final Path payloadOut) throws CarrierException {
        return extractFullToFile(stegoFile, password, payloadOut, null);
    }

    /**
     * 从载体文件提取 Payload 到文件（带进度回调）。
     *
     * <p>默认实现回退到 {@link #extractFull}（读入内存后分块写出），写出阶段
     * 按已写字节数回调进度 0~1.0；支持大文件的适配器应覆写为按
     * {@code meta.payloadSize()} 精确读取并流式写入，同时逐块回调进度。
     *
     * @param stegoFile  隐写载体文件
     * @param password   密码（可为 null）
     * @param payloadOut Payload 输出文件路径
     * @param listener   进度监听器（可为 null）
     * @return 解析后的载体元数据
     * @throws CarrierException 提取失败
     */
    public CarrierMetadata extractFullToFile(final Path stegoFile, final byte[] password,
                                             final Path payloadOut,
                                             final ProgressListener listener)
            throws CarrierException {
        CarrierResult result = extractFull(stegoFile, password);
        byte[] payload = result.payload();
        try (OutputStream out = Files.newOutputStream(payloadOut)) {
            int off = 0;
            while (off < payload.length) {
                int n = Math.min(WRITE_CHUNK_BYTES, payload.length - off);
                out.write(payload, off, n);
                off += n;
                if (listener != null) {
                    listener.onProgress((double) off / Math.max(payload.length, 1));
                }
            }
        } catch (IOException e) {
            throw new CarrierException("写入 Payload 文件失败: " + e.getMessage(), e);
        }
        return result.metadata();
    }

    /** 默认回退提取的写出分块大小（256 KiB）。 */
    private static final int WRITE_CHUNK_BYTES = 1 << 18;

    // ---- 只读预检（供移动端在提取前判定 KDF 档位与压缩标志） ----

    /**
     * 只读取并解析载体元数据，不读取 Payload。
     *
     * <p>供移动端提取前预检使用：只需知道 {@code CarrierMetadata} 中的 Argon2
     * 参数档位，无需提取整个 Payload。默认实现直接委托 {@link #doExtract}。
     *
     * @param stegoFile 隐写载体文件
     * @param password  密码（可为 null；文件隐写载体的定位不依赖密码）
     * @return 解析后的载体元数据
     * @throws CarrierException 提取或解析失败
     */
    public CarrierMetadata readMetadataOnly(final Path stegoFile, final byte[] password)
            throws CarrierException {
        return doExtract(stegoFile, password);
    }

    /**
     * 只读取 Payload 头的前若干字节，不读取完整 Payload。
     *
     * <p>供移动端提取前预检使用：只需 Payload 头的前 10 字节即可判定「加密前压缩」
     * 标志，无需提取整个 Payload。默认实现读取完整 Payload 后截断；支持大文件的
     * 适配器应覆写为定点读取，避免把大 Payload 全量读入内存。
     *
     * @param stegoFile 隐写载体文件
     * @param meta      已解析的载体元数据（含 payloadSize）
     * @param maxLen    最多读取的字节数
     * @return Payload 头的前 {@code min(maxLen, payloadSize)} 字节
     * @throws CarrierException 读取失败
     */
    public byte[] readPayloadPrefix(final Path stegoFile, final CarrierMetadata meta,
                                    final int maxLen) throws CarrierException {
        byte[] payload = readPayload(stegoFile, meta);
        int n = Math.min(maxLen, payload.length);
        return Arrays.copyOf(payload, n);
    }

    // ---- 子类必须实现 ----

    /**
     * 格式特定的嵌入逻辑（写入解码器忽略区）。
     *
     * @param carrier  原始载体文件路径
     * @param payload  STEG-V2 Payload 字节数组（或门面组合块）
     * @param meta     序列化后的 {@link CarrierMetadata} 字节数组
     * @param output   输出文件路径
     * @param password 密码
     * @param options  嵌入选项
     * @throws CarrierException 嵌入失败
     */
    protected abstract void doEmbed(Path carrier, byte[] payload, byte[] meta,
                                    Path output, byte[] password,
                                    EmbedOptions options) throws CarrierException;

    /**
     * 格式特定的提取逻辑——读取并解析载体元数据。
     *
     * <p>实现应从载体文件的格式特定位置读取 CarrierMetadata 原始字节，
     * 调用 {@link CarrierMetadata#fromBytes(byte[])} 解析后返回。
     *
     * @param stegoFile 隐写载体文件
     * @param password  密码
     * @return 解析后的载体元数据
     * @throws CarrierException 提取或解析失败
     */
    protected abstract CarrierMetadata doExtract(Path stegoFile, byte[] password)
            throws CarrierException;

    /**
     * 从载体文件读取完整 Payload 数据。
     *
     * @param stegoFile 隐写载体文件
     * @param meta      已解析的载体元数据（含 payloadSize）
     * @return 完整的 Payload 字节数组
     * @throws CarrierException 读取失败
     */
    protected abstract byte[] readPayload(Path stegoFile, CarrierMetadata meta)
            throws CarrierException;

    // ---- 可选覆盖 ----

    /**
     * 验证载体文件是否为合法格式（嵌入前检查）。
     *
     * <p>默认仅检查是否为常规文件，子类可以覆盖以检查文件签名等。
     *
     * @param carrierFile 载体文件路径
     * @throws CarrierException 格式不合法
     */
    protected void validateCarrier(final Path carrierFile) throws CarrierException {
        if (!Files.isRegularFile(carrierFile)) {
            throw new CarrierException("载体文件不存在或不是常规文件: " + carrierFile);
        }
    }

    /**
     * 构建 Carrier Metadata 二进制块。
     *
     * <p>根据 {@link EmbedOptions} 设置 flags。注意：salt、hkdfSalt、nonce、serpentIv、
     * stealthSalt 应由调用方预先填充，或由子类覆盖此方法自行提供；默认使用全零占位。
     *
     * @param payloadSize Payload 总字节数
     * @param options     嵌入选项
     * @return 序列化后的 {@link CarrierMetadata} 字节数组
     */
    protected byte[] buildCarrierMetadata(final long payloadSize, final EmbedOptions options) {
        byte flags = CarrierMetadata.buildFlags(
                options.isParanoid(), options.hasIntegrity(), options.isStealth());
        byte[] salt = new byte[16];
        byte[] hkdfSalt = new byte[32];
        byte[] nonce = new byte[24];
        byte[] serpentIv = options.isParanoid() ? new byte[16] : null;
        byte[] stealthSalt = options.isStealth() ? new byte[16] : null;

        CarrierMetadata meta = new CarrierMetadata(payloadSize, flags,
                salt, hkdfSalt, nonce, serpentIv, stealthSalt);
        return meta.toBytes();
    }

    /**
     * 默认检测实现——从文件末尾 256 字节搜索 "EGFS" 魔数。
     *
     * <p>适用于所有"末尾追加"模式的适配器。自定义 chunk/box 模式的适配器
     * 应覆盖此方法以提供格式特定的检测逻辑。
     *
     * @param file 待检测文件
     * @return true 如果发现载体元数据魔数
     */
    @Override
    public boolean detect(final Path file) {
        try {
            long fileSize = Files.size(file);
            int searchLen = Math.min(256, (int) fileSize);
            byte[] tail = new byte[searchLen];
            try (java.io.InputStream in = Files.newInputStream(file)) {
                long skipBytes = fileSize - searchLen;
                long skipped = 0;
                while (skipped < skipBytes) {
                    long s = in.skip(skipBytes - skipped);
                    if (s <= 0) {
                        return false;
                    }
                    skipped += s;
                }
                int read = in.readNBytes(tail, 0, searchLen);
                if (read != searchLen) {
                    return false;
                }
            }
            // 在尾部搜索魔数
            for (int i = 0; i <= tail.length - CarrierMetadata.MAGIC_LEN; i++) {
                boolean match = true;
                for (int j = 0; j < CarrierMetadata.MAGIC_LEN; j++) {
                    if (tail[i + j] != CarrierMetadata.MAGIC[j]) {
                        match = false;
                        break;
                    }
                }
                if (match) {
                    return true;
                }
            }
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * 默认容量估算——容量无关方案返回理论无限。
     *
     * @param carrierFile 载体文件
     * @return {@link Long#MAX_VALUE}
     */
    @Override
    public long capacity(final Path carrierFile) {
        return Long.MAX_VALUE;
    }
}
