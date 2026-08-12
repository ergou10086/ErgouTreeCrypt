package hbnu.project.ergoutreecrypt.filestego.carrier.zip;

import hbnu.project.ergoutreecrypt.filestego.api.CarrierException;
import hbnu.project.ergoutreecrypt.filestego.api.EmbedOptions;
import hbnu.project.ergoutreecrypt.filestego.carrier.spi.AbstractCarrierAdapter;
import hbnu.project.ergoutreecrypt.filestego.carrier.spi.CarrierMetadata;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;
import java.util.List;

/**
 * ZIP 载体适配器
 * 不受限方案
 *
 * <p>ZIP 解析器从文件末尾向前扫描 EOCD（End Of Central Directory，签名
 * {@code 0x06054B50}）作为解析起点，因此在 ZIP 逻辑末尾（EOCD 记录及其注释之后）
 * 追加的任意数据会被解压工具完全忽略。本适配器据此把
 * {@code [CarrierMetadata + STEG-V2 Payload]} 组合块追加到 ZIP 末尾。
 *
 * <p>ZIP 压缩位流没有稳定可注入的有效负载冗余，故采用末尾追加的容量无关方案。
 *
 * @author ErgouTree
 * @since 2026/8/5
 */
public final class ZipCarrierAdapter extends AbstractCarrierAdapter {

    /** EOCD 记录签名（小端存储：50 4B 05 06）。 */
    private static final byte[] EOCD_SIGNATURE = {0x50, 0x4B, 0x05, 0x06};

    /** EOCD 固定部分字节数（不含可变注释）。 */
    private static final int EOCD_MIN_LEN = 22;

    /** EOCD 注释长度字段的最大值（uint16）。 */
    private static final int MAX_COMMENT_LEN = 0xFFFF;

    @Override
    public String id() {
        return "zip";
    }

    @Override
    public String displayName() {
        return "ZIP 压缩包";
    }

    @Override
    public List<String> supportedExtensions() {
        return List.of(".zip");
    }

    @Override
    protected void validateCarrier(final Path carrierFile) throws CarrierException {
        super.validateCarrier(carrierFile);
        try {
            byte[] bytes = Files.readAllBytes(carrierFile);
            if (findEocdOffset(bytes) < 0) {
                throw new CarrierException("不是有效的 ZIP 文件（未找到 EOCD 记录）: " + carrierFile);
            }
        } catch (IOException e) {
            throw new CarrierException("读取 ZIP 文件失败: " + e.getMessage(), e);
        }
    }

    @Override
    protected void doEmbed(final Path carrier, final byte[] payload, final byte[] meta,
                           final Path output, final byte[] password,
                           final EmbedOptions options) throws CarrierException {
        // payload 参数此处为门面组合好的 [CarrierMetadata + Payload] 不透明块
        byte[] combined = payload;
        try {
            byte[] zipBytes = Files.readAllBytes(carrier);
            try (OutputStream out = Files.newOutputStream(output,
                    StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING)) {
                out.write(zipBytes);
                out.write(combined);
            }
        } catch (IOException e) {
            throw new CarrierException("ZIP 嵌入失败: " + e.getMessage(), e);
        }
    }

    @Override
    protected CarrierMetadata doExtract(final Path stegoFile, final byte[] password)
            throws CarrierException {
        byte[] combined = readCombined(stegoFile);
        return CarrierMetadata.fromBytes(combined);
    }

    @Override
    protected byte[] readPayload(final Path stegoFile, final CarrierMetadata meta)
            throws CarrierException {
        byte[] combined = readCombined(stegoFile);
        int metaLen = CarrierMetadata.totalSize(meta.isParanoid(), meta.isStealth());
        if (combined.length < metaLen) {
            throw new CarrierException("ZIP 隐写数据不完整：组合块短于元数据长度");
        }
        return Arrays.copyOfRange(combined, metaLen, combined.length);
    }

    @Override
    public boolean detect(final Path file) {
        try {
            byte[] bytes = Files.readAllBytes(file);
            int trailerStart = trailerStart(bytes);
            if (trailerStart < 0 || trailerStart >= bytes.length) {
                return false;
            }
            byte[] tail = Arrays.copyOfRange(bytes, trailerStart, bytes.length);
            return CarrierMetadata.startsWithMagic(tail);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * 读取 ZIP 逻辑末尾之后追加的组合块。
     *
     * @param stegoFile 隐写 ZIP 文件
     * @return 组合块字节
     * @throws CarrierException 未找到隐写数据或读取失败
     */
    private byte[] readCombined(final Path stegoFile) throws CarrierException {
        try {
            byte[] bytes = Files.readAllBytes(stegoFile);
            int trailerStart = trailerStart(bytes);
            if (trailerStart < 0 || trailerStart >= bytes.length) {
                throw new CarrierException("ZIP 中未找到隐写数据");
            }
            byte[] tail = Arrays.copyOfRange(bytes, trailerStart, bytes.length);
            if (!CarrierMetadata.startsWithMagic(tail)) {
                throw new CarrierException("ZIP 尾部数据不是有效的隐写载荷");
            }
            return tail;
        } catch (IOException e) {
            throw new CarrierException("读取 ZIP 隐写数据失败: " + e.getMessage(), e);
        }
    }

    /**
     * 计算追加数据（组合块）的起始偏移——即 EOCD 记录（含注释）之后的位置。
     *
     * <p>优先选择"注释末尾之后恰好是 EGFS 隐写魔数"的 EOCD 候选，其次退回到
     * "注释末尾正好等于文件末尾"（无隐写数据）的候选，从而在追加了加密尾部数据的
     * 情况下也能稳定定位真实 EOCD。
     *
     * @param bytes ZIP 文件字节
     * @return 追加数据起始偏移，未找到有效 EOCD 返回 -1
     */
    private static int trailerStart(final byte[] bytes) {
        int eocd = findEocdOffset(bytes);
        if (eocd < 0) {
            return -1;
        }
        int commentLen = readUInt16LE(bytes, eocd + 20);
        return eocd + EOCD_MIN_LEN + commentLen;
    }

    /**
     * 从文件末尾向前扫描定位 EOCD 记录的起始偏移。
     *
     * <p>对于嵌入了隐写数据的 ZIP：EOCD 记录在逻辑末尾（嵌入数据之前），
     * 因此距离物理文件末尾可能超过注释长度上限（64KB），需要扫描整个文件。
     * 对于未嵌入隐写数据的原始 ZIP：EOCD 必须在文件末尾，只需回溯
     * {@code EOCD_MIN_LEN + MAX_COMMENT_LEN} 字节。
     *
     * <p>采用两轮筛选以避免压缩数据或加密载荷中的 EOCD 伪匹配：
     * <ol>
     *   <li>第一轮：在全文件范围内从后向前搜索，候选 EOCD 注释末尾之后
     *       紧跟 EGFS 隐写魔数（已嵌入隐写数据的场景）。</li>
     *   <li>第二轮：只在末尾 64KB 窗口内搜索，候选注释末尾恰好等于
     *       文件末尾（未嵌入隐写数据的原始 ZIP）。</li>
     * </ol>
     *
     * @param bytes ZIP 文件字节
     * @return EOCD 记录起始偏移，未找到返回 -1
     */
    private static int findEocdOffset(final byte[] bytes) {
        if (bytes.length < EOCD_MIN_LEN) {
            return -1;
        }

        // 第一轮：全文件扫描——注释之后紧跟 EGFS 隐写魔数
        // 因为追加的隐写数据大小无上限，EOCD 可能离物理文件末尾很远
        for (int i = bytes.length - EOCD_MIN_LEN; i >= 0; i--) {
            if (!matchAt(bytes, i, EOCD_SIGNATURE)) {
                continue;
            }
            int commentLen = readUInt16LE(bytes, i + 20);
            int declaredEnd = i + EOCD_MIN_LEN + commentLen;
            if (declaredEnd <= bytes.length
                    && startsWithEgfsAt(bytes, declaredEnd)) {
                return i;
            }
        }

        // 第二轮：末尾 64KB 窗口——注释末尾恰好等于文件末尾（原始 ZIP，无隐写数据）
        int maxBack = Math.min(bytes.length, EOCD_MIN_LEN + MAX_COMMENT_LEN);
        int start = bytes.length - maxBack;
        for (int i = bytes.length - EOCD_MIN_LEN; i >= start; i--) {
            if (!matchAt(bytes, i, EOCD_SIGNATURE)) {
                continue;
            }
            int commentLen = readUInt16LE(bytes, i + 20);
            if (i + EOCD_MIN_LEN + commentLen == bytes.length) {
                return i;
            }
        }
        return -1;
    }

    /**
     * 判断给定偏移处是否以 EGFS 魔数开头（原位检测，不复制数组）。
     *
     * @param data   字节数组
     * @param offset 起始偏移
     * @return true 如果该位置以 EGFS 开头
     */
    private static boolean startsWithEgfsAt(final byte[] data, final int offset) {
        return offset + CarrierMetadata.MAGIC_LEN <= data.length
                && data[offset]     == 0x45
                && data[offset + 1] == 0x47
                && data[offset + 2] == 0x46
                && data[offset + 3] == 0x53;
    }

    /**
     * 判断给定偏移处是否匹配签名。
     */
    private static boolean matchAt(final byte[] data, final int offset, final byte[] sig) {
        if (offset < 0 || offset + sig.length > data.length) {
            return false;
        }
        for (int i = 0; i < sig.length; i++) {
            if (data[offset + i] != sig[i]) {
                return false;
            }
        }
        return true;
    }

    /**
     * 读取小端 uint16。
     */
    private static int readUInt16LE(final byte[] data, final int offset) {
        return (data[offset] & 0xFF) | ((data[offset + 1] & 0xFF) << 8);
    }
}
