package hbnu.project.ergoutreecrypt.filestego.carrier.zip;

import hbnu.project.ergoutreecrypt.filestego.api.CarrierException;
import hbnu.project.ergoutreecrypt.filestego.api.EmbedOptions;
import hbnu.project.ergoutreecrypt.filestego.api.ProgressListener;
import hbnu.project.ergoutreecrypt.filestego.carrier.spi.AbstractCarrierAdapter;
import hbnu.project.ergoutreecrypt.filestego.carrier.spi.CarrierMetadata;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.RandomAccessFile;
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

    /** 流式倒扫/复制分块大小（1 MiB）。 */
    private static final int STREAM_CHUNK_BYTES = 1 << 20;

    /** 元数据探测上限（≥ paranoid+stealth 组合下的最大 126 字节）。 */
    private static final int META_PROBE_LEN = 128;

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
            if (!hasEocdAtTail(carrierFile)) {
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
        // 按 meta.payloadSize() 精确截断，防止 obfuscateSize 追加的 padding 混入
        long payloadSize = meta.payloadSize();
        int end = Math.min(combined.length, (int) Math.min(Integer.MAX_VALUE,
                metaLen + payloadSize));
        if (end < metaLen) {
            throw new CarrierException("ZIP 隐写数据不完整：Payload 超出可寻址范围");
        }
        return Arrays.copyOfRange(combined, metaLen, end);
    }

    @Override
    public boolean detect(final Path file) {
        try {
            return locateTrailerStart(file) >= 0;
        } catch (Exception e) {
            return false;
        }
    }

    // ---- 流式嵌入 / 提取（大文件，恒定内存） ----

    @Override
    public boolean supportsStreamingEmbed() {
        return true;
    }

    @Override
    public boolean supportsStreamingExtract() {
        return true;
    }

    /**
     * 流式嵌入：分块复制载体后依次追加元数据与 Payload 文件，不将任何部分
     * 全量读入内存。
     *
     * @param carrierFile 原始载体文件路径
     * @param meta        序列化后的 CarrierMetadata 字节数组
     * @param payloadFile STEG-V2 Payload 文件路径
     * @param output      输出文件路径
     * @param password    密码（ZIP 末尾追加方案不使用）
     * @param options     嵌入选项
     * @throws CarrierException 嵌入失败
     */
    @Override
    public void embedFromFile(final Path carrierFile, final byte[] meta,
                              final Path payloadFile, final Path output,
                              final byte[] password, final EmbedOptions options)
            throws CarrierException {
        embedFromFile(carrierFile, meta, payloadFile, output, password, options, null);
    }

    /**
     * 流式嵌入（带进度回调）：分块复制载体后依次追加元数据与 Payload 文件，
     * 并按已复制字节数占载体与 Payload 总字节数的比例逐块回调进度。
     *
     * @param carrierFile 原始载体文件路径
     * @param meta        序列化后的 CarrierMetadata 字节数组
     * @param payloadFile STEG-V2 Payload 文件路径
     * @param output      输出文件路径
     * @param password    密码（ZIP 末尾追加方案不使用）
     * @param options     嵌入选项
     * @param listener    进度监听器（可为 null）
     * @throws CarrierException 嵌入失败
     */
    @Override
    public void embedFromFile(final Path carrierFile, final byte[] meta,
                              final Path payloadFile, final Path output,
                              final byte[] password, final EmbedOptions options,
                              final ProgressListener listener)
            throws CarrierException {
        long done = 0;
        try (OutputStream out = Files.newOutputStream(output,
                StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING)) {
            long carrierSize = Files.size(carrierFile);
            long total = carrierSize + Files.size(payloadFile);
            // 1. 分块复制载体
            byte[] buf = new byte[STREAM_CHUNK_BYTES];
            try (InputStream cin = Files.newInputStream(carrierFile)) {
                int n;
                while ((n = cin.read(buf)) > 0) {
                    out.write(buf, 0, n);
                    done += n;
                    if (listener != null) {
                        listener.onProgress((double) done / Math.max(total, 1L));
                    }
                }
            }
            // 2. 追加元数据
            out.write(meta);
            // 3. 分块追加 Payload
            try (InputStream in = Files.newInputStream(payloadFile)) {
                int n;
                while ((n = in.read(buf)) > 0) {
                    out.write(buf, 0, n);
                    done += n;
                    if (listener != null) {
                        listener.onProgress((double) done / Math.max(total, 1L));
                    }
                }
            }
            if (listener != null) {
                listener.onProgress(1.0);
            }
        } catch (IOException e) {
            throw new CarrierException("ZIP 嵌入失败: " + e.getMessage(), e);
        }
    }

    /**
     * 流式提取：倒扫定位 trailer 起点，定点读取元数据，再按
     * {@code meta.payloadSize()} 精确流式拷贝 Payload 到文件。
     *
     * @param stegoFile  隐写载体文件
     * @param password   密码（ZIP 末尾追加方案不使用）
     * @param payloadOut Payload 输出文件路径
     * @return 解析后的载体元数据
     * @throws CarrierException 提取失败
     */
    @Override
    public CarrierMetadata extractFullToFile(final Path stegoFile, final byte[] password,
                                             final Path payloadOut) throws CarrierException {
        return extractFullToFile(stegoFile, password, payloadOut, null);
    }

    /**
     * 流式提取（带进度回调）：倒扫定位 trailer 起点，定点读取元数据，再按
     * {@code meta.payloadSize()} 精确流式拷贝 Payload 到文件，并按已拷贝
     * 字节数逐块回调进度。
     *
     * @param stegoFile  隐写载体文件
     * @param password   密码（ZIP 末尾追加方案不使用）
     * @param payloadOut Payload 输出文件路径
     * @param listener   进度监听器（可为 null）
     * @return 解析后的载体元数据
     * @throws CarrierException 提取失败
     */
    @Override
    public CarrierMetadata extractFullToFile(final Path stegoFile, final byte[] password,
                                             final Path payloadOut,
                                             final ProgressListener listener)
            throws CarrierException {
        try (RandomAccessFile raf = new RandomAccessFile(stegoFile.toFile(), "r")) {
            long fileSize = Files.size(stegoFile);
            long trailerStart = locateTrailerStart(stegoFile);
            if (trailerStart < 0) {
                throw new CarrierException("ZIP 中未找到隐写数据");
            }
            // 定点读取并解析元数据（最多 126 字节）
            int metaProbe = (int) Math.min(META_PROBE_LEN, fileSize - trailerStart);
            byte[] metaRaw = new byte[metaProbe];
            raf.seek(trailerStart);
            raf.readFully(metaRaw);
            CarrierMetadata meta = CarrierMetadata.fromBytes(metaRaw);
            int metaLen = CarrierMetadata.totalSize(meta.isParanoid(), meta.isStealth());
            long payloadStart = trailerStart + metaLen;
            long payloadSize = meta.payloadSize();
            if (payloadSize < 0 || payloadStart + payloadSize > fileSize) {
                throw new CarrierException("ZIP 隐写数据不完整：Payload 超出文件范围");
            }
            // 定点流式拷贝 payloadSize 字节
            raf.seek(payloadStart);
            try (OutputStream out = Files.newOutputStream(payloadOut,
                    StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING)) {
                copyRange(raf, out, payloadSize, listener);
            }
            return meta;
        } catch (CarrierException e) {
            throw e;
        } catch (IOException e) {
            throw new CarrierException("读取 ZIP 隐写数据失败: " + e.getMessage(), e);
        }
    }

    // ---- 流式定位与校验 ----

    /**
     * 流式定位隐写 ZIP 的 trailer 起点（EOCD 记录含注释之后）。
     *
     * <p>嵌入布局为 [zip][EOCD+注释][EGFS meta][payload]，payload 在文件末尾，
     * 因此 EOCD 距离物理文件尾可能超过 64KB 注释窗口。从文件尾向前按
     * {@value #STREAM_CHUNK_BYTES} 字节分块倒扫 EOCD 签名（块间 3 字节重叠处理
     * 跨块签名）；每个候选定点读取 commentLen 并对"注释末尾"做完整
     * {@link CarrierMetadata#fromBytes} 校验（魔数 + 版本 + 字段合法性，
     * 假阳性概率可忽略）。首个通过校验的候选即真实 EOCD。
     *
     * @param stegoFile 隐写 ZIP 文件
     * @return trailer 起点偏移（EGFS 元数据起始位置），未找到返回 -1
     * @throws IOException 读取失败
     */
    private static long locateTrailerStart(final Path stegoFile) throws IOException {
        long fileSize = Files.size(stegoFile);
        if (fileSize < EOCD_MIN_LEN) {
            return -1;
        }
        byte[] buf = new byte[STREAM_CHUNK_BYTES + EOCD_SIGNATURE.length - 1];
        try (RandomAccessFile raf = new RandomAccessFile(stegoFile.toFile(), "r")) {
            long nextEnd = fileSize;
            while (nextEnd > 0) {
                long readStart = Math.max(0, nextEnd - STREAM_CHUNK_BYTES);
                int want = (int) (nextEnd - readStart);
                if (readStart > 0) {
                    // 多读 3 字节重叠，处理跨块 EOCD 签名
                    readStart -= EOCD_SIGNATURE.length - 1;
                    want += EOCD_SIGNATURE.length - 1;
                }
                raf.seek(readStart);
                raf.readFully(buf, 0, want);
                for (int i = want - EOCD_MIN_LEN; i >= 0; i--) {
                    long absOffset = readStart + i;
                    // 候选记录延伸到重叠区之外（下一块范围），由下一轮处理
                    if (absOffset + EOCD_MIN_LEN > nextEnd) {
                        continue;
                    }
                    if (!matchAt(buf, i, EOCD_SIGNATURE, want)) {
                        continue;
                    }
                    int commentLen = (buf[i + 20] & 0xFF) | ((buf[i + 21] & 0xFF) << 8);
                    long declaredEnd = absOffset + EOCD_MIN_LEN + commentLen;
                    if (declaredEnd > fileSize) {
                        continue;
                    }
                    if (isMetadataAt(raf, declaredEnd, fileSize)) {
                        return declaredEnd;
                    }
                }
                if (readStart <= 0) {
                    break;
                }
                nextEnd = readStart + EOCD_SIGNATURE.length - 1;
            }
            return -1;
        }
    }

    /**
     * 校验给定偏移处是否为完整合法的 CarrierMetadata（魔数 + 可解析）。
     *
     * @param raf      已打开的随机读取通道
     * @param offset   待校验偏移
     * @param fileSize 文件总大小
     * @return true 表示该偏移处为合法载体元数据
     * @throws IOException 读取失败
     */
    private static boolean isMetadataAt(final RandomAccessFile raf, final long offset,
                                        final long fileSize) throws IOException {
        if (offset < 0 || offset + CarrierMetadata.MAGIC_LEN > fileSize) {
            return false;
        }
        int probeLen = (int) Math.min(META_PROBE_LEN, fileSize - offset);
        byte[] probe = new byte[probeLen];
        raf.seek(offset);
        raf.readFully(probe);
        if (!CarrierMetadata.startsWithMagic(probe)) {
            return false;
        }
        try {
            CarrierMetadata.fromBytes(probe);
            return true;
        } catch (CarrierException e) {
            return false;
        }
    }

    /**
     * 流式校验干净 ZIP：EOCD（含注释）必须位于文件末尾 64KB 窗口内且注释末尾
     * 恰好等于文件末尾（无追加数据）。
     *
     * @param file ZIP 文件路径
     * @return true 表示尾部存在合法 EOCD
     * @throws IOException 读取失败
     */
    private static boolean hasEocdAtTail(final Path file) throws IOException {
        long fileSize = Files.size(file);
        if (fileSize < EOCD_MIN_LEN) {
            return false;
        }
        int maxBack = (int) Math.min(fileSize, EOCD_MIN_LEN + MAX_COMMENT_LEN);
        try (RandomAccessFile raf = new RandomAccessFile(file.toFile(), "r")) {
            byte[] tail = new byte[maxBack];
            raf.seek(fileSize - maxBack);
            raf.readFully(tail);
            for (int i = tail.length - EOCD_MIN_LEN; i >= 0; i--) {
                if (!matchAt(tail, i, EOCD_SIGNATURE, tail.length)) {
                    continue;
                }
                int commentLen = (tail[i + 20] & 0xFF) | ((tail[i + 21] & 0xFF) << 8);
                long declaredEnd = fileSize - maxBack + i + EOCD_MIN_LEN + commentLen;
                if (declaredEnd == fileSize) {
                    return true;
                }
            }
            return false;
        }
    }

    /**
     * 从随机读取通道定点分块拷贝指定字节数到输出流，并按已拷贝字节数回调进度。
     *
     * @param raf      随机读取通道
     * @param out      输出流
     * @param length   待拷贝字节数
     * @param listener 进度监听器（可为 null）
     * @throws IOException 读写失败
     */
    private static void copyRange(final RandomAccessFile raf, final OutputStream out,
                                  final long length, final ProgressListener listener)
            throws IOException {
        byte[] buf = new byte[STREAM_CHUNK_BYTES];
        long remaining = length;
        while (remaining > 0) {
            int n = (int) Math.min(remaining, buf.length);
            raf.readFully(buf, 0, n);
            out.write(buf, 0, n);
            remaining -= n;
            if (listener != null) {
                listener.onProgress((double) (length - remaining) / Math.max(length, 1L));
            }
        }
        if (listener != null && length <= 0) {
            listener.onProgress(1.0);
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
        return matchAt(data, offset, sig, data.length);
    }

    /**
     * 判断给定偏移处是否匹配签名（限定有效数据长度，用于流式分块缓冲）。
     *
     * @param data    字节缓冲
     * @param offset  起始偏移
     * @param sig     签名
     * @param dataLen 缓冲内有效字节数
     * @return true 表示匹配
     */
    private static boolean matchAt(final byte[] data, final int offset, final byte[] sig,
                                   final int dataLen) {
        if (offset < 0 || offset + sig.length > dataLen) {
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
