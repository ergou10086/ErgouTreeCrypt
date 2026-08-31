package hbnu.project.ergoutreecrypt.filestego.carrier.png;

import hbnu.project.ergoutreecrypt.filestego.api.CarrierException;
import hbnu.project.ergoutreecrypt.filestego.api.EmbedOptions;
import hbnu.project.ergoutreecrypt.filestego.api.ProgressListener;
import hbnu.project.ergoutreecrypt.filestego.carrier.spi.AbstractCarrierAdapter;
import hbnu.project.ergoutreecrypt.filestego.carrier.spi.CarrierMetadata;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;
import java.util.List;
import java.util.zip.CRC32;

/**
 * PNG 载体适配器（不受限方案）。
 *
 * <p>将 {@code [CarrierMetadata + STEG-V2 Payload]} 组合块写入 PNG 文件的
 * 解码器忽略区，两种落点由 {@link EmbedOptions#preferChunk()} 切换：
 * <ul>
 *   <li><b>方案 A（默认，preferChunk=true）</b>——插入自定义 {@code stEG} ancillary chunk
 *       到 IEND 之前。PNG 规范要求解码器忽略未知辅助 chunk，兼容性好且更隐蔽。</li>
 *   <li><b>方案 B（preferChunk=false）</b>——在 IEND 之后直接追加组合块，最简、
 *       与二进制尾部追加一致。</li>
 * </ul>
 *
 * <p>本适配器仅做"薄封装"：组合块由门面 {@code FileStegoCodec} 构建（含密码学参数），
 * 适配器把它作为不透明字节写入/读取，不重复实现密码学或 Payload 逻辑。
 *
 * @author ErgouTree
 * @since 2026/8/5
 */
public final class PngCarrierAdapter extends AbstractCarrierAdapter {

    /** PNG 文件签名（8 字节）。 */
    private static final byte[] PNG_SIGNATURE = {
            (byte) 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A
    };

    /** IEND chunk 类型标识。 */
    private static final byte[] IEND_TYPE = {0x49, 0x45, 0x4E, 0x44}; // "IEND"

    /** 自定义隐写 chunk 类型 "stEG"（辅助、私有、不可复制）。 */
    private static final byte[] STEG_TYPE = {0x73, 0x74, 0x45, 0x47}; // "stEG"

    /** chunk 头部（length 4B + type 4B）与 CRC（4B）的固定开销。 */
    private static final int CHUNK_OVERHEAD = 4 + 4 + 4;

    /** 流式复制分块大小（1 MiB）。 */
    private static final int STREAM_CHUNK_BYTES = 1 << 20;

    /** 元数据探测上限（≥ paranoid+stealth 组合下的最大 126 字节）。 */
    private static final int META_PROBE_LEN = 128;

    /** chunk 走查数量上限，防御病态文件。 */
    private static final int MAX_CHUNK_COUNT = 1_000_000;

    @Override
    public String id() {
        return "png";
    }

    @Override
    public String displayName() {
        return "PNG 图像";
    }

    @Override
    public List<String> supportedExtensions() {
        return List.of(".png");
    }

    @Override
    protected void validateCarrier(final Path carrierFile) throws CarrierException {
        super.validateCarrier(carrierFile);
        try {
            byte[] head = new byte[PNG_SIGNATURE.length];
            try (var in = Files.newInputStream(carrierFile)) {
                int read = in.readNBytes(head, 0, head.length);
                if (read != head.length || !Arrays.equals(head, PNG_SIGNATURE)) {
                    throw new CarrierException("不是有效的 PNG 文件（签名不匹配）: " + carrierFile);
                }
            }
        } catch (IOException e) {
            throw new CarrierException("读取 PNG 文件失败: " + e.getMessage(), e);
        }
    }

    @Override
    protected void doEmbed(final Path carrier, final byte[] payload, final byte[] meta,
                           final Path output, final byte[] password,
                           final EmbedOptions options) throws CarrierException {
        // payload 参数此处为门面组合好的 [CarrierMetadata + Payload] 不透明块
        byte[] combined = payload;
        try {
            byte[] pngBytes = Files.readAllBytes(carrier);
            int iendStart = locateIendStart(pngBytes);

            if (options.preferChunk()) {
                embedAsChunk(pngBytes, iendStart, combined, output);
            } else {
                embedAsTrailer(pngBytes, combined, output);
            }
        } catch (IOException e) {
            throw new CarrierException("PNG 嵌入失败: " + e.getMessage(), e);
        }
    }

    @Override
    protected CarrierMetadata doExtract(final Path stegoFile, final byte[] password)
            throws CarrierException {
        byte[] combined = readCombined(stegoFile);
        return parseMetadata(combined);
    }

    @Override
    protected byte[] readPayload(final Path stegoFile, final CarrierMetadata meta)
            throws CarrierException {
        byte[] combined = readCombined(stegoFile);
        int metaLen = CarrierMetadata.totalSize(meta.isParanoid(), meta.isStealth());
        if (combined.length < metaLen) {
            throw new CarrierException("PNG 隐写数据不完整：组合块短于元数据长度");
        }
        // 按 meta.payloadSize() 精确截断，防止 obfuscateSize 追加的 padding 混入
        long payloadSize = meta.payloadSize();
        int end = Math.min(combined.length, (int) Math.min(Integer.MAX_VALUE,
                metaLen + payloadSize));
        return Arrays.copyOfRange(combined, metaLen, end);
    }

    @Override
    public boolean detect(final Path file) {
        try (FileChannel ch = FileChannel.open(file, StandardOpenOption.READ)) {
            long fileSize = ch.size();
            if (fileSize < PNG_SIGNATURE.length) {
                return false;
            }
            ByteBuffer sigBuf = readAt(ch, 0, PNG_SIGNATURE.length);
            byte[] sig = new byte[PNG_SIGNATURE.length];
            sigBuf.get(sig);
            if (!Arrays.equals(sig, PNG_SIGNATURE)) {
                return false;
            }
            // 方案 A：存在 stEG chunk
            if (findStegChunkRange(ch, fileSize) != null) {
                return true;
            }
            // 方案 B：IEND 之后存在以 EGFS 魔数开头的追加数据
            long iendStart = locateIendStart(ch, fileSize);
            long trailerStart = iendStart + CHUNK_OVERHEAD; // IEND: len(0)+type+crc
            if (trailerStart + CarrierMetadata.MAGIC_LEN <= fileSize) {
                ByteBuffer magic = readAt(ch, trailerStart, CarrierMetadata.MAGIC_LEN);
                byte[] magicBytes = new byte[CarrierMetadata.MAGIC_LEN];
                magic.get(magicBytes);
                return CarrierMetadata.startsWithMagic(magicBytes);
            }
            return false;
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
     * 流式嵌入：按 {@code preferChunk} 选择方案 A（stEG chunk，流式计算 CRC）
     * 或方案 B（IEND 后追加），不将 Payload 全量读入内存。
     *
     * @param carrierFile 原始载体文件路径
     * @param meta        序列化后的 CarrierMetadata 字节数组
     * @param payloadFile STEG-V2 Payload 文件路径
     * @param output      输出文件路径
     * @param password    密码（PNG 方案不使用）
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
     * 流式嵌入（带进度回调）：按 {@code preferChunk} 选择方案 A（stEG chunk）或
     * 方案 B（IEND 后追加），并按已复制字节数占载体与 Payload 总字节数的比例
     * 逐块回调进度。
     *
     * @param carrierFile 原始载体文件路径
     * @param meta        序列化后的 CarrierMetadata 字节数组
     * @param payloadFile STEG-V2 Payload 文件路径
     * @param output      输出文件路径
     * @param password    密码（PNG 方案不使用）
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
        try {
            long carrierSize = Files.size(carrierFile);
            if (options.preferChunk()) {
                long iendStart;
                try (FileChannel ch = FileChannel.open(carrierFile, StandardOpenOption.READ)) {
                    iendStart = locateIendStart(ch, carrierSize);
                }
                embedAsChunkFromFile(carrierFile, iendStart, meta, payloadFile, output,
                        carrierSize, listener);
            } else {
                embedAsTrailerFromFile(carrierFile, meta, payloadFile, output, listener);
            }
            if (listener != null) {
                listener.onProgress(1.0);
            }
        } catch (CarrierException e) {
            throw e;
        } catch (IOException e) {
            throw new CarrierException("PNG 嵌入失败: " + e.getMessage(), e);
        }
    }

    /**
     * 流式提取：定位 stEG chunk（方案 A）或 IEND 尾部（方案 B），定点读取元数据，
     * 再按 {@code meta.payloadSize()} 精确流式拷贝 Payload 到文件。
     *
     * @param stegoFile  隐写载体文件
     * @param password   密码（PNG 方案不使用）
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
     * 流式提取（带进度回调）：定位 stEG chunk（方案 A）或 IEND 尾部（方案 B），
     * 定点读取元数据，再按 {@code meta.payloadSize()} 精确流式拷贝 Payload 到
     * 文件，并按已拷贝字节数逐块回调进度。
     *
     * @param stegoFile  隐写载体文件
     * @param password   密码（PNG 方案不使用）
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
        try (FileChannel ch = FileChannel.open(stegoFile, StandardOpenOption.READ)) {
            long fileSize = ch.size();
            if (fileSize < PNG_SIGNATURE.length) {
                throw new CarrierException("不是有效的 PNG 文件（签名不匹配）");
            }
            ByteBuffer sigBuf = readAt(ch, 0, PNG_SIGNATURE.length);
            byte[] sig = new byte[PNG_SIGNATURE.length];
            sigBuf.get(sig);
            if (!Arrays.equals(sig, PNG_SIGNATURE)) {
                throw new CarrierException("不是有效的 PNG 文件（签名不匹配）");
            }
            // 方案 A：stEG chunk；回退方案 B：IEND 之后追加
            long dataStart;
            long dataLen;
            long[] stegData = findStegChunkRange(ch, fileSize);
            if (stegData != null) {
                dataStart = stegData[0];
                dataLen = stegData[1];
            } else {
                long iendStart = locateIendStart(ch, fileSize);
                dataStart = iendStart + CHUNK_OVERHEAD;
                dataLen = fileSize - dataStart;
                if (dataLen < CarrierMetadata.MAGIC_LEN) {
                    throw new CarrierException("PNG 中未找到隐写数据");
                }
            }
            // 定点读取并解析元数据（最多 126 字节）
            int metaProbe = (int) Math.min(META_PROBE_LEN, dataLen);
            ByteBuffer metaRaw = readAt(ch, dataStart, metaProbe);
            byte[] metaBytes = new byte[metaProbe];
            metaRaw.get(metaBytes);
            if (!CarrierMetadata.startsWithMagic(metaBytes)) {
                throw new CarrierException("PNG 隐写数据不是有效的隐写载荷");
            }
            CarrierMetadata meta = CarrierMetadata.fromBytes(metaBytes);
            int metaLen = CarrierMetadata.totalSize(meta.isParanoid(), meta.isStealth());
            long payloadStart = dataStart + metaLen;
            long payloadSize = meta.payloadSize();
            if (payloadSize < 0 || metaLen + payloadSize > dataLen) {
                throw new CarrierException("PNG 隐写数据不完整：Payload 超出范围");
            }
            try (OutputStream out = Files.newOutputStream(payloadOut,
                    StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING)) {
                copyRange(ch, payloadStart, payloadSize, out, listener);
            }
            return meta;
        } catch (CarrierException e) {
            throw e;
        } catch (IOException e) {
            throw new CarrierException("读取 PNG 隐写数据失败: " + e.getMessage(), e);
        }
    }

    /**
     * 只读预检：定点读取并解析元数据（不读取 Payload）。
     *
     * @param stegoFile 隐写载体文件
     * @param password  密码（PNG 方案不使用）
     * @return 解析后的载体元数据
     * @throws CarrierException 定位或解析失败
     */
    @Override
    public CarrierMetadata readMetadataOnly(final Path stegoFile, final byte[] password)
            throws CarrierException {
        try (FileChannel ch = FileChannel.open(stegoFile, StandardOpenOption.READ)) {
            long fileSize = ch.size();
            if (fileSize < PNG_SIGNATURE.length) {
                throw new CarrierException("不是有效的 PNG 文件（签名不匹配）");
            }
            ByteBuffer sigBuf = readAt(ch, 0, PNG_SIGNATURE.length);
            byte[] sig = new byte[PNG_SIGNATURE.length];
            sigBuf.get(sig);
            if (!Arrays.equals(sig, PNG_SIGNATURE)) {
                throw new CarrierException("不是有效的 PNG 文件（签名不匹配）");
            }
            long dataStart;
            long dataLen;
            long[] stegData = findStegChunkRange(ch, fileSize);
            if (stegData != null) {
                dataStart = stegData[0];
                dataLen = stegData[1];
            } else {
                long iendStart = locateIendStart(ch, fileSize);
                dataStart = iendStart + CHUNK_OVERHEAD;
                dataLen = fileSize - dataStart;
                if (dataLen < CarrierMetadata.MAGIC_LEN) {
                    throw new CarrierException("PNG 中未找到隐写数据");
                }
            }
            int metaProbe = (int) Math.min(META_PROBE_LEN, dataLen);
            ByteBuffer metaRaw = readAt(ch, dataStart, metaProbe);
            byte[] metaBytes = new byte[metaProbe];
            metaRaw.get(metaBytes);
            if (!CarrierMetadata.startsWithMagic(metaBytes)) {
                throw new CarrierException("PNG 隐写数据不是有效的隐写载荷");
            }
            return CarrierMetadata.fromBytes(metaBytes);
        } catch (CarrierException e) {
            throw e;
        } catch (IOException e) {
            throw new CarrierException("读取 PNG 元数据失败: " + e.getMessage(), e);
        }
    }

    /**
     * 只读预检：定点读取 Payload 头前若干字节（不读取完整 Payload）。
     *
     * @param stegoFile 隐写载体文件
     * @param meta      已解析的载体元数据（含 payloadSize）
     * @param maxLen    最多读取的字节数
     * @return Payload 头前 {@code min(maxLen, payloadSize)} 字节
     * @throws CarrierException 定位或读取失败
     */
    @Override
    public byte[] readPayloadPrefix(final Path stegoFile, final CarrierMetadata meta,
                                    final int maxLen) throws CarrierException {
        try (FileChannel ch = FileChannel.open(stegoFile, StandardOpenOption.READ)) {
            long fileSize = ch.size();
            long dataStart;
            long dataLen;
            long[] stegData = findStegChunkRange(ch, fileSize);
            if (stegData != null) {
                dataStart = stegData[0];
                dataLen = stegData[1];
            } else {
                long iendStart = locateIendStart(ch, fileSize);
                dataStart = iendStart + CHUNK_OVERHEAD;
                dataLen = fileSize - dataStart;
            }
            int metaLen = CarrierMetadata.totalSize(meta.isParanoid(), meta.isStealth());
            long payloadStart = dataStart + metaLen;
            long payloadSize = meta.payloadSize();
            if (payloadSize < 0 || metaLen + payloadSize > dataLen) {
                throw new CarrierException("PNG 隐写数据不完整：Payload 超出范围");
            }
            int n = (int) Math.min(maxLen, payloadSize);
            ByteBuffer buf = readAt(ch, payloadStart, n);
            byte[] out = new byte[n];
            buf.get(out);
            return out;
        } catch (CarrierException e) {
            throw e;
        } catch (IOException e) {
            throw new CarrierException("读取 PNG Payload 前缀失败: " + e.getMessage(), e);
        }
    }

    // ---- 流式 PNG 结构走查与写入 ----

    /**
     * 流式方案 A 嵌入：复制 IEND 前内容，插入 stEG chunk（head + 分块 data + 流式 CRC 尾），再复制 IEND 及其后内容。
     *
     * @param carrier     原始载体文件
     * @param iendStart   IEND chunk 起始偏移
     * @param meta        序列化后的 CarrierMetadata 字节数组
     * @param payloadFile STEG-V2 Payload 文件路径
     * @param output      输出文件路径
     * @param carrierSize 载体文件大小
     * @param listener    进度监听器（可为 null），按已复制字节数回调
     * @throws IOException      读写失败
     * @throws CarrierException chunk 数据过长
     */
    private void embedAsChunkFromFile(final Path carrier, final long iendStart,
                                      final byte[] meta, final Path payloadFile,
                                      final Path output, final long carrierSize,
                                      final ProgressListener listener)
            throws IOException, CarrierException {
        long payloadSize = Files.size(payloadFile);
        long dataLen = meta.length + payloadSize;
        if (dataLen > 0x7FFFFFFFL) {
            throw new CarrierException("PNG stEG chunk 超过 31-bit 长度上限");
        }
        long total = carrierSize + payloadSize;
        try (InputStream in = Files.newInputStream(carrier);
             OutputStream out = Files.newOutputStream(output,
                     StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING)) {
            // 1. 复制 IEND 之前的内容
            long done = copyStream(in, out, iendStart, listener, 0L, total);
            // 2. chunk 头：length + type
            ByteBuffer head = ByteBuffer.allocate(8).order(ByteOrder.BIG_ENDIAN);
            head.putInt((int) dataLen);
            head.put(STEG_TYPE);
            out.write(head.array());
            // 3. data（meta + payload 文件），同时累积 CRC（覆盖 type + data）
            CRC32 crc = new CRC32();
            crc.update(STEG_TYPE);
            out.write(meta);
            crc.update(meta);
            byte[] buf = new byte[STREAM_CHUNK_BYTES];
            try (InputStream pin = Files.newInputStream(payloadFile)) {
                int n;
                while ((n = pin.read(buf)) > 0) {
                    out.write(buf, 0, n);
                    crc.update(buf, 0, n);
                    done += n;
                    if (listener != null) {
                        listener.onProgress((double) done / Math.max(total, 1L));
                    }
                }
            }
            // 4. CRC 尾
            ByteBuffer crcBuf = ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN);
            crcBuf.putInt((int) crc.getValue());
            out.write(crcBuf.array());
            // 5. 复制 IEND 及其后内容
            copyStream(in, out, carrierSize - iendStart, listener, done, total);
        }
    }

    /**
     * 流式方案 B 嵌入：复制载体后依次追加元数据与 Payload 文件。
     *
     * @param carrier     原始载体文件
     * @param meta        序列化后的 CarrierMetadata 字节数组
     * @param payloadFile STEG-V2 Payload 文件路径
     * @param output      输出文件路径
     * @param listener    进度监听器（可为 null），按已复制字节数回调
     * @throws IOException 读写失败
     */
    private void embedAsTrailerFromFile(final Path carrier, final byte[] meta,
                                        final Path payloadFile, final Path output,
                                        final ProgressListener listener)
            throws IOException {
        long carrierSize = Files.size(carrier);
        long payloadSize = Files.size(payloadFile);
        long total = carrierSize + payloadSize;
        try (OutputStream out = Files.newOutputStream(output,
                StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING)) {
            try (InputStream cin = Files.newInputStream(carrier)) {
                copyStream(cin, out, carrierSize, listener, 0L, total);
            }
            out.write(meta);
            byte[] buf = new byte[STREAM_CHUNK_BYTES];
            long done = carrierSize;
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
        }
    }

    /**
     * 流式定位 IEND chunk 起始偏移（定点读取 chunk 头并跳转，不读入整文件）。
     *
     * @param ch       文件通道
     * @param fileSize 文件大小
     * @return IEND chunk 起始偏移
     * @throws IOException      读取失败
     * @throws CarrierException 不是有效 PNG 或缺少 IEND
     */
    private static long locateIendStart(final FileChannel ch, final long fileSize)
            throws IOException, CarrierException {
        if (fileSize < PNG_SIGNATURE.length) {
            throw new CarrierException("不是有效的 PNG 文件或缺少 IEND chunk");
        }
        ByteBuffer sigBuf = readAt(ch, 0, PNG_SIGNATURE.length);
        byte[] sig = new byte[PNG_SIGNATURE.length];
        sigBuf.get(sig);
        if (!Arrays.equals(sig, PNG_SIGNATURE)) {
            throw new CarrierException("不是有效的 PNG 文件或缺少 IEND chunk");
        }
        long pos = PNG_SIGNATURE.length;
        int chunkCount = 0;
        while (pos + 8 <= fileSize) {
            if (++chunkCount > MAX_CHUNK_COUNT) {
                throw new CarrierException("PNG chunk 数量异常（可能损坏）");
            }
            ByteBuffer head = readAt(ch, pos, 8);
            long len = Integer.toUnsignedLong(head.getInt(0));
            byte[] type = new byte[4];
            head.get(4, type);
            if (Arrays.equals(type, IEND_TYPE)) {
                return pos;
            }
            long next = pos + 8 + len + 4;
            if (next <= pos || next > fileSize) {
                throw new CarrierException("不是有效的 PNG 文件或缺少 IEND chunk");
            }
            pos = next;
        }
        throw new CarrierException("不是有效的 PNG 文件或缺少 IEND chunk");
    }

    /**
     * 流式查找 stEG chunk 的数据区间 [dataStart, dataLen]，未找到返回 null
     * （方案 B 的 IEND 终止即返回）。
     *
     * @param ch       文件通道
     * @param fileSize 文件大小
     * @return 长度为 2 的数组 [dataStart, dataLen]；未找到返回 null
     * @throws IOException      读取失败
     * @throws CarrierException PNG 结构损坏
     */
    private static long[] findStegChunkRange(final FileChannel ch, final long fileSize)
            throws IOException, CarrierException {
        long pos = PNG_SIGNATURE.length;
        int chunkCount = 0;
        while (pos + 8 <= fileSize) {
            if (++chunkCount > MAX_CHUNK_COUNT) {
                throw new CarrierException("PNG chunk 数量异常（可能损坏）");
            }
            ByteBuffer head = readAt(ch, pos, 8);
            long len = Integer.toUnsignedLong(head.getInt(0));
            byte[] type = new byte[4];
            head.get(4, type);
            long dataStart = pos + 8;
            if (Arrays.equals(type, STEG_TYPE)) {
                if (dataStart + len + 4 > fileSize) {
                    throw new CarrierException("PNG stEG chunk 损坏");
                }
                return new long[]{dataStart, len};
            }
            if (Arrays.equals(type, IEND_TYPE)) {
                return null;
            }
            long next = dataStart + len + 4;
            if (next <= pos || next > fileSize) {
                throw new CarrierException("PNG chunk 结构损坏");
            }
            pos = next;
        }
        return null;
    }

    /**
     * 从输入流精确拷贝指定字节数到输出流，并按累计已拷贝字节数回调进度。
     *
     * @param in       输入流
     * @param out      输出流
     * @param length   待拷贝字节数
     * @param listener 进度监听器（可为 null）
     * @param done     本段拷贝开始前已完成的字节数
     * @param total    进度分母（整体总字节数）
     * @return 本段拷贝结束后的累计完成字节数
     * @throws IOException 读写失败
     */
    private static long copyStream(final InputStream in, final OutputStream out,
                                   final long length, final ProgressListener listener,
                                   final long done, final long total) throws IOException {
        byte[] buf = new byte[STREAM_CHUNK_BYTES];
        long remaining = length;
        long copied = done;
        while (remaining > 0) {
            int n = in.read(buf, 0, (int) Math.min(remaining, buf.length));
            if (n < 0) {
                throw new IOException("PNG 载体意外结束");
            }
            out.write(buf, 0, n);
            remaining -= n;
            copied += n;
            if (listener != null) {
                listener.onProgress((double) copied / Math.max(total, 1L));
            }
        }
        return copied;
    }

    /**
     * 从通道定点分块拷贝指定字节数到输出流，并按已拷贝字节数回调进度。
     *
     * @param ch       文件通道
     * @param pos      起始偏移
     * @param length   待拷贝字节数
     * @param out      输出流
     * @param listener 进度监听器（可为 null）
     * @throws IOException 读写失败
     */
    private static void copyRange(final FileChannel ch, final long pos, final long length,
                                  final OutputStream out, final ProgressListener listener)
            throws IOException {
        ByteBuffer buf = ByteBuffer.allocate(STREAM_CHUNK_BYTES);
        byte[] tmp = buf.array();
        long remaining = length;
        long cur = pos;
        while (remaining > 0) {
            int want = (int) Math.min(remaining, tmp.length);
            buf.clear();
            buf.limit(want);
            int read = 0;
            while (read < want) {
                int n = ch.read(buf, cur + read);
                if (n < 0) {
                    throw new IOException("读取 PNG 时遇到意外文件结束，位置 " + cur);
                }
                read += n;
            }
            out.write(tmp, 0, want);
            cur += want;
            remaining -= want;
            if (listener != null) {
                listener.onProgress((double) (length - remaining) / Math.max(length, 1L));
            }
        }
        if (listener != null && length <= 0) {
            listener.onProgress(1.0);
        }
    }

    /**
     * 从通道指定偏移读取固定长度。
     *
     * @param ch  文件通道
     * @param pos 偏移
     * @param len 长度
     * @return 已 flip 的缓冲区
     * @throws IOException 读取失败或意外 EOF
     */
    private static ByteBuffer readAt(final FileChannel ch, final long pos, final int len)
            throws IOException {
        ByteBuffer bb = ByteBuffer.allocate(len);
        int read = 0;
        while (read < len) {
            int n = ch.read(bb, pos + read);
            if (n < 0) {
                throw new IOException("读取 PNG 时遇到意外文件结束，位置 " + pos);
            }
            read += n;
        }
        bb.flip();
        return bb;
    }

    // ---- 方案 A：stEG chunk ----

    /**
     * 将组合块作为 stEG ancillary chunk 插入到 IEND 之前并写出。
     *
     * @param pngBytes  原始 PNG 字节
     * @param iendStart IEND chunk 的起始偏移（length 字段）
     * @param combined  待嵌入的组合块
     * @param output    输出文件路径
     * @throws IOException 写出失败
     */
    private void embedAsChunk(final byte[] pngBytes, final int iendStart,
                              final byte[] combined, final Path output) throws IOException {
        byte[] chunk = buildChunk(STEG_TYPE, combined);
        try (OutputStream out = Files.newOutputStream(output,
                StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING)) {
            // IEND 之前的全部内容
            out.write(pngBytes, 0, iendStart);
            // 插入 stEG chunk
            out.write(chunk);
            // 原 IEND chunk 到文件结尾
            out.write(pngBytes, iendStart, pngBytes.length - iendStart);
        }
    }

    // ---- 方案 B：IEND 之后追加 ----

    /**
     * 在 IEND 之后追加组合块并写出。
     *
     * @param pngBytes 原始 PNG 字节
     * @param combined 待嵌入的组合块
     * @param output   输出文件路径
     * @throws IOException 写出失败
     */
    private void embedAsTrailer(final byte[] pngBytes, final byte[] combined,
                                final Path output) throws IOException {
        try (OutputStream out = Files.newOutputStream(output,
                StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING)) {
            out.write(pngBytes);
            out.write(combined);
        }
    }

    // ---- 读取组合块（自动兼容两种方案） ----

    /**
     * 从隐写 PNG 中读取组合块（优先 stEG chunk，回退 IEND 追加）。
     *
     * @param stegoFile 隐写 PNG 文件
     * @return 组合块字节
     * @throws CarrierException 未找到隐写数据或读取失败
     */
    private byte[] readCombined(final Path stegoFile) throws CarrierException {
        try {
            byte[] pngBytes = Files.readAllBytes(stegoFile);
            // 方案 A：stEG chunk
            byte[] chunkData = findStegChunkData(pngBytes);
            if (chunkData != null) {
                return chunkData;
            }
            // 方案 B：IEND 之后
            int iendStart = locateIendStart(pngBytes);
            int trailerStart = iendStart + CHUNK_OVERHEAD;
            if (trailerStart >= pngBytes.length) {
                throw new CarrierException("PNG 中未找到隐写数据");
            }
            byte[] tail = Arrays.copyOfRange(pngBytes, trailerStart, pngBytes.length);
            if (!CarrierMetadata.startsWithMagic(tail)) {
                throw new CarrierException("PNG 尾部数据不是有效的隐写载荷");
            }
            return tail;
        } catch (IOException e) {
            throw new CarrierException("读取 PNG 隐写数据失败: " + e.getMessage(), e);
        }
    }

    /**
     * 解析组合块头部的 {@link CarrierMetadata}。
     *
     * @param combined 组合块字节
     * @return 解析后的载体元数据
     * @throws CarrierException 解析失败
     */
    private CarrierMetadata parseMetadata(final byte[] combined) throws CarrierException {
        return CarrierMetadata.fromBytes(combined);
    }

    // ---- PNG 结构解析辅助 ----

    /**
     * 校验 PNG 签名。
     *
     * @param data PNG 字节
     * @return true 如果以 PNG 签名开头
     */
    private static boolean hasPngSignature(final byte[] data) {
        if (data.length < PNG_SIGNATURE.length) {
            return false;
        }
        for (int i = 0; i < PNG_SIGNATURE.length; i++) {
            if (data[i] != PNG_SIGNATURE[i]) {
                return false;
            }
        }
        return true;
    }

    /**
     * 定位 IEND chunk 的起始偏移（length 字段位置）。
     *
     * @param pngBytes PNG 字节
     * @return IEND chunk 起始偏移
     * @throws CarrierException 不是有效 PNG 或未找到 IEND
     */
    private static int locateIendStart(final byte[] pngBytes) throws CarrierException {
        int pos = tryLocateIendStart(pngBytes);
        if (pos < 0) {
            throw new CarrierException("不是有效的 PNG 文件或缺少 IEND chunk");
        }
        return pos;
    }

    /**
     * 尝试定位 IEND chunk 起始偏移，失败返回 -1（不抛异常，供 detect 使用）。
     *
     * @param pngBytes PNG 字节
     * @return IEND chunk 起始偏移，未找到返回 -1
     */
    private static int tryLocateIendStart(final byte[] pngBytes) {
        if (!hasPngSignature(pngBytes)) {
            return -1;
        }
        int pos = PNG_SIGNATURE.length;
        // 逐 chunk 遍历：length(4) + type(4) + data(length) + crc(4)
        while (pos + 8 <= pngBytes.length) {
            long len = readUInt32(pngBytes, pos);
            int typeStart = pos + 4;
            if (typeStart + 4 > pngBytes.length) {
                return -1;
            }
            boolean isIend = matchType(pngBytes, typeStart, IEND_TYPE);
            if (isIend) {
                return pos;
            }
            long next = (long) pos + 8 + len + 4;
            if (next <= pos || next > pngBytes.length) {
                return -1;
            }
            pos = (int) next;
        }
        return -1;
    }

    /**
     * 查找 stEG chunk 的数据部分。
     *
     * @param pngBytes PNG 字节
     * @return stEG chunk 的 data 字节，未找到返回 null
     */
    private static byte[] findStegChunkData(final byte[] pngBytes) {
        if (!hasPngSignature(pngBytes)) {
            return null;
        }
        int pos = PNG_SIGNATURE.length;
        while (pos + 8 <= pngBytes.length) {
            long len = readUInt32(pngBytes, pos);
            int typeStart = pos + 4;
            int dataStart = pos + 8;
            if (dataStart + len + 4 > pngBytes.length) {
                return null;
            }
            if (matchType(pngBytes, typeStart, STEG_TYPE)) {
                return Arrays.copyOfRange(pngBytes, dataStart, (int) (dataStart + len));
            }
            if (matchType(pngBytes, typeStart, IEND_TYPE)) {
                return null;
            }
            pos = (int) (dataStart + len + 4);
        }
        return null;
    }

    /**
     * 构建一个合法的 PNG chunk：length(4) + type(4) + data + CRC(4)。
     *
     * @param type chunk 类型（4 字节）
     * @param data chunk 数据
     * @return 完整的 chunk 字节
     */
    private static byte[] buildChunk(final byte[] type, final byte[] data) {
        ByteBuffer bb = ByteBuffer.allocate(CHUNK_OVERHEAD + data.length)
                .order(ByteOrder.BIG_ENDIAN);
        bb.putInt(data.length);
        bb.put(type);
        bb.put(data);
        // CRC 覆盖 type + data
        CRC32 crc = new CRC32();
        crc.update(type);
        crc.update(data);
        bb.putInt((int) crc.getValue());
        return bb.array();
    }

    /**
     * 读取大端 uint32。
     */
    private static long readUInt32(final byte[] data, final int offset) {
        return ((long) (data[offset] & 0xFF) << 24)
                | ((data[offset + 1] & 0xFF) << 16)
                | ((data[offset + 2] & 0xFF) << 8)
                | (data[offset + 3] & 0xFF);
    }

    /**
     * 判断给定偏移处 4 字节是否匹配目标 chunk 类型。
     */
    private static boolean matchType(final byte[] data, final int offset, final byte[] type) {
        for (int i = 0; i < 4; i++) {
            if (data[offset + i] != type[i]) {
                return false;
            }
        }
        return true;
    }
}
