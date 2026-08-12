package hbnu.project.ergoutreecrypt.filestego.carrier.png;

import hbnu.project.ergoutreecrypt.filestego.api.CarrierException;
import hbnu.project.ergoutreecrypt.filestego.api.EmbedOptions;
import hbnu.project.ergoutreecrypt.filestego.carrier.spi.AbstractCarrierAdapter;
import hbnu.project.ergoutreecrypt.filestego.carrier.spi.CarrierMetadata;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
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
        return Arrays.copyOfRange(combined, metaLen, combined.length);
    }

    @Override
    public boolean detect(final Path file) {
        try {
            byte[] pngBytes = Files.readAllBytes(file);
            if (pngBytes.length < PNG_SIGNATURE.length
                    || !hasPngSignature(pngBytes)) {
                return false;
            }
            // 方案 A：存在 stEG chunk
            if (findStegChunkData(pngBytes) != null) {
                return true;
            }
            // 方案 B：IEND 之后存在以 EGFS 魔数开头的追加数据
            int iendStart = tryLocateIendStart(pngBytes);
            if (iendStart >= 0) {
                int trailerStart = iendStart + CHUNK_OVERHEAD; // IEND: len(0)+type+crc
                if (trailerStart <= pngBytes.length) {
                    byte[] tail = Arrays.copyOfRange(pngBytes, trailerStart, pngBytes.length);
                    return CarrierMetadata.startsWithMagic(tail);
                }
            }
            return false;
        } catch (Exception e) {
            return false;
        }
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
