package hbnu.project.ergoutreecrypt.filestego.carrier.flac;

import hbnu.project.ergoutreecrypt.filestego.api.CarrierException;
import hbnu.project.ergoutreecrypt.filestego.api.EmbedOptions;
import hbnu.project.ergoutreecrypt.filestego.carrier.spi.AbstractCarrierAdapter;
import hbnu.project.ergoutreecrypt.filestego.carrier.spi.CarrierMetadata;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * FLAC 载体适配器，不受限方案。
 *
 * <p>在 metadata block 序列中插入 {@code APPLICATION} 块（type=2），
 * Application ID 为 {@code EGTC}，块体为门面组合好的
 * {@code [CarrierMetadata + STEG-V2 Payload]}。
 *
 * <p>插入策略保证 {@code STREAMINFO} 始终为第一个 metadata block：
 * <ul>
 *   <li>仅有一个 LAST 块（通常即 STREAMINFO）时：清除其 LAST 位，
 *       在其后追加 {@code APPLICATION(LAST=true)}</li>
 *   <li>多个 metadata 块时：在最后一个块之前插入
 *       {@code APPLICATION(LAST=false)}，原 LAST 块保持 {@code LAST=true}</li>
 * </ul>
 *
 * <p>FLAC 解码器会忽略未知 Application ID 的 APPLICATION 块，音频帧区字节不变。
 *
 * @author ErgouTree
 * @since 2026/8/11
 */
public final class FlacCarrierAdapter extends AbstractCarrierAdapter {

    /** FLAC 文件魔数 "fLaC"。 */
    private static final byte[] FLAC_MAGIC = {0x66, 0x4C, 0x61, 0x43};

    /** APPLICATION metadata block 类型。 */
    private static final int BLOCK_TYPE_APPLICATION = 2;

    /** STREAMINFO metadata block 类型（必须为第一个块）。 */
    private static final int BLOCK_TYPE_STREAMINFO = 0;

    /** 工具专属 Application ID "EGTC"。 */
    private static final byte[] APP_ID = "EGTC".getBytes(StandardCharsets.US_ASCII);

    /** metadata block 头长度（LAST+TYPE+SIZE）。 */
    private static final int BLOCK_HEADER_LEN = 4;

    /** APPLICATION 块体的最大字节数（24-bit 长度上限减去 Application ID 的 4 字节）。 */
    private static final int MAX_APP_BLOCK_BODY = 0x00FFFFFF - 4;

    /** APPLICATION 块的最大字节数（完整块体，含 Application ID）。 */
    private static final int MAX_BLOCK_DATA = 0x00FFFFFF;

    @Override
    public String id() {
        return "flac";
    }

    @Override
    public String displayName() {
        return "FLAC 音频";
    }

    @Override
    public List<String> supportedExtensions() {
        return List.of(".flac");
    }

    @Override
    public long capacity(final Path carrierFile) {
        // FLAC metadata block 有 24-bit 长度字段，单个 APPLICATION 块体最大约 16 MB
        return MAX_APP_BLOCK_BODY;
    }

    @Override
    protected void validateCarrier(final Path carrierFile) throws CarrierException {
        super.validateCarrier(carrierFile);
        try {
            byte[] head = new byte[FLAC_MAGIC.length];
            try (var in = Files.newInputStream(carrierFile)) {
                int read = in.readNBytes(head, 0, head.length);
                if (read != head.length || !regionMatches(head, 0, FLAC_MAGIC)) {
                    throw new CarrierException("不是有效的 FLAC 文件（缺少 fLaC 签名）: "
                            + carrierFile);
                }
            }
        } catch (IOException e) {
            throw new CarrierException("读取 FLAC 文件失败: " + e.getMessage(), e);
        }
    }

    @Override
    protected void doEmbed(final Path carrier, final byte[] payload, final byte[] meta,
                           final Path output, final byte[] password,
                           final EmbedOptions options) throws CarrierException {
        // payload 参数此处为门面组合好的 [CarrierMetadata + Payload] 不透明块
        byte[] combined = payload;
        try {
            byte[] flacBytes = Files.readAllBytes(carrier);
            if (flacBytes.length < FLAC_MAGIC.length + BLOCK_HEADER_LEN
                    || !regionMatches(flacBytes, 0, FLAC_MAGIC)) {
                throw new CarrierException("不是有效的 FLAC 文件");
            }

            ParsedFlac parsed = parseMetadata(flacBytes);
            if (parsed.blocks.isEmpty()) {
                throw new CarrierException("FLAC 缺少 metadata block");
            }
            MetadataBlock first = parsed.blocks.get(0);
            if (first.type != BLOCK_TYPE_STREAMINFO) {
                throw new CarrierException("FLAC 首个 metadata block 必须是 STREAMINFO");
            }

            byte[] appBody = concat(APP_ID, combined);
            byte[] appBlock = encodeBlock(false, BLOCK_TYPE_APPLICATION, appBody);

            try (OutputStream out = Files.newOutputStream(output,
                    StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING)) {
                out.write(FLAC_MAGIC);

                if (parsed.blocks.size() == 1) {
                    // 仅 STREAMINFO：清除 LAST，追加 APPLICATION 作为新 LAST
                    MetadataBlock streamInfo = parsed.blocks.get(0);
                    out.write(encodeBlock(false, streamInfo.type, streamInfo.data));
                    out.write(encodeBlock(true, BLOCK_TYPE_APPLICATION, appBody));
                } else {
                    // 在最后一个块之前插入 APPLICATION(LAST=false)
                    int lastIdx = parsed.blocks.size() - 1;
                    for (int i = 0; i < lastIdx; i++) {
                        MetadataBlock b = parsed.blocks.get(i);
                        out.write(encodeBlock(false, b.type, b.data));
                    }
                    out.write(appBlock);
                    MetadataBlock last = parsed.blocks.get(lastIdx);
                    out.write(encodeBlock(true, last.type, last.data));
                }

                // 音频帧原样拷贝
                if (parsed.framesOffset < flacBytes.length) {
                    out.write(flacBytes, parsed.framesOffset,
                            flacBytes.length - parsed.framesOffset);
                }
            }
        } catch (IOException e) {
            throw new CarrierException("FLAC 嵌入失败: " + e.getMessage(), e);
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
            throw new CarrierException("FLAC 隐写数据不完整：组合块短于元数据长度");
        }
        return Arrays.copyOfRange(combined, metaLen, combined.length);
    }

    @Override
    public boolean detect(final Path file) {
        try {
            byte[] bytes = Files.readAllBytes(file);
            byte[] data = findStegCombined(bytes);
            return data != null && CarrierMetadata.startsWithMagic(data);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * 从隐写 FLAC 中读取 APPLICATION 块内的组合块数据。
     *
     * @param stegoFile 隐写 FLAC 文件
     * @return 组合块字节
     * @throws CarrierException 未找到隐写 APPLICATION 或读取失败
     */
    private byte[] readCombined(final Path stegoFile) throws CarrierException {
        try {
            byte[] bytes = Files.readAllBytes(stegoFile);
            byte[] data = findStegCombined(bytes);
            if (data == null) {
                throw new CarrierException("FLAC 中未找到隐写数据（APPLICATION/EGTC）");
            }
            if (!CarrierMetadata.startsWithMagic(data)) {
                throw new CarrierException("FLAC APPLICATION 块不是有效的隐写载荷");
            }
            return data;
        } catch (IOException e) {
            throw new CarrierException("读取 FLAC 隐写数据失败: " + e.getMessage(), e);
        }
    }

    /**
     * 遍历 metadata block，返回首个 Application ID 为 EGTC 的组合块。
     *
     * @param bytes FLAC 文件字节
     * @return 组合块（不含 Application ID），未找到返回 null
     */
    private static byte[] findStegCombined(final byte[] bytes) {
        if (bytes.length < FLAC_MAGIC.length + BLOCK_HEADER_LEN
                || !regionMatches(bytes, 0, FLAC_MAGIC)) {
            return null;
        }
        try {
            ParsedFlac parsed = parseMetadata(bytes);
            for (MetadataBlock block : parsed.blocks) {
                if (block.type != BLOCK_TYPE_APPLICATION) {
                    continue;
                }
                if (block.data.length < APP_ID.length + 4) {
                    continue;
                }
                if (!regionMatches(block.data, 0, APP_ID)) {
                    continue;
                }
                byte[] combined = Arrays.copyOfRange(block.data, APP_ID.length, block.data.length);
                if (CarrierMetadata.startsWithMagic(combined)) {
                    return combined;
                }
            }
        } catch (CarrierException e) {
            return null;
        }
        return null;
    }

    /**
     * 解析 FLAC metadata block 序列。
     *
     * @param bytes 完整 FLAC 文件字节
     * @return 解析结果（块列表 + 音频帧起始偏移）
     * @throws CarrierException 结构非法
     */
    private static ParsedFlac parseMetadata(final byte[] bytes) throws CarrierException {
        List<MetadataBlock> blocks = new ArrayList<>();
        int pos = FLAC_MAGIC.length;
        boolean sawLast = false;
        while (pos + BLOCK_HEADER_LEN <= bytes.length && !sawLast) {
            int header = ((bytes[pos] & 0xFF) << 24)
                    | ((bytes[pos + 1] & 0xFF) << 16)
                    | ((bytes[pos + 2] & 0xFF) << 8)
                    | (bytes[pos + 3] & 0xFF);
            boolean last = (header & 0x80000000) != 0;
            int type = (header >>> 24) & 0x7F;
            int size = header & 0x00FFFFFF;
            int dataStart = pos + BLOCK_HEADER_LEN;
            if (dataStart + size > bytes.length) {
                throw new CarrierException("FLAC metadata block 长度越界");
            }
            byte[] data = Arrays.copyOfRange(bytes, dataStart, dataStart + size);
            blocks.add(new MetadataBlock(last, type, data, pos));
            pos = dataStart + size;
            sawLast = last;
        }
        if (!sawLast && blocks.isEmpty()) {
            throw new CarrierException("FLAC 未解析到任何 metadata block");
        }
        if (!sawLast) {
            throw new CarrierException("FLAC metadata 序列缺少 LAST 标志");
        }
        return new ParsedFlac(blocks, pos);
    }

    /**
     * 编码单个 metadata block（header + body）。
     *
     * @param last 是否为最后一个 metadata block
     * @param type 块类型（0–127）
     * @param data 块体
     * @return 编码后的完整块字节
     * @throws CarrierException 块体过大
     */
    private static byte[] encodeBlock(final boolean last, final int type, final byte[] data)
            throws CarrierException {
        if (data.length > MAX_BLOCK_DATA) {
            throw new CarrierException(String.format(
                    "FLAC metadata block 超过 24-bit 长度上限"
                            + "（最大约 %.1f MB，当前数据约 %.1f MB）。"
                            + " 建议：切换为 ZIP 或 PNG 等无容量限制的载体格式。",
                    (double) MAX_BLOCK_DATA / (1024 * 1024),
                    (double) data.length / (1024 * 1024)));
        }
        byte[] out = new byte[BLOCK_HEADER_LEN + data.length];
        int header = ((last ? 0x80 : 0x00) | (type & 0x7F)) << 24;
        header |= (data.length & 0x00FFFFFF);
        out[0] = (byte) ((header >>> 24) & 0xFF);
        out[1] = (byte) ((header >>> 16) & 0xFF);
        out[2] = (byte) ((header >>> 8) & 0xFF);
        out[3] = (byte) (header & 0xFF);
        System.arraycopy(data, 0, out, BLOCK_HEADER_LEN, data.length);
        return out;
    }

    /**
     * 拼接两段字节。
     *
     * @param a 前段
     * @param b 后段
     * @return 拼接结果
     */
    private static byte[] concat(final byte[] a, final byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    /**
     * 判断给定偏移处是否匹配目标标识。
     *
     * @param data   源字节
     * @param offset 起始偏移
     * @param tag    目标标识
     * @return 是否匹配
     */
    private static boolean regionMatches(final byte[] data, final int offset, final byte[] tag) {
        if (offset < 0 || offset + tag.length > data.length) {
            return false;
        }
        for (int i = 0; i < tag.length; i++) {
            if (data[offset + i] != tag[i]) {
                return false;
            }
        }
        return true;
    }

    /**
     * 单个 metadata block 的解析结果。
     *
     * @param last         原 LAST 标志
     * @param type         块类型
     * @param data         块体
     * @param headerOffset 块头在文件中的偏移
     */
    private record MetadataBlock(boolean last, int type, byte[] data, int headerOffset) {
    }

    /**
     * FLAC metadata 解析结果。
     *
     * @param blocks       metadata 块列表（按文件顺序）
     * @param framesOffset 音频帧起始偏移
     */
    private record ParsedFlac(List<MetadataBlock> blocks, int framesOffset) {
    }
}
