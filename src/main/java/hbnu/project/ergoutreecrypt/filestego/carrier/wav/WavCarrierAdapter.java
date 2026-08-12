package hbnu.project.ergoutreecrypt.filestego.carrier.wav;

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

/**
 * WAV 载体适配器（不受限方案）。
 *
 * <p>WAV 是 RIFF 容器，播放器会安全跳过不认识的 chunk。本适配器在文件末尾追加一个
 * 自定义 {@code STEG} chunk，chunk 数据即门面组合好的
 * {@code [CarrierMetadata + STEG-V2 Payload]}：
 * <pre>
 *   "RIFF" &lt;size&gt; "WAVE"   ← size 更新为包含 STEG chunk 的新总长
 *   fmt  chunk
 *   data chunk
 *   "STEG" &lt;chunkSize LE&gt; [combined] [pad if odd]
 * </pre>
 *
 * <p>RIFF 规范要求 chunk payload 为奇数长度时补 1 字节填充；填充字节不计入 chunk size，
 * 因此提取时按 size 精确切分即可正确还原，无边界歧义。
 *
 * @author ErgouTree
 * @since 2026/8/5
 */
public final class WavCarrierAdapter extends AbstractCarrierAdapter {

    /** "RIFF" 标识。 */
    private static final byte[] RIFF = {0x52, 0x49, 0x46, 0x46};

    /** "WAVE" 标识。 */
    private static final byte[] WAVE = {0x57, 0x41, 0x56, 0x45};

    /** 自定义隐写 chunk 标识 "STEG"。 */
    private static final byte[] STEG = {0x53, 0x54, 0x45, 0x47};

    /** RIFF 头部长度（"RIFF" + size4 + "WAVE"）。 */
    private static final int RIFF_HEADER_LEN = 12;

    /** RIFF size 字段偏移（紧跟 "RIFF" 之后）。 */
    private static final int RIFF_SIZE_OFFSET = 4;

    /** chunk 头部长度（id4 + size4）。 */
    private static final int CHUNK_HEADER_LEN = 8;

    @Override
    public String id() {
        return "wav";
    }

    @Override
    public String displayName() {
        return "WAV 音频";
    }

    @Override
    public List<String> supportedExtensions() {
        return List.of(".wav");
    }

    @Override
    protected void validateCarrier(final Path carrierFile) throws CarrierException {
        super.validateCarrier(carrierFile);
        try {
            byte[] head = new byte[RIFF_HEADER_LEN];
            try (var in = Files.newInputStream(carrierFile)) {
                int read = in.readNBytes(head, 0, head.length);
                if (read != head.length
                        || !regionMatches(head, 0, RIFF)
                        || !regionMatches(head, 8, WAVE)) {
                    throw new CarrierException("不是有效的 WAV 文件（RIFF/WAVE 签名不匹配）: "
                            + carrierFile);
                }
            }
        } catch (IOException e) {
            throw new CarrierException("读取 WAV 文件失败: " + e.getMessage(), e);
        }
    }

    @Override
    protected void doEmbed(final Path carrier, final byte[] payload, final byte[] meta,
                           final Path output, final byte[] password,
                           final EmbedOptions options) throws CarrierException {
        // payload 参数此处为门面组合好的 [CarrierMetadata + Payload] 不透明块
        byte[] combined = payload;
        try {
            byte[] wavBytes = Files.readAllBytes(carrier);
            if (wavBytes.length < RIFF_HEADER_LEN) {
                throw new CarrierException("WAV 文件过小，不是合法 RIFF");
            }

            boolean pad = (combined.length & 1) == 1;
            int stegChunkTotal = CHUNK_HEADER_LEN + combined.length + (pad ? 1 : 0);

            // 更新 RIFF size 字段：原 size + 追加的 STEG chunk 总字节数
            long originalRiffSize = readUInt32LE(wavBytes, RIFF_SIZE_OFFSET);
            long newRiffSize = originalRiffSize + stegChunkTotal;
            byte[] outHeader = wavBytes.clone();
            writeUInt32LE(outHeader, RIFF_SIZE_OFFSET, newRiffSize);

            try (OutputStream out = Files.newOutputStream(output,
                    StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING)) {
                out.write(outHeader);
                // STEG chunk 头 + 数据
                out.write(STEG);
                out.write(uint32LE(combined.length));
                out.write(combined);
                if (pad) {
                    out.write(0);
                }
            }
        } catch (IOException e) {
            throw new CarrierException("WAV 嵌入失败: " + e.getMessage(), e);
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
            throw new CarrierException("WAV 隐写数据不完整：组合块短于元数据长度");
        }
        return Arrays.copyOfRange(combined, metaLen, combined.length);
    }

    @Override
    public boolean detect(final Path file) {
        try {
            byte[] bytes = Files.readAllBytes(file);
            byte[] data = findStegChunkData(bytes);
            return data != null && CarrierMetadata.startsWithMagic(data);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * 从隐写 WAV 中读取 STEG chunk 的组合块数据。
     *
     * @param stegoFile 隐写 WAV 文件
     * @return 组合块字节
     * @throws CarrierException 未找到 STEG chunk 或读取失败
     */
    private byte[] readCombined(final Path stegoFile) throws CarrierException {
        try {
            byte[] bytes = Files.readAllBytes(stegoFile);
            byte[] data = findStegChunkData(bytes);
            if (data == null) {
                throw new CarrierException("WAV 中未找到隐写数据（STEG chunk）");
            }
            if (!CarrierMetadata.startsWithMagic(data)) {
                throw new CarrierException("WAV STEG chunk 不是有效的隐写载荷");
            }
            return data;
        } catch (IOException e) {
            throw new CarrierException("读取 WAV 隐写数据失败: " + e.getMessage(), e);
        }
    }

    /**
     * 遍历 RIFF chunk 链，返回首个 {@code STEG} chunk 的数据部分。
     *
     * @param bytes WAV 文件字节
     * @return STEG chunk 数据，未找到返回 null
     */
    private static byte[] findStegChunkData(final byte[] bytes) {
        if (bytes.length < RIFF_HEADER_LEN
                || !regionMatches(bytes, 0, RIFF)
                || !regionMatches(bytes, 8, WAVE)) {
            return null;
        }
        int pos = RIFF_HEADER_LEN;
        while (pos + CHUNK_HEADER_LEN <= bytes.length) {
            long size = readUInt32LE(bytes, pos + 4);
            int dataStart = pos + CHUNK_HEADER_LEN;
            if (dataStart + size > bytes.length) {
                // size 越界，视为损坏
                return null;
            }
            if (regionMatches(bytes, pos, STEG)) {
                return Arrays.copyOfRange(bytes, dataStart, (int) (dataStart + size));
            }
            // 前进到下一个 chunk（奇数 payload 需跳过 1 字节填充）
            long advance = CHUNK_HEADER_LEN + size + (size & 1L);
            long next = pos + advance;
            if (next <= pos || next > bytes.length) {
                return null;
            }
            pos = (int) next;
        }
        return null;
    }

    // ---- 小端读写辅助 ----

    /**
     * 判断给定偏移处 4 字节是否匹配目标标识。
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
     * 读取小端 uint32。
     */
    private static long readUInt32LE(final byte[] data, final int offset) {
        return (data[offset] & 0xFFL)
                | ((data[offset + 1] & 0xFFL) << 8)
                | ((data[offset + 2] & 0xFFL) << 16)
                | ((data[offset + 3] & 0xFFL) << 24);
    }

    /**
     * 就地写入小端 uint32。
     */
    private static void writeUInt32LE(final byte[] data, final int offset, final long value) {
        data[offset] = (byte) (value & 0xFF);
        data[offset + 1] = (byte) ((value >>> 8) & 0xFF);
        data[offset + 2] = (byte) ((value >>> 16) & 0xFF);
        data[offset + 3] = (byte) ((value >>> 24) & 0xFF);
    }

    /**
     * 生成小端 uint32 字节序列。
     */
    private static byte[] uint32LE(final long value) {
        return ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN)
                .putInt((int) value).array();
    }
}
