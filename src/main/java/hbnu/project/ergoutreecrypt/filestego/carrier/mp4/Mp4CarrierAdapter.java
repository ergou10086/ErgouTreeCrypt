package hbnu.project.ergoutreecrypt.filestego.carrier.mp4;

import hbnu.project.ergoutreecrypt.filestego.api.CarrierException;
import hbnu.project.ergoutreecrypt.filestego.api.EmbedOptions;
import hbnu.project.ergoutreecrypt.filestego.carrier.spi.AbstractCarrierAdapter;
import hbnu.project.ergoutreecrypt.filestego.carrier.spi.CarrierMetadata;
import hbnu.project.ergoutreecrypt.mediacrypt.MediaCryptException;
import hbnu.project.ergoutreecrypt.mediacrypt.mp4.BoxParser;
import hbnu.project.ergoutreecrypt.mediacrypt.mp4.Mp4Box;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;
import java.util.List;

/**
 * MP4 / ISO-BMFF 载体适配器。
 *
 * <p>在文件末尾追加自定义 {@code uuid} box，usertype 为工具专属
 * {@code EGTC-STEGO-MP401}（与媒体加密用的 {@code EGTC-AVE-MEDIA01} 严格分离），
 * box payload 为门面组合好的 {@code [CarrierMetadata + STEG-V2 Payload]}：
 * <pre>
 *   ftyp / moov / mdat / ...
 *   [size:4 BE][uuid][EGTC-STEGO-MP401:16][combined]
 * </pre>
 *
 * <p>解析复用 {@link BoxParser}；写入不调用 {@code Mp4UuidMetadata.append}，
 * 避免绑定媒体加密 UUID。当前置 box 使用 {@code size==0}（延伸至 EOF）导致
 * 顶层扫描吞并末尾 uuid 时，从文件尾部窗口回退扫描定位隐写 uuid。
 *
 * @author ErgouTree
 * @since 2026/8/11
 */
public final class Mp4CarrierAdapter extends AbstractCarrierAdapter {

    /** 隐写专用 uuid usertype（16 字节 ASCII）。 */
    public static final byte[] STEG_UUID =
            "EGTC-STEGO-MP401".getBytes(StandardCharsets.US_ASCII);

    /** uuid box 类型。 */
    private static final String UUID_TYPE = "uuid";

    /** 普通 box 头长度（size + type）。 */
    private static final int BOX_HEADER_LEN = 8;

    @Override
    public String id() {
        return "mp4";
    }

    @Override
    public String displayName() {
        return "MP4 视频";
    }

    @Override
    public List<String> supportedExtensions() {
        return List.of(".mp4", ".m4a", ".m4v");
    }

    @Override
    protected void validateCarrier(final Path carrierFile) throws CarrierException {
        super.validateCarrier(carrierFile);
        try {
            BoxParser.parse(carrierFile);
        } catch (MediaCryptException e) {
            throw new CarrierException("不是有效的 MP4 文件: " + e.getMessage(), e);
        } catch (IOException e) {
            throw new CarrierException("读取 MP4 文件失败: " + e.getMessage(), e);
        }
    }

    @Override
    protected void doEmbed(final Path carrier, final byte[] payload, final byte[] meta,
                           final Path output, final byte[] password,
                           final EmbedOptions options) throws CarrierException {
        // payload 参数此处为门面组合好的 [CarrierMetadata + Payload] 不透明块
        byte[] combined = payload;
        try {
            // 先复制载体，再在末尾追加隐写 uuid box（保持原 box 偏移不变）
            Files.copy(carrier, output, StandardCopyOption.REPLACE_EXISTING);
            appendStegUuidBox(output, combined);
        } catch (IOException e) {
            throw new CarrierException("MP4 嵌入失败: " + e.getMessage(), e);
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
            throw new CarrierException("MP4 隐写数据不完整：组合块短于元数据长度");
        }
        return Arrays.copyOfRange(combined, metaLen, combined.length);
    }

    @Override
    public boolean detect(final Path file) {
        try {
            Mp4Box box = findStegUuidBox(file);
            if (box == null) {
                return false;
            }
            byte[] combined = readUuidPayload(file, box);
            return CarrierMetadata.startsWithMagic(combined);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * 从隐写 MP4 中读取 uuid box 内的组合块。
     *
     * @param stegoFile 隐写 MP4 文件
     * @return 组合块字节
     * @throws CarrierException 未找到隐写 uuid 或读取失败
     */
    private byte[] readCombined(final Path stegoFile) throws CarrierException {
        try {
            Mp4Box box = findStegUuidBox(stegoFile);
            if (box == null) {
                throw new CarrierException("MP4 中未找到隐写数据（uuid/EGTC-STEGO-MP401）");
            }
            byte[] combined = readUuidPayload(stegoFile, box);
            if (!CarrierMetadata.startsWithMagic(combined)) {
                throw new CarrierException("MP4 uuid box 不是有效的隐写载荷");
            }
            return combined;
        } catch (IOException e) {
            throw new CarrierException("读取 MP4 隐写数据失败: " + e.getMessage(), e);
        }
    }

    /**
     * 定位隐写专用 uuid box：先走顶层解析，失败则尾部回退扫描。
     *
     * @param file MP4 文件
     * @return 匹配的 uuid box，未找到返回 null
     * @throws IOException 读取失败
     */
    private static Mp4Box findStegUuidBox(final Path file) throws IOException {
        try {
            BoxParser parser = BoxParser.parse(file);
            try (FileChannel ch = FileChannel.open(file, StandardOpenOption.READ)) {
                for (Mp4Box b : parser.boxes()) {
                    if (!UUID_TYPE.equals(b.type()) || b.payloadSize() < STEG_UUID.length) {
                        continue;
                    }
                    ByteBuffer u = readAt(ch, b.payloadOffset(), STEG_UUID.length);
                    if (matches(u, STEG_UUID)) {
                        return b;
                    }
                }
            }
        } catch (MediaCryptException ignored) {
            // 结构异常时仍尝试尾部扫描
        }
        return scanForStegUuidBox(file);
    }

    /**
     * 扫描隐写 uuid box（处理 mdat size==0 吞并末尾 box 的情况）。
     *
     * <p>搜索连续的 {@code "uuid" + STEG_UUID} 模式，再回退 4 字节校验 size 字段，
     * 从而在任意 Payload 体积下仍能定位末尾追加的隐写 box。
     *
     * @param path MP4 文件
     * @return 匹配的 uuid box，未找到返回 null
     * @throws IOException 读取失败
     */
    private static Mp4Box scanForStegUuidBox(final Path path) throws IOException {
        byte[] typeAndUuid = new byte[4 + STEG_UUID.length];
        System.arraycopy(UUID_TYPE.getBytes(StandardCharsets.US_ASCII), 0, typeAndUuid, 0, 4);
        System.arraycopy(STEG_UUID, 0, typeAndUuid, 4, STEG_UUID.length);

        try (FileChannel ch = FileChannel.open(path, StandardOpenOption.READ)) {
            long fileSize = ch.size();
            if (fileSize < BOX_HEADER_LEN + STEG_UUID.length) {
                return null;
            }
            // 分块扫描：块间保留 pattern-1 字节重叠，避免跨界漏检
            final int chunkSize = 1024 * 1024;
            byte[] buf = new byte[chunkSize + typeAndUuid.length - 1];
            long filePos = 0;
            int carry = 0;
            while (filePos < fileSize) {
                int toRead = (int) Math.min(chunkSize, fileSize - filePos);
                ByteBuffer bb = ByteBuffer.wrap(buf, carry, toRead);
                int read = 0;
                while (read < toRead) {
                    int n = ch.read(bb, filePos + read);
                    if (n < 0) {
                        break;
                    }
                    read += n;
                }
                if (read <= 0) {
                    break;
                }
                int available = carry + read;
                int searchLimit = available - typeAndUuid.length + 1;
                for (int i = 0; i < searchLimit; i++) {
                    if (!regionMatches(buf, i, typeAndUuid)) {
                        continue;
                    }
                    // type 字段起始于绝对偏移 (filePos - carry + i)；size 在其前 4 字节
                    long typeOffset = filePos - carry + i;
                    long boxOffset = typeOffset - 4;
                    if (boxOffset < 0) {
                        continue;
                    }
                    ByteBuffer sizeBuf = readAt(ch, boxOffset, 4);
                    long size32 = sizeBuf.order(ByteOrder.BIG_ENDIAN).getInt(0) & 0xFFFFFFFFL;
                    if (size32 < BOX_HEADER_LEN + STEG_UUID.length) {
                        continue;
                    }
                    if (boxOffset + size32 > fileSize) {
                        continue;
                    }
                    long payloadOffset = boxOffset + BOX_HEADER_LEN;
                    long payloadSize = size32 - BOX_HEADER_LEN;
                    // 组合块紧跟 STEG_UUID，须以 EGFS 魔数开头
                    if (payloadSize < STEG_UUID.length + 4) {
                        continue;
                    }
                    ByteBuffer magic = readAt(ch, payloadOffset + STEG_UUID.length, 4);
                    byte[] magicBytes = new byte[4];
                    magic.get(magicBytes);
                    if (!CarrierMetadata.startsWithMagic(magicBytes)) {
                        continue;
                    }
                    return new Mp4Box(UUID_TYPE, boxOffset, BOX_HEADER_LEN,
                            payloadOffset, payloadSize);
                }
                // 保留尾部重叠供下一块
                if (available >= typeAndUuid.length - 1) {
                    System.arraycopy(buf, available - (typeAndUuid.length - 1),
                            buf, 0, typeAndUuid.length - 1);
                    carry = typeAndUuid.length - 1;
                } else {
                    carry = available;
                }
                filePos += read;
            }
        }
        return null;
    }

    /**
     * 判断缓冲区指定偏移是否匹配目标字节序列。
     *
     * @param data   缓冲区
     * @param offset 偏移
     * @param tag    目标序列
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
     * 读取 uuid box 中 usertype 之后的组合块字节。
     *
     * @param file    MP4 文件
     * @param uuidBox 已定位的隐写 uuid box
     * @return 组合块
     * @throws IOException      读取失败
     * @throws CarrierException box 过小
     */
    private static byte[] readUuidPayload(final Path file, final Mp4Box uuidBox)
            throws IOException, CarrierException {
        if (uuidBox.payloadSize() < STEG_UUID.length) {
            throw new CarrierException("MP4 隐写 uuid box 过小");
        }
        long metaOffset = uuidBox.payloadOffset() + STEG_UUID.length;
        int metaLen = (int) (uuidBox.payloadSize() - STEG_UUID.length);
        try (FileChannel ch = FileChannel.open(file, StandardOpenOption.READ)) {
            ByteBuffer bb = ByteBuffer.allocate(metaLen);
            int read = 0;
            while (read < metaLen) {
                int n = ch.read(bb, metaOffset + read);
                if (n < 0) {
                    throw new IOException("读取 MP4 uuid 隐写数据时遇到意外文件结束");
                }
                read += n;
            }
            return bb.array();
        }
    }

    /**
     * 将组合块作为隐写 uuid box 追加到文件末尾。
     *
     * @param file     目标文件（通常为已复制的载体）
     * @param combined 组合块
     * @throws IOException      写入失败
     * @throws CarrierException box 过大无法用 32-bit size 表示
     */
    private static void appendStegUuidBox(final Path file, final byte[] combined)
            throws IOException, CarrierException {
        int payloadLen = STEG_UUID.length + combined.length;
        long boxSize = BOX_HEADER_LEN + (long) payloadLen;
        if (boxSize > 0xFFFFFFFFL) {
            throw new CarrierException("MP4 隐写 uuid box 超过 32-bit size 上限");
        }
        ByteBuffer bb = ByteBuffer.allocate((int) boxSize).order(ByteOrder.BIG_ENDIAN);
        bb.putInt((int) boxSize);
        bb.put(UUID_TYPE.getBytes(StandardCharsets.US_ASCII));
        bb.put(STEG_UUID);
        bb.put(combined);
        bb.flip();

        try (FileChannel ch = FileChannel.open(file, StandardOpenOption.WRITE)) {
            long end = ch.size();
            while (bb.hasRemaining()) {
                end += ch.write(bb, end);
            }
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
                throw new IOException("读取 MP4 时遇到意外文件结束，位置 " + pos);
            }
            read += n;
        }
        bb.flip();
        return bb;
    }

    /**
     * 比较缓冲区前缀与期望字节是否一致。
     *
     * @param bb       缓冲区（从位置 0 起）
     * @param expected 期望字节
     * @return 是否匹配
     */
    private static boolean matches(final ByteBuffer bb, final byte[] expected) {
        for (int i = 0; i < expected.length; i++) {
            if (bb.get(i) != expected[i]) {
                return false;
            }
        }
        return true;
    }

}
