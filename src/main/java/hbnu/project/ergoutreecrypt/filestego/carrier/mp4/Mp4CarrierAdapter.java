package hbnu.project.ergoutreecrypt.filestego.carrier.mp4;

import hbnu.project.ergoutreecrypt.filestego.api.CarrierException;
import hbnu.project.ergoutreecrypt.filestego.api.EmbedOptions;
import hbnu.project.ergoutreecrypt.filestego.api.ProgressListener;
import hbnu.project.ergoutreecrypt.filestego.carrier.spi.AbstractCarrierAdapter;
import hbnu.project.ergoutreecrypt.filestego.carrier.spi.CarrierMetadata;
import hbnu.project.ergoutreecrypt.mediacrypt.MediaCryptException;
import hbnu.project.ergoutreecrypt.mediacrypt.mp4.BoxParser;
import hbnu.project.ergoutreecrypt.mediacrypt.mp4.Mp4Box;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
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

    /** 流式复制分块大小（1 MiB）。 */
    private static final int STREAM_CHUNK_BYTES = 1 << 20;

    /** 元数据探测上限（≥ paranoid+stealth 组合下的最大 126 字节）。 */
    private static final int META_PROBE_LEN = 128;

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
        // 按 meta.payloadSize() 精确截断，防止 obfuscateSize 追加的 padding 混入
        long payloadSize = meta.payloadSize();
        int end = Math.min(combined.length, (int) Math.min(Integer.MAX_VALUE,
                metaLen + payloadSize));
        return Arrays.copyOfRange(combined, metaLen, end);
    }

    @Override
    public boolean detect(final Path file) {
        try {
            Mp4Box box = findStegUuidBox(file);
            if (box == null || box.payloadSize() < STEG_UUID.length + 4) {
                return false;
            }
            // 只读取 usertype 之后的 4 字节魔数，避免将整个 Payload 读入内存
            try (FileChannel ch = FileChannel.open(file, StandardOpenOption.READ)) {
                ByteBuffer magic = readAt(ch, box.payloadOffset() + STEG_UUID.length, 4);
                byte[] magicBytes = new byte[4];
                magic.get(magicBytes);
                return CarrierMetadata.startsWithMagic(magicBytes);
            }
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
     * 流式嵌入：复制载体后，在文件末尾追加隐写 uuid box（box 头 + usertype +
     * 元数据 + Payload 文件分块写入），不将 Payload 读入内存。
     *
     * @param carrierFile 原始载体文件路径
     * @param meta        序列化后的 CarrierMetadata 字节数组
     * @param payloadFile STEG-V2 Payload 文件路径
     * @param output      输出文件路径
     * @param password    密码（MP4 uuid box 方案不使用）
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
     * 流式嵌入（带进度回调）：分块复制载体后，在文件末尾追加隐写 uuid box
     * （box 头 + usertype + 元数据 + Payload 分块写入），并按已复制字节数占
     * 载体与 Payload 总字节数的比例逐块回调进度。
     *
     * @param carrierFile 原始载体文件路径
     * @param meta        序列化后的 CarrierMetadata 字节数组
     * @param payloadFile STEG-V2 Payload 文件路径
     * @param output      输出文件路径
     * @param password    密码（MP4 uuid box 方案不使用）
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
            long total = carrierSize + Files.size(payloadFile);
            // 先分块复制载体（保持原 box 偏移不变），再在末尾追加隐写 uuid box
            long done = 0;
            byte[] buf = new byte[STREAM_CHUNK_BYTES];
            try (InputStream in = Files.newInputStream(carrierFile);
                 OutputStream out = Files.newOutputStream(output,
                         StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING)) {
                int n;
                while ((n = in.read(buf)) > 0) {
                    out.write(buf, 0, n);
                    done += n;
                    if (listener != null) {
                        listener.onProgress((double) done / Math.max(total, 1L));
                    }
                }
            }
            appendStegUuidBoxFromFile(output, meta, payloadFile, listener, done, total);
            if (listener != null) {
                listener.onProgress(1.0);
            }
        } catch (IOException e) {
            throw new CarrierException("MP4 嵌入失败: " + e.getMessage(), e);
        }
    }

    /**
     * 流式提取：定位隐写 uuid box，定点读取元数据，再按
     * {@code meta.payloadSize()} 精确流式拷贝 Payload 到文件。
     *
     * @param stegoFile  隐写载体文件
     * @param password   密码（MP4 uuid box 方案不使用）
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
     * 流式提取（带进度回调）：定位隐写 uuid box，定点读取元数据，再按
     * {@code meta.payloadSize()} 精确流式拷贝 Payload 到文件，并按已拷贝
     * 字节数逐块回调进度。
     *
     * @param stegoFile  隐写载体文件
     * @param password   密码（MP4 uuid box 方案不使用）
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
        try {
            Mp4Box box = findStegUuidBox(stegoFile);
            if (box == null) {
                throw new CarrierException("MP4 中未找到隐写数据（uuid/EGTC-STEGO-MP401）");
            }
            if (box.payloadSize() < STEG_UUID.length) {
                throw new CarrierException("MP4 隐写 uuid box 过小");
            }
            long metaOffset = box.payloadOffset() + STEG_UUID.length;
            long combinedLen = box.payloadSize() - STEG_UUID.length;
            CarrierMetadata meta;
            try (FileChannel ch = FileChannel.open(stegoFile, StandardOpenOption.READ)) {
                // 定点读取并解析元数据（最多 126 字节）
                int metaProbe = (int) Math.min(META_PROBE_LEN, combinedLen);
                ByteBuffer metaRaw = readAt(ch, metaOffset, metaProbe);
                byte[] metaBytes = new byte[metaProbe];
                metaRaw.get(metaBytes);
                meta = CarrierMetadata.fromBytes(metaBytes);
                int metaLen = CarrierMetadata.totalSize(meta.isParanoid(), meta.isStealth());
                long payloadStart = metaOffset + metaLen;
                long payloadSize = meta.payloadSize();
                if (payloadSize < 0 || metaLen + payloadSize > combinedLen) {
                    throw new CarrierException("MP4 隐写数据不完整：Payload 超出 box 范围");
                }
                // 定点流式拷贝 payloadSize 字节
                try (OutputStream out = Files.newOutputStream(payloadOut,
                        StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING)) {
                    copyRange(ch, payloadStart, payloadSize, out, listener);
                }
            }
            return meta;
        } catch (CarrierException e) {
            throw e;
        } catch (IOException e) {
            throw new CarrierException("读取 MP4 隐写数据失败: " + e.getMessage(), e);
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
     * 流式追加隐写 uuid box：box 头 + usertype + 元数据 + Payload 文件分块写入。
     *
     * <p>与 {@link #appendStegUuidBox} 产出相同的 box 布局，但 Payload 从文件
     * 分块读入，不分配整块内存。box size 在写入前可预知
     * （8 + 16 + metaLen + payloadFileSize），须满足 32-bit size 上限。
     *
     * @param file        目标文件（通常为已复制的载体）
     * @param meta        序列化后的 CarrierMetadata 字节数组
     * @param payloadFile STEG-V2 Payload 文件路径
     * @param listener    进度监听器（可为 null），按已写入字节数回调
     * @param done        box 写入前已完成的字节数
     * @param total       进度分母（整体总字节数）
     * @throws IOException      写入失败
     * @throws CarrierException box 过大无法用 32-bit size 表示
     */
    private static void appendStegUuidBoxFromFile(final Path file, final byte[] meta,
                                                  final Path payloadFile,
                                                  final ProgressListener listener,
                                                  final long done, final long total)
            throws IOException, CarrierException {
        long payloadLen = STEG_UUID.length + meta.length + Files.size(payloadFile);
        long boxSize = BOX_HEADER_LEN + payloadLen;
        if (boxSize > 0xFFFFFFFFL) {
            throw new CarrierException("MP4 隐写 uuid box 超过 32-bit size 上限");
        }
        try (FileChannel ch = FileChannel.open(file, StandardOpenOption.WRITE)) {
            long pos = ch.size();
            // box 头 + usertype
            ByteBuffer head = ByteBuffer.allocate(BOX_HEADER_LEN + STEG_UUID.length)
                    .order(ByteOrder.BIG_ENDIAN);
            head.putInt((int) boxSize);
            head.put(UUID_TYPE.getBytes(StandardCharsets.US_ASCII));
            head.put(STEG_UUID);
            head.flip();
            pos += ch.write(head, pos);
            // 元数据
            ByteBuffer metaBuf = ByteBuffer.wrap(meta);
            while (metaBuf.hasRemaining()) {
                pos += ch.write(metaBuf, pos);
            }
            // Payload 分块追加
            ByteBuffer buf = ByteBuffer.allocate(STREAM_CHUNK_BYTES);
            byte[] tmp = buf.array();
            long copied = done;
            try (InputStream in = Files.newInputStream(payloadFile)) {
                int n;
                while ((n = in.read(tmp)) > 0) {
                    buf.clear();
                    buf.limit(n);
                    pos += ch.write(buf, pos);
                    copied += n;
                    if (listener != null) {
                        listener.onProgress((double) copied / Math.max(total, 1L));
                    }
                }
            }
        }
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
                    throw new IOException("读取 MP4 时遇到意外文件结束，位置 " + cur);
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
