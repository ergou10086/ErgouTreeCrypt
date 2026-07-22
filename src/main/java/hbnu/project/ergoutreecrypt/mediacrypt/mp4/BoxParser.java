package hbnu.project.ergoutreecrypt.mediacrypt.mp4;

import hbnu.project.ergoutreecrypt.mediacrypt.MediaCryptException;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;

/**
 * ISO-BMFF（MP4）顶层 box 扫描器
 * 遍历文件的顶层 box 序列，定位 {@code ftyp}/{@code moov}/{@code mdat}及自定义 {@code uuid} 元数据 box。
 *
 * <p>支持 32 位 size、64 位 largesize（size==1）、延伸至文件尾（size==0）。仅扫描顶层 box（V-MDAT 档只需定位 {@code mdat}）；子 box（如 {@code stbl}）的深入解析留待 V-SAMPLE 档。
 *
 * @author ErgouTree
 */
public final class BoxParser {

    /**
     * 自定义元数据 box 的 16 字节 UUID（"EGTC-AVE-MEDIA01" ASCII）。
     */
    public static final byte[] META_UUID = "EGTC-AVE-MEDIA01".getBytes(StandardCharsets.US_ASCII);

    private final List<Mp4Box> boxes;
    private final long fileSize;

    private BoxParser(List<Mp4Box> boxes, long fileSize) {
        this.boxes = boxes;
        this.fileSize = fileSize;
    }

    /**
     * 解析 MP4 顶层 box。
     *
     * @throws MediaCryptException 非法 ISO-BMFF
     */
    public static BoxParser parse(Path path) throws MediaCryptException, IOException {
        try (FileChannel ch = FileChannel.open(path, StandardOpenOption.READ)) {
            long fileSize = ch.size();
            if (fileSize < 8) {
                throw new MediaCryptException("文件过小，不是合法 MP4");
            }

            List<Mp4Box> boxes = new ArrayList<>();
            long pos = 0;
            boolean sawFtyp = false;

            while (pos + 8 <= fileSize) {
                ByteBuffer hdr = readAt(ch, pos, 8);
                long size32 = hdr.order(ByteOrder.BIG_ENDIAN).getInt(0) & 0xFFFFFFFFL;
                String type = ascii(hdr, 4, 4);

                int headerSize = 8;
                long boxSize;
                if (size32 == 1) {
                    ByteBuffer large = readAt(ch, pos + 8, 8);
                    boxSize = large.order(ByteOrder.BIG_ENDIAN).getLong(0);
                    headerSize = 16;
                } else if (size32 == 0) {
                    // 延伸到文件尾。
                    boxSize = fileSize - pos;
                } else {
                    boxSize = size32;
                }

                if (boxSize < headerSize || pos + boxSize > fileSize) {
                    // 容错：非法/截断 box，停止解析。
                    if (boxes.isEmpty()) {
                        throw new MediaCryptException("MP4 顶层 box 长度非法");
                    }
                    break;
                }

                if (pos == 0 && !"ftyp".equals(type)) {
                    // 多数 MP4 以 ftyp 起始；非 ftyp 起始的（如某些 mov）也尝试解析，但记录。
                    sawFtyp = false;
                }
                if ("ftyp".equals(type)) {
                    sawFtyp = true;
                }

                long payloadOffset = pos + headerSize;
                long payloadSize = boxSize - headerSize;
                boolean zeroSize = (size32 == 0);
                boxes.add(new Mp4Box(type, pos, headerSize, payloadOffset, payloadSize, zeroSize));
                pos += boxSize;
            }

            if (boxes.isEmpty()) {
                throw new MediaCryptException("未解析到任何 MP4 box");
            }
            // 不强制要求 ftyp，但要求至少存在已知结构；这里仅做温和校验。
            if (!sawFtyp && findBox(boxes, "moov") == null && findBox(boxes, "mdat") == null) {
                throw new MediaCryptException("不是合法的 MP4（缺少 ftyp/moov/mdat）");
            }

            return new BoxParser(boxes, fileSize);
        }
    }

    private static Mp4Box findBox(List<Mp4Box> boxes, String type) {
        for (Mp4Box b : boxes) {
            if (b.type().equals(type)) {
                return b;
            }
        }
        return null;
    }

    private static boolean matches(ByteBuffer bb, byte[] expected) {
        for (int i = 0; i < expected.length; i++) {
            if (bb.get(i) != expected[i]) {
                return false;
            }
        }
        return true;
    }

    private static ByteBuffer readAt(FileChannel ch, long pos, int len) throws IOException {
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

    private static String ascii(ByteBuffer bb, int off, int len) {
        byte[] b = new byte[len];
        for (int i = 0; i < len; i++) {
            b[i] = bb.get(off + i);
        }
        return new String(b, StandardCharsets.US_ASCII);
    }

    /**
     * 查找指定类型的首个顶层 box。
     */
    public Mp4Box findBox(String type) {
        return findBox(boxes, type);
    }

    /**
     * 返回 {@code mdat} box。
     *
     * @throws MediaCryptException 缺少 mdat
     */
    public Mp4Box requireMdat() throws MediaCryptException {
        Mp4Box mdat = findBox("mdat");
        if (mdat == null) {
            throw new MediaCryptException("MP4 缺少 mdat box（无媒体数据可加密）");
        }
        return mdat;
    }

    /**
     * 查找自定义元数据 uuid box（匹配 {@link #META_UUID}）。
     *
     * @return box 或 {@code null}
     */
    public Mp4Box findMetaUuidBox(Path path) throws IOException {
        try (FileChannel ch = FileChannel.open(path, StandardOpenOption.READ)) {
            for (Mp4Box b : boxes) {
                if (!"uuid".equals(b.type()) || b.payloadSize() < META_UUID.length) {
                    continue;
                }
                ByteBuffer u = readAt(ch, b.payloadOffset(), META_UUID.length);
                if (matches(u, META_UUID)) {
                    return b;
                }
            }
        }
        return null;
    }

    /**
     * 直接扫描文件原始字节查找自定义 uuid 元数据 box（绕过解析出的 box 列表）。
     *
     * <p>用于恢复场景：当某个前置 box 使用 size==0（延伸至文件尾），
     * 解析器会把追加在末尾的 uuid box "吞并"进该 box，导致 parsed box 列表中不包含 uuid。
     * 本方法从文件末尾逐 box 向前扫描，定位匹配 {@link #META_UUID} 的 uuid box。
     *
     * @param path 加密后的媒体文件
     * @return 匹配的 uuid box 或 {@code null}
     */
    public static Mp4Box scanForMetaUuidBox(Path path) throws IOException {
        try (FileChannel ch = FileChannel.open(path, StandardOpenOption.READ)) {
            long fileSize = ch.size();
            // uuid box 至少需要 8(header) + 16(uuid) = 24 字节。
            // 从文件末尾向前搜索，步进为读取 8 字节头。
            // 策略：从文件末尾区域扫描可能的 uuid box 头。
            long searchStart = Math.max(0, fileSize - 2048);
            // 从 searchStart 开始，以 1 字节步进扫描 "uuid" 类型标记
            for (long pos = searchStart; pos + 8 <= fileSize; pos++) {
                ByteBuffer hdr = readAt(ch, pos, 8);
                long size32 = hdr.order(ByteOrder.BIG_ENDIAN).getInt(0) & 0xFFFFFFFFL;
                String type = ascii(hdr, 4, 4);
                if (!"uuid".equals(type)) {
                    continue;
                }
                int headerSize = 8;
                long boxSize;
                if (size32 == 1) {
                    if (pos + 16 > fileSize) {
                        continue;
                    }
                    ByteBuffer large = readAt(ch, pos + 8, 8);
                    boxSize = large.order(ByteOrder.BIG_ENDIAN).getLong(0);
                    headerSize = 16;
                } else if (size32 == 0) {
                    boxSize = fileSize - pos;
                } else {
                    boxSize = size32;
                }
                if (boxSize < headerSize + META_UUID.length || pos + boxSize > fileSize) {
                    continue;
                }
                long payloadOffset = pos + headerSize;
                long payloadSize = boxSize - headerSize;
                if (payloadSize < META_UUID.length) {
                    continue;
                }
                ByteBuffer u = readAt(ch, payloadOffset, META_UUID.length);
                if (matches(u, META_UUID)) {
                    return new Mp4Box(type, pos, headerSize, payloadOffset, payloadSize);
                }
            }
        }
        return null;
    }

    public List<Mp4Box> boxes() {
        return boxes;
    }

    public long fileSize() {
        return fileSize;
    }
}
