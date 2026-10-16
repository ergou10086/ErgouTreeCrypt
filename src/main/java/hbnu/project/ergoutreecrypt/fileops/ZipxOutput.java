package hbnu.project.ergoutreecrypt.fileops;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * 写入 ZIP64 记录，保留 ZIPX 方法编号和 WinZip AES 标志。
 */
final class ZipxOutput implements Closeable {
    private final OutputStream out;
    private final List<Entry> entries = new ArrayList<>();
    private long position;

    /**
     * 打开暂存输出归档。
     *
     * @param path 暂存归档路径
     * @throws IOException 打开失败
     */
    ZipxOutput(Path path) throws IOException {
        out = new BufferedOutputStream(Files.newOutputStream(path));
    }

    /**
     * 追加已压缩且可选加密的文件数据。
     *
     * @param name UTF-8 编码的条目名
     * @param payload 暂存载荷；目录条目为 null
     * @param method 实际压缩方法
     * @param size 未压缩大小
     * @param crc 未压缩数据的 CRC32
     * @param encrypted 载荷是否使用 WinZip AE-2
     * @throws IOException 写入失败
     */
    void add(String name, Path payload, int method, long size, long crc, boolean encrypted) throws IOException {
        byte[] encoded = name.getBytes(StandardCharsets.UTF_8);
        if (encoded.length > 65535) throw new IOException("ZIPX entry name too long: " + name);
        boolean directory = payload == null;
        byte[] aes = encrypted ? new byte[]{1, (byte) 0x99, 7, 0, 2, 0, 'A', 'E', 3,
                (byte) method, (byte) (method >>> 8)} : new byte[0];
        int version = Math.max(45, method == 12 ? 46 : method == 14 || method == 95 ? 63 : 20);
        if (encrypted) version = Math.max(version, 51);
        int flags = 0x800 | (encrypted ? 1 : 0) | (method == 14 ? 2 : 0);
        Entry entry = new Entry(encoded, encrypted ? 99 : method, flags, version, encrypted ? 0 : crc,
                size, directory ? 0 : Files.size(payload), position, aes, directory);
        number(0x04034b50L, 4);
        number(version, 2);
        number(flags, 2);
        number(entry.method, 2);
        number(0, 2);
        number(0x21, 2);
        number(entry.crc, 4);
        number(0xffffffffL, 4);
        number(0xffffffffL, 4);
        number(encoded.length, 2);
        number(20 + aes.length, 2);
        bytes(encoded);
        number(1, 2);
        number(16, 2);
        number(size, 8);
        number(entry.compressed, 8);
        bytes(aes);
        if (payload != null) {
            try (InputStream in = Files.newInputStream(payload)) {
                long copied = in.transferTo(out);
                if (copied != entry.compressed) throw new IOException("ZIPX payload size changed");
                position += copied;
            }
        }
        entries.add(entry);
    }

    /**
     * 写入中央目录和 ZIP64 结束记录。
     *
     * @throws IOException 写入失败
     */
    void finish() throws IOException {
        long start = position;
        for (Entry entry : entries) {
            number(0x02014b50L, 4);
            number(entry.version, 2);
            number(entry.version, 2);
            number(entry.flags, 2);
            number(entry.method, 2);
            number(0, 2);
            number(0x21, 2);
            number(entry.crc, 4);
            number(0xffffffffL, 4);
            number(0xffffffffL, 4);
            number(entry.name.length, 2);
            number(28 + entry.aes.length, 2);
            number(0, 2);
            number(0, 2);
            number(0, 2);
            number(entry.directory ? 0x10 : 0, 4);
            number(0xffffffffL, 4);
            bytes(entry.name);
            number(1, 2);
            number(24, 2);
            number(entry.size, 8);
            number(entry.compressed, 8);
            number(entry.offset, 8);
            bytes(entry.aes);
        }
        long length = position - start;
        long zip64 = position;
        number(0x06064b50L, 4);
        number(44, 8);
        number(45, 2);
        number(45, 2);
        number(0, 4);
        number(0, 4);
        number(entries.size(), 8);
        number(entries.size(), 8);
        number(length, 8);
        number(start, 8);
        number(0x07064b50L, 4);
        number(0, 4);
        number(zip64, 8);
        number(1, 4);
        number(0x06054b50L, 4);
        number(0, 2);
        number(0, 2);
        number(0xffff, 2);
        number(0xffff, 2);
        number(0xffffffffL, 4);
        number(0xffffffffL, 4);
        number(0, 2);
    }

    /**
     * 写入小端无符号整数。
     *
     * @param value 整数值
     * @param length 字节宽度
     * @throws IOException 写入失败
     */
    private void number(long value, int length) throws IOException {
        for (int i = 0; i < length; i++) out.write((int) (value >>> (8 * i)) & 255);
        position += length;
    }

    /**
     * 写入字节并推进归档偏移。
     *
     * @param value 待写入字节
     * @throws IOException 写入失败
     */
    private void bytes(byte[] value) throws IOException {
        out.write(value);
        position += value.length;
    }

    /**
     * 关闭暂存输出流。
     */
    @Override
    public void close() throws IOException {
        out.close();
    }

    /**
     * 保留至中央目录写入完成的元数据。
     *
     * @param name 编码后的条目名
     * @param method 头中的压缩方法
     * @param flags 通用标志
     * @param version 最低提取版本
     * @param crc 存储的 CRC
     * @param size 未压缩字节数
     * @param compressed 载荷字节数
     * @param offset 本地头偏移
     * @param aes AES 扩展字段
     * @param directory 是否为目录条目
     */
    private record Entry(byte[] name, int method, int flags, int version, long crc,
                         long size, long compressed, long offset, byte[] aes, boolean directory) {
    }
}
