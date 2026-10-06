package hbnu.project.ergoutreecrypt.fileops;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

/** Writes ZIP64 records, preserving ZIPX method numbers and WinZip AES flags. */
final class ZipxOutput implements Closeable {
    private final OutputStream out;
    private final List<Entry> entries = new ArrayList<>();
    private long position;

    /**
     * Metadata retained until the central directory is written.
     * @param name encoded entry name
     * @param method header compression method
     * @param flags general-purpose flags
     * @param version minimum extraction version
     * @param crc stored CRC
     * @param size uncompressed byte count
     * @param compressed payload byte count
     * @param offset local header offset
     * @param aes AES extra field
     * @param directory whether the entry is a directory
     */
    private record Entry(byte[] name, int method, int flags, int version, long crc,
                         long size, long compressed, long offset, byte[] aes, boolean directory) { }

    /**
     * Opens a staged output archive.
     * @param path staged archive path
     * @throws IOException opening failed
     */
    ZipxOutput(Path path) throws IOException {
        out = new BufferedOutputStream(Files.newOutputStream(path));
    }

    /**
     * Appends already compressed and optionally encrypted file data.
     * @param name UTF-8 entry name
     * @param payload staged payload, or null for a directory
     * @param method actual compression method
     * @param size uncompressed size
     * @param crc uncompressed CRC32
     * @param encrypted whether the payload uses WinZip AE-2
     * @throws IOException writing failed
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
        number(version, 2); number(flags, 2); number(entry.method, 2);
        number(0, 2); number(0x21, 2);
        number(entry.crc, 4); number(0xffffffffL, 4); number(0xffffffffL, 4);
        number(encoded.length, 2); number(20 + aes.length, 2);
        bytes(encoded);
        number(1, 2); number(16, 2); number(size, 8); number(entry.compressed, 8);
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
     * Writes the central directory and ZIP64 end records.
     * @throws IOException writing failed
     */
    void finish() throws IOException {
        long start = position;
        for (Entry entry : entries) {
            number(0x02014b50L, 4); number(entry.version, 2); number(entry.version, 2);
            number(entry.flags, 2); number(entry.method, 2);
            number(0, 2); number(0x21, 2); number(entry.crc, 4);
            number(0xffffffffL, 4); number(0xffffffffL, 4);
            number(entry.name.length, 2); number(28 + entry.aes.length, 2);
            number(0, 2); number(0, 2); number(0, 2);
            number(entry.directory ? 0x10 : 0, 4); number(0xffffffffL, 4);
            bytes(entry.name);
            number(1, 2); number(24, 2);
            number(entry.size, 8); number(entry.compressed, 8); number(entry.offset, 8);
            bytes(entry.aes);
        }
        long length = position - start;
        long zip64 = position;
        number(0x06064b50L, 4); number(44, 8); number(45, 2); number(45, 2);
        number(0, 4); number(0, 4); number(entries.size(), 8); number(entries.size(), 8);
        number(length, 8); number(start, 8);
        number(0x07064b50L, 4); number(0, 4); number(zip64, 8); number(1, 4);
        number(0x06054b50L, 4); number(0, 2); number(0, 2);
        number(0xffff, 2); number(0xffff, 2);
        number(0xffffffffL, 4); number(0xffffffffL, 4); number(0, 2);
    }

    /**
     * Writes a little-endian unsigned integer.
     * @param value integer value
     * @param length byte width
     * @throws IOException writing failed
     */
    private void number(long value, int length) throws IOException {
        for (int i = 0; i < length; i++) out.write((int) (value >>> (8 * i)) & 255);
        position += length;
    }

    /**
     * Writes bytes and advances the archive offset.
     * @param value bytes to write
     * @throws IOException writing failed
     */
    private void bytes(byte[] value) throws IOException {
        out.write(value);
        position += value.length;
    }

    /** Closes the staged output stream. */
    @Override public void close() throws IOException {
        out.close();
    }
}
