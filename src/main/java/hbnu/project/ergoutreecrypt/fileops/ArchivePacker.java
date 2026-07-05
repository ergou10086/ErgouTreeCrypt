package hbnu.project.ergoutreecrypt.fileops;

import net.lingala.zip4j.ZipFile;
import net.lingala.zip4j.model.ZipParameters;
import net.lingala.zip4j.model.enums.AesKeyStrength;
import net.lingala.zip4j.model.enums.EncryptionMethod;
import org.apache.commons.compress.archivers.sevenz.SevenZArchiveEntry;
import org.apache.commons.compress.archivers.sevenz.SevenZMethod;
import org.apache.commons.compress.archivers.sevenz.SevenZOutputFile;
import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveOutputStream;
import org.apache.commons.compress.compressors.gzip.GzipCompressorOutputStream;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

/**
 * 归档打包工具。
 *
 * <p>支持 ZIP / GZ / TAR.GZ / 7Z 四种格式。密码保护策略：
 * <ul>
 *   <li><b>ZIP：</b>使用 zip4j 原生 AES-256 加密，外部工具（Bandizip / 7-Zip）
 *       可正确提示密码。</li>
 *   <li><b>7Z：</b>使用 7z 原生 AES-256 容器加密，外部工具可正确提示密码。</li>
 *   <li><b>GZ / TAR.GZ：</b>无原生密码支持，采用整体 AES-256-CTR 加密包裹
 *       （MAGIC + salt + IV + ciphertext），需用本工具解密。</li>
 * </ul>
 *
 * @author ErgouTree
 */
public final class ArchivePacker {

    /**
     * 加密文件魔数标识（12 字节）。
     */
    private static final byte[] MAGIC = "EGTC_ARCHV1\0".getBytes();

    /**
     * PBKDF2 salt 长度（16 字节）。
     */
    private static final int SALT_SIZE = 16;

    /**
     * AES-CTR IV 长度（16 字节）。
     */
    private static final int IV_SIZE = 16;

    /**
     * AES 密钥长度（32 字节，AES-256）。
     */
    private static final int KEY_SIZE = 32;

    /**
     * PBKDF2-HMAC-SHA256 迭代次数。
     */
    private static final int PBKDF2_ITERATIONS = 100_000;

    private ArchivePacker() {
    }

    /**
     * 将单个文件或目录打包为指定格式的归档。
     *
     * @param output   输出归档路径
     * @param input    输入文件或目录
     * @param format   归档格式
     * @param password 加密密码（可为 null/空）
     * @throws IOException 打包或加密失败
     */
    public static void pack(Path output, Path input, Format format, String password) throws IOException {
        boolean hasPwd = password != null && !password.isEmpty();
        if (hasPwd) {
            switch (format) {
                case ZIP -> { packZipNative(output, input, password); return; }
                case _7Z -> { pack7z(output, input, password); return; }
            }
        }
        // 无密码或需要整体包裹的格式（GZ / TAR.GZ）
        Path workOutput = hasPwd ? Files.createTempFile("ergou-plain-", ".tmp") : output;
        try {
            switch (format) {
                case ZIP -> packZipPlain(workOutput, input);
                case GZ -> packGz(workOutput, input);
                case TAR_GZ -> packTarGz(workOutput, input);
                default -> throw new IllegalArgumentException("Unsupported format: " + format);
            }
            if (hasPwd) {
                wrapEncrypted(workOutput, output, password);
            }
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException("Archive encryption failed: " + e.getMessage(), e);
        } finally {
            if (hasPwd) {
                Files.deleteIfExists(workOutput);
            }
        }
    }

    /**
     * 将多个文件打包为单个归档。
     *
     * <p>GZ 格式天然仅支持单文件流，多文件时自动按 TAR.GZ 处理。
     *
     * @param output   输出归档路径
     * @param baseDir  计算条目相对名的基准目录
     * @param entries  要打入归档的文件路径列表
     * @param format   归档格式
     * @param password 加密密码（可为 null/空）
     * @throws IOException 打包或加密失败
     */
    public static void packEntries(Path output, Path baseDir, List<Path> entries,
                                   Format format, String password) throws IOException {
        if (entries == null || entries.isEmpty()) {
            throw new IOException("no entries to archive");
        }

        Format effective = (format == Format.GZ && entries.size() > 1) ? Format.TAR_GZ : format;
        boolean hasPwd = password != null && !password.isEmpty();
        if (hasPwd) {
            switch (effective) {
                case ZIP -> { packZipEntriesNative(output, baseDir, entries, password); return; }
                case _7Z -> { pack7zEntries(output, baseDir, entries, password); return; }
            }
        }
        // 无密码或需要整体包裹的格式（GZ / TAR.GZ）
        Path workOutput = hasPwd ? Files.createTempFile("ergou-plain-", ".tmp") : output;
        try {
            switch (effective) {
                case ZIP -> packZipEntriesPlain(workOutput, baseDir, entries);
                case GZ -> packGz(workOutput, entries.getFirst());
                case TAR_GZ -> packTarGzEntries(workOutput, baseDir, entries);
                default -> throw new IllegalArgumentException("Unsupported format: " + effective);
            }
            if (hasPwd) {
                wrapEncrypted(workOutput, output, password);
            }
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException("Archive encryption failed: " + e.getMessage(), e);
        } finally {
            if (hasPwd) {
                Files.deleteIfExists(workOutput);
            }
        }
    }

    // ==================== 条目名生成 ====================

    /**
     * 生成归档内条目名：以 baseDir 为基准的相对路径，路径分隔符统一为 '/'。
     */
    private static String entryName(Path baseDir, Path file) {
        if (baseDir != null && file.startsWith(baseDir)) {
            return baseDir.relativize(file).toString().replace('\\', '/');
        }
        return file.getFileName().toString();
    }

    // ==================== 整体加密包裹（GZ / TAR.GZ） ====================

    /**
     * 将明文文件整体 AES-256-CTR 加密，写入目标路径。
     *
     * <p>输出格式：MAGIC(12) + salt(16) + IV(16) + ciphertext。
     */
    private static void wrapEncrypted(Path input, Path output, String password) throws Exception {
        byte[] salt = new byte[SALT_SIZE];
        new SecureRandom().nextBytes(salt);
        byte[] iv = new byte[IV_SIZE];
        new SecureRandom().nextBytes(iv);

        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, PBKDF2_ITERATIONS, KEY_SIZE * 8);
        SecretKeySpec key = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");

        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));

        try (OutputStream fos = Files.newOutputStream(output)) {
            fos.write(MAGIC);
            fos.write(salt);
            fos.write(iv);
            try (CipherOutputStream cos = new CipherOutputStream(fos, cipher);
                 InputStream fin = Files.newInputStream(input)) {
                fin.transferTo(cos);
            }
        }
    }

    // ==================== ZIP 原生加密（zip4j） ====================

    /**
     * 使用 zip4j 创建 AES-256 原生加密 ZIP（单文件）。
     */
    private static void packZipNative(Path output, Path input, String password) throws IOException {
        ZipParameters params = new ZipParameters();
        params.setEncryptFiles(true);
        params.setEncryptionMethod(EncryptionMethod.AES);
        params.setAesKeyStrength(AesKeyStrength.KEY_STRENGTH_256);
        try (ZipFile zipFile = new ZipFile(output.toFile(), password.toCharArray())) {
            if (Files.isDirectory(input)) {
                zipFile.addFolder(input.toFile(), params);
            } else {
                zipFile.addFile(input.toFile(), params);
            }
        }
    }

    /**
     * 使用 zip4j 创建 AES-256 原生加密 ZIP（多文件，保留目录结构）。
     */
    private static void packZipEntriesNative(Path output, Path baseDir, List<Path> entries,
                                             String password) throws IOException {
        try (ZipFile zipFile = new ZipFile(output.toFile(), password.toCharArray())) {
            for (Path file : entries) {
                ZipParameters params = new ZipParameters();
                params.setEncryptFiles(true);
                params.setEncryptionMethod(EncryptionMethod.AES);
                params.setAesKeyStrength(AesKeyStrength.KEY_STRENGTH_256);
                params.setFileNameInZip(entryName(baseDir, file));
                if (Files.isDirectory(file)) {
                    zipFile.addFolder(file.toFile(), params);
                } else {
                    zipFile.addFile(file.toFile(), params);
                }
            }
        }
    }

    // ==================== ZIP 明文（commons-compress） ====================

    /**
     * 使用 commons-compress 创建明文 ZIP（STORED 模式，无加密）。
     */
    private static void packZipPlain(Path output, Path input) throws IOException {
        try (OutputStream fos = Files.newOutputStream(output);
             org.apache.commons.compress.archivers.zip.ZipArchiveOutputStream zos =
                     new org.apache.commons.compress.archivers.zip.ZipArchiveOutputStream(fos)) {
            org.apache.commons.compress.archivers.zip.ZipArchiveEntry entry =
                    new org.apache.commons.compress.archivers.zip.ZipArchiveEntry(
                            input.getFileName().toString());
            entry.setMethod(org.apache.commons.compress.archivers.zip.ZipArchiveEntry.STORED);
            long size = Files.size(input);
            entry.setSize(size);
            entry.setCompressedSize(size);
            entry.setCrc(computeCrc32(input));
            zos.putArchiveEntry(entry);
            Files.copy(input, zos);
            zos.closeArchiveEntry();
        }
    }

    /**
     * 使用 commons-compress 创建明文 ZIP（多文件，STORED 模式，无加密）。
     */
    private static void packZipEntriesPlain(Path output, Path baseDir, List<Path> entries) throws Exception {
        try (OutputStream fos = Files.newOutputStream(output);
             org.apache.commons.compress.archivers.zip.ZipArchiveOutputStream zos =
                     new org.apache.commons.compress.archivers.zip.ZipArchiveOutputStream(fos)) {
            for (Path file : entries) {
                org.apache.commons.compress.archivers.zip.ZipArchiveEntry entry =
                        new org.apache.commons.compress.archivers.zip.ZipArchiveEntry(entryName(baseDir, file));
                entry.setMethod(org.apache.commons.compress.archivers.zip.ZipArchiveEntry.STORED);
                long size = Files.size(file);
                entry.setSize(size);
                entry.setCompressedSize(size);
                entry.setCrc(computeCrc32(file));
                zos.putArchiveEntry(entry);
                Files.copy(file, zos);
                zos.closeArchiveEntry();
            }
        }
    }

    // ==================== GZ / TAR.GZ 明文 ====================

    /**
     * 打包单文件为 GZ 压缩（明文）。
     */
    private static void packGz(Path output, Path input) throws IOException {
        try (OutputStream fos = Files.newOutputStream(output);
             org.apache.commons.compress.compressors.gzip.GzipCompressorOutputStream gzos =
                     new org.apache.commons.compress.compressors.gzip.GzipCompressorOutputStream(fos);
             InputStream fin = Files.newInputStream(input)) {
            fin.transferTo(gzos);
            gzos.finish();
        }
    }

    /**
     * 打包单文件为 TAR.GZ 归档（明文）。
     */
    private static void packTarGz(Path output, Path input) throws IOException {
        try (OutputStream fos = Files.newOutputStream(output);
             GzipCompressorOutputStream gzos = new GzipCompressorOutputStream(fos);
             TarArchiveOutputStream tos = new TarArchiveOutputStream(gzos)) {
            tos.setLongFileMode(TarArchiveOutputStream.LONGFILE_POSIX);
            TarArchiveEntry entry = new TarArchiveEntry(input, input.getFileName().toString());
            entry.setSize(Files.size(input));
            tos.putArchiveEntry(entry);
            Files.copy(input, tos);
            tos.closeArchiveEntry();
            tos.finish();
        }
    }

    /**
     * 将多个文件条目写入 TAR.GZ 归档（明文）。
     */
    private static void packTarGzEntries(Path output, Path baseDir, List<Path> entries) throws Exception {
        try (OutputStream fos = Files.newOutputStream(output);
             GzipCompressorOutputStream gzos = new GzipCompressorOutputStream(fos);
             TarArchiveOutputStream tos = new TarArchiveOutputStream(gzos)) {
            tos.setLongFileMode(TarArchiveOutputStream.LONGFILE_POSIX);
            for (Path file : entries) {
                TarArchiveEntry entry = new TarArchiveEntry(file, entryName(baseDir, file));
                entry.setSize(Files.size(file));
                tos.putArchiveEntry(entry);
                Files.copy(file, tos);
                tos.closeArchiveEntry();
            }
            tos.finish();
        }
    }

    // ==================== 7Z 原生加密 ====================

    /**
     * 打包单文件为 7z 归档（支持原生密码）。
     */
    private static void pack7z(Path output, Path input, String password) throws IOException {
        boolean hasPwd = password != null && !password.isEmpty();
        try (SevenZOutputFile szos = hasPwd
                ? new SevenZOutputFile(output.toFile(), password.toCharArray())
                : new SevenZOutputFile(output.toFile())) {
            szos.setContentCompression(SevenZMethod.COPY);
            SevenZArchiveEntry entry = new SevenZArchiveEntry();
            entry.setName(input.getFileName().toString());
            entry.setSize(Files.size(input));
            szos.putArchiveEntry(entry);
            byte[] buf = new byte[8192];
            try (InputStream in = Files.newInputStream(input)) {
                int n;
                while ((n = in.read(buf)) > 0) {
                    szos.write(buf, 0, n);
                }
            }
            szos.closeArchiveEntry();
            szos.finish();
        }
    }

    /**
     * 将多个文件条目写入 7z 归档（支持原生密码）。
     */
    private static void pack7zEntries(Path output, Path baseDir, List<Path> entries,
                                      String password) throws IOException {
        boolean hasPwd = password != null && !password.isEmpty();
        try (SevenZOutputFile szos = hasPwd
                ? new SevenZOutputFile(output.toFile(), password.toCharArray())
                : new SevenZOutputFile(output.toFile())) {
            szos.setContentCompression(SevenZMethod.COPY);
            for (Path file : entries) {
                SevenZArchiveEntry entry = new SevenZArchiveEntry();
                entry.setName(entryName(baseDir, file));
                entry.setSize(Files.size(file));
                szos.putArchiveEntry(entry);
                byte[] buf = new byte[8192];
                try (InputStream in = Files.newInputStream(file)) {
                    int n;
                    while ((n = in.read(buf)) > 0) {
                        szos.write(buf, 0, n);
                    }
                }
                szos.closeArchiveEntry();
            }
            szos.finish();
        }
    }

    // ==================== 工具方法 ====================

    /**
     * 计算文件的 CRC-32 校验值（用于 ZIP STORED 模式）。
     */
    private static long computeCrc32(Path file) throws IOException {
        java.util.zip.CRC32 crc = new java.util.zip.CRC32();
        byte[] buf = new byte[8192];
        try (InputStream in = Files.newInputStream(file)) {
            int n;
            while ((n = in.read(buf)) > 0) {
                crc.update(buf, 0, n);
            }
        }
        return crc.getValue();
    }

    /**
     * 解析归档格式字符串（如 "ZIP" / "GZ" / "TAR.GZ" / "7Z" 等）。
     *
     * @param raw 格式字符串
     * @return 对应的 Format 枚举值
     */
    public static Format parseFormat(String raw) {
        return Format.valueOf(raw.toUpperCase().replace('.', '_'));
    }

    /**
     * 返回归档格式对应的文件扩展名。
     *
     * @param format 归档格式
     * @return 扩展名字符串（含前导点）
     */
    public static String extOf(Format format) {
        return switch (format) {
            case ZIP -> ".zip";
            case GZ -> ".gz";
            case TAR_GZ -> ".tar.gz";
            case _7Z -> ".7z";
        };
    }

    /**
     * 归档格式枚举。
     */
    public enum Format {
        ZIP,
        GZ,
        TAR_GZ,
        _7Z
    }
}
