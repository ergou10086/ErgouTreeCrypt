package hbnu.project.ergoutreecrypt.fileops;

import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveOutputStream;
import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;
import org.apache.commons.compress.archivers.zip.ZipArchiveOutputStream;
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
 * <p>支持 ZIP / GZ / TAR.GZ 三种格式。若提供密码，则先对文件做 AES-256-CTR 加密后再写入归档。
 * 加密文件格式：MAGIC(12) + salt(16) + IV(16) + ciphertext。
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
        try {
            switch (format) {
                case ZIP -> packZip(output, input, password);
                case GZ -> packGz(output, input, password);
                case TAR_GZ -> packTarGz(output, input, password);
                default -> throw new IllegalArgumentException("Unsupported format: " + format);
            }
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException("Archive encryption failed: " + e.getMessage(), e);
        }
    }

    /**
     * 将多个文件打包为单个归档。
     *
     * <p>每个条目使用相对于 {@code baseDir} 的相对路径作为归档内条目名以保留目录结构。
     * 若设置了密码，则对每个条目内容做 AES-256-CTR 加密。
     * GZ 格式天然仅支持单文件流，多文件时自动按 TAR.GZ 处理。
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

        // GZ 仅支持单文件，多文件时自动升级为 TAR.GZ
        Format effective = (format == Format.GZ && entries.size() > 1) ? Format.TAR_GZ : format;
        try {
            switch (effective) {
                case ZIP -> packZipEntries(output, baseDir, entries, password);
                case GZ -> packGz(output, entries.getFirst(), password);
                case TAR_GZ -> packTarGzEntries(output, baseDir, entries, password);
                default -> throw new IllegalArgumentException("Unsupported format: " + effective);
            }
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException("Archive encryption failed: " + e.getMessage(), e);
        }
    }

    /**
     * 生成归档内条目名。相对 baseDir；若加密则追加 .enc 后缀。
     */
    private static String entryName(Path baseDir, Path file, boolean encrypted) {
        String rel;
        if (baseDir != null && file.startsWith(baseDir)) {
            rel = baseDir.relativize(file).toString().replace('\\', '/');
        } else {
            rel = file.getFileName().toString();
        }
        return encrypted ? rel + ".enc" : rel;
    }

    /**
     * 将多个文件条目写入 ZIP 归档（STORED 模式）。
     */
    private static void packZipEntries(Path output, Path baseDir, List<Path> entries,
                                       String password) throws Exception {
        boolean hasPwd = password != null && !password.isEmpty();
        List<Path> temps = new ArrayList<>();
        try (OutputStream fos = Files.newOutputStream(output);
             ZipArchiveOutputStream zos = new ZipArchiveOutputStream(fos)) {
            for (Path file : entries) {
                Path src = maybeEncrypt(file, password);
                if (src != file) {
                    temps.add(src);
                }
                ZipArchiveEntry entry = new ZipArchiveEntry(entryName(baseDir, file, hasPwd));
                entry.setMethod(ZipArchiveEntry.STORED);
                long size = Files.size(src);
                entry.setSize(size);
                entry.setCompressedSize(size);
                entry.setCrc(computeCrc32(src));
                zos.putArchiveEntry(entry);
                Files.copy(src, zos);
                zos.closeArchiveEntry();
            }
        } finally {
            // 清理临时加密文件
            for (Path t : temps) {
                Files.deleteIfExists(t);
            }
        }
    }

    /**
     * 将多个文件条目写入 TAR.GZ 归档。
     */
    private static void packTarGzEntries(Path output, Path baseDir, List<Path> entries,
                                         String password) throws Exception {
        boolean hasPwd = password != null && !password.isEmpty();
        List<Path> temps = new ArrayList<>();
        try (OutputStream fos = Files.newOutputStream(output);
             GzipCompressorOutputStream gzos = new GzipCompressorOutputStream(fos);
             TarArchiveOutputStream tos = new TarArchiveOutputStream(gzos)) {
            tos.setLongFileMode(TarArchiveOutputStream.LONGFILE_POSIX);
            for (Path file : entries) {
                Path src = maybeEncrypt(file, password);
                if (src != file) {
                    temps.add(src);
                }
                TarArchiveEntry entry = new TarArchiveEntry(src, entryName(baseDir, file, hasPwd));
                entry.setSize(Files.size(src));
                tos.putArchiveEntry(entry);
                Files.copy(src, tos);
                tos.closeArchiveEntry();
            }
            tos.finish();
        } finally {
            for (Path t : temps) {
                Files.deleteIfExists(t);
            }
        }
    }

    /**
     * 若提供了密码，则先对输入文件做 AES-256-CTR 加密并写入临时文件，
     * 返回临时文件路径。否则返回原始路径。
     */
    private static Path maybeEncrypt(Path input, String password) throws Exception {
        if (password == null || password.isEmpty()) {
            return input;
        }

        // 生成随机 salt 与 IV
        byte[] salt = new byte[SALT_SIZE];
        new SecureRandom().nextBytes(salt);
        byte[] iv = new byte[IV_SIZE];
        new SecureRandom().nextBytes(iv);

        // PBKDF2 派生 AES 密钥
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, PBKDF2_ITERATIONS, KEY_SIZE * 8);
        SecretKeySpec key = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");

        // AES-256-CTR 加密
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));

        // 写入：魔数 + salt + IV + 密文
        Path tmp = Files.createTempFile("ergou-archive-", ".tmp");
        try (OutputStream fos = Files.newOutputStream(tmp)) {
            fos.write(MAGIC);
            fos.write(salt);
            fos.write(iv);
            try (CipherOutputStream cos = new CipherOutputStream(fos, cipher);
                 InputStream fin = Files.newInputStream(input)) {
                fin.transferTo(cos);
            }
        }
        return tmp;
    }

    /**
     * 打包单文件为 ZIP 归档（STORED 模式）。
     */
    private static void packZip(Path output, Path input, String password) throws IOException {
        Path src;
        try {
            src = maybeEncrypt(input, password);
        } catch (Exception e) {
            throw new IOException("Archive encryption failed: " + e.getMessage(), e);
        }
        try {
            try (OutputStream fos = Files.newOutputStream(output);
                 ZipArchiveOutputStream zos = new ZipArchiveOutputStream(fos)) {

                String entryName = password != null && !password.isEmpty()
                        ? input.getFileName().toString() + ".enc" : input.getFileName().toString();
                ZipArchiveEntry entry = new ZipArchiveEntry(entryName);
                entry.setMethod(ZipArchiveEntry.STORED);
                long size = Files.size(src);
                entry.setSize(size);
                entry.setCompressedSize(size);
                entry.setCrc(computeCrc32(src));
                zos.putArchiveEntry(entry);
                Files.copy(src, zos);
                zos.closeArchiveEntry();
            }
        } finally {
            if (src != input) {
                Files.deleteIfExists(src);
            }
        }
    }

    /**
     * 打包单文件为 GZ 压缩。
     */
    private static void packGz(Path output, Path input, String password) throws IOException {
        Path src;
        try {
            src = maybeEncrypt(input, password);
        } catch (Exception e) {
            throw new IOException("Archive encryption failed: " + e.getMessage(), e);
        }
        try {
            try (OutputStream fos = Files.newOutputStream(output);
                 GzipCompressorOutputStream gzos = new GzipCompressorOutputStream(fos);
                 InputStream fin = Files.newInputStream(src)) {
                fin.transferTo(gzos);
                gzos.finish();
            }
        } finally {
            if (src != input) {
                Files.deleteIfExists(src);
            }
        }
    }

    /**
     * 打包单文件为 TAR.GZ 归档。
     */
    private static void packTarGz(Path output, Path input, String password) throws IOException {
        Path src;
        try {
            src = maybeEncrypt(input, password);
        } catch (Exception e) {
            throw new IOException("Archive encryption failed: " + e.getMessage(), e);
        }
        try {
            try (OutputStream fos = Files.newOutputStream(output);
                 GzipCompressorOutputStream gzos = new GzipCompressorOutputStream(fos);
                 TarArchiveOutputStream tos = new TarArchiveOutputStream(gzos)) {
                tos.setLongFileMode(TarArchiveOutputStream.LONGFILE_POSIX);
                String entryName = src.getFileName().toString();
                TarArchiveEntry entry = new TarArchiveEntry(src, entryName);
                entry.setSize(Files.size(src));
                tos.putArchiveEntry(entry);
                Files.copy(src, tos);
                tos.closeArchiveEntry();
                tos.finish();
            }
        } finally {
            if (src != input) {
                Files.deleteIfExists(src);
            }
        }
    }

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
     * 解析归档格式字符串（如 "ZIP" / "GZ" / "TAR.GZ" / "TAR_GZ"）。
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
        };
    }

    /**
     * 归档格式枚举。
     */
    public enum Format {
        ZIP,
        GZ,
        TAR_GZ
    }
}
