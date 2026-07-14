package hbnu.project.ergoutreecrypt.fileops;

import net.lingala.zip4j.ZipFile;
import net.lingala.zip4j.model.ZipParameters;
import net.lingala.zip4j.model.enums.AesKeyStrength;
import net.lingala.zip4j.model.enums.CompressionMethod;
import net.lingala.zip4j.model.enums.EncryptionMethod;
import org.apache.commons.compress.archivers.sevenz.SevenZArchiveEntry;
import org.apache.commons.compress.archivers.sevenz.SevenZMethod;
import org.apache.commons.compress.archivers.sevenz.SevenZOutputFile;
import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveOutputStream;
import org.apache.commons.compress.compressors.gzip.GzipCompressorOutputStream;

import hbnu.project.ergoutreecrypt.i18n.Messages;
import hbnu.project.ergoutreecrypt.settings.SettingsManager;
import hbnu.project.ergoutreecrypt.volume.ProgressPhase;
import hbnu.project.ergoutreecrypt.volume.ProgressReporter;

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
import java.util.List;

/**
 * 归档打包工具。
 *
 * <p>支持 ZIP / GZ / TAR.GZ / 7Z 四种格式。密码保护策略：
 * <ul>
 *   <li><b>ZIP：</b>使用 zip4j 原生 AES-256 加密，外部工具（Bandizip / 7-Zip）
 *       可正确提示密码；不受工具特有加密开关影响。</li>
 *   <li><b>GZ / TAR.GZ / 7Z：</b>无（或放弃）原生密码，采用本工具特有的整体
 *       AES-256-CTR 加密包裹（MAGIC + salt + IV + ciphertext），仅能用本工具解密。
 *       是否允许对这三种格式加密，由
 *       {@link SettingsManager#isArchiveCustomEncryption()} 控制（默认关闭）。</li>
 * </ul>
 *
 * <p>归档密码解析见 {@link #resolveArchivePassword(String, String, Format)}，
 * 是否在归档密码为空时回退加密密码由
 * {@link SettingsManager#isArchivePasswordFallback()} 控制（默认关闭）。
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

    /**
     * 解析实际用于归档保护的密码（不区分格式，兼容旧调用）。
     *
     * <p>等价于 {@link #resolveArchivePassword(String, String, Format)} 传入 {@code null} 格式，
     * 即不做「非 ZIP 格式工具特有加密」开关校验，仅按显式密码 + 回退开关解析。
     *
     * @param archivePassword    归档密码（可为 null/空）
     * @param encryptionPassword 文件加密密码（可为 null/空）
     * @return 非空密码，或 null 表示不保护归档
     */
    public static String resolveArchivePassword(String archivePassword, String encryptionPassword) {
        return resolveArchivePassword(archivePassword, encryptionPassword, null);
    }

    /**
     * 解析实际用于归档保护的密码。
     *
     * <p>规则：
     * <ul>
     *   <li>对 GZ / TAR.GZ / 7Z：仅当
     *       {@link SettingsManager#isArchiveCustomEncryption()} 开启时才允许加密，
     *       否则一律返回 null（明文归档）。</li>
     *   <li>显式归档密码非空时直接采用。</li>
     *   <li>归档密码为空时，仅当
     *       {@link SettingsManager#isArchivePasswordFallback()} 开启才回退到加密密码。</li>
     * </ul>
     * ZIP 始终可加密，不受工具特有加密开关影响。
     *
     * @param archivePassword    归档密码（可为 null/空）
     * @param encryptionPassword 文件加密密码（可为 null/空）
     * @param format             归档格式；null 表示不做格式校验
     * @return 非空密码，或 null 表示不保护归档
     */
    public static String resolveArchivePassword(String archivePassword, String encryptionPassword,
                                                Format format) {
        // 非 ZIP 格式未开启工具特有加密时，不允许任何密码
        if (isCustomEncryptionFormat(format) && !SettingsManager.isArchiveCustomEncryption()) {
            return null;
        }
        if (archivePassword != null && !archivePassword.isEmpty()) {
            return archivePassword;
        }
        if (SettingsManager.isArchivePasswordFallback()
                && encryptionPassword != null
                && !encryptionPassword.isEmpty()) {
            return encryptionPassword;
        }
        return null;
    }

    /**
     * 判断格式是否属于「工具特有加密」范畴（GZ / TAR.GZ / 7Z）。
     *
     * @param format 归档格式，可为 null
     * @return true 表示该格式加密受工具特有加密开关控制
     */
    public static boolean isCustomEncryptionFormat(Format format) {
        return format == Format.GZ || format == Format.TAR_GZ || format == Format._7Z;
    }

    /**
     * 判断路径是否为受原生密码保护的 ZIP（zip4j AES）。
     *
     * <p>7Z 已不再使用原生加密（改为本工具 MAGIC 整体包裹），故此方法仅检测 ZIP。
     *
     * @param archive 归档路径
     * @return true 表示 ZIP 内容受原生密码保护
     * @throws IOException 检测失败
     */
    public static boolean isNativelyPasswordProtected(Path archive) throws IOException {
        if (archive == null || !Files.isRegularFile(archive)) {
            return false;
        }
        String name = archive.getFileName().toString().toLowerCase();
        if (name.endsWith(".zip")) {
            try (ZipFile zf = new ZipFile(archive.toFile())) {
                return zf.isEncrypted();
            } catch (Exception e) {
                throw new IOException("Failed to inspect ZIP encryption: " + e.getMessage(), e);
            }
        }
        return false;
    }

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
        pack(output, input, format, password, null);
    }

    /**
     * 将单个文件或目录打包为指定格式的归档，并回调进度。
     *
     * @param output   输出归档路径
     * @param input    输入文件或目录
     * @param format   归档格式
     * @param password 加密密码（可为 null/空）
     * @param reporter 进度回调（可为 null）
     * @throws IOException 打包或加密失败
     */
    public static void pack(Path output, Path input, Format format, String password,
                            ProgressReporter reporter) throws IOException {
        reportArchive(reporter, 0f, Messages.get("status.archiving"));
        boolean hasPwd = password != null && !password.isEmpty();
        // ZIP 走原生 AES；GZ / TAR.GZ / 7Z 用本工具特有的整体 AES 包裹（MAGIC）
        if (hasPwd && format == Format.ZIP) {
            packZipNative(output, input, password);
            reportArchive(reporter, 1f, Messages.get("status.archiving"));
            return;
        }
        // 无密码；或需要整体包裹的格式（GZ / TAR.GZ / 7Z）
        Path workOutput = hasPwd ? Files.createTempFile("ergou-plain-", ".tmp") : output;
        try {
            switch (format) {
                case ZIP -> packZipPlain(workOutput, input);
                case GZ -> packGz(workOutput, input);
                case TAR_GZ -> packTarGz(workOutput, input);
                case _7Z -> pack7z(workOutput, input);
                default -> throw new IllegalArgumentException("Unsupported format: " + format);
            }
            reportArchive(reporter, hasPwd ? 0.7f : 0.95f, Messages.get("status.archiving"));
            if (hasPwd) {
                wrapEncrypted(workOutput, output, password);
            }
            reportArchive(reporter, 1f, Messages.get("status.archiving"));
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
        packEntries(output, baseDir, entries, format, password, null);
    }

    /**
     * 将多个文件打包为单个归档，并按条目回调进度。
     *
     * @param output   输出归档路径
     * @param baseDir  计算条目相对名的基准目录
     * @param entries  要打入归档的文件路径列表
     * @param format   归档格式
     * @param password 加密密码（可为 null/空）
     * @param reporter 进度回调（可为 null）
     * @throws IOException 打包或加密失败
     */
    public static void packEntries(Path output, Path baseDir, List<Path> entries,
                                   Format format, String password,
                                   ProgressReporter reporter) throws IOException {
        if (entries == null || entries.isEmpty()) {
            throw new IOException("no entries to archive");
        }

        Format effective = (format == Format.GZ && entries.size() > 1) ? Format.TAR_GZ : format;
        boolean hasPwd = password != null && !password.isEmpty();
        reportArchive(reporter, 0f,
                Messages.format("status.archiving.progress", 0, entries.size()));

        // ZIP 走原生 AES；GZ / TAR.GZ / 7Z 用本工具特有的整体 AES 包裹（MAGIC）
        if (hasPwd && effective == Format.ZIP) {
            packZipEntriesNative(output, baseDir, entries, password, reporter);
            return;
        }
        // 无密码；或需要整体包裹的格式（GZ / TAR.GZ / 7Z）
        Path workOutput = hasPwd ? Files.createTempFile("ergou-plain-", ".tmp") : output;
        try {
            switch (effective) {
                case ZIP -> packZipEntriesPlain(workOutput, baseDir, entries, reporter);
                case GZ -> {
                    packGz(workOutput, entries.getFirst());
                    reportArchive(reporter, hasPwd ? 0.7f : 1f, Messages.get("status.archiving"));
                }
                case TAR_GZ -> packTarGzEntries(workOutput, baseDir, entries, reporter);
                case _7Z -> pack7zEntries(workOutput, baseDir, entries, reporter);
                default -> throw new IllegalArgumentException("Unsupported format: " + effective);
            }
            if (hasPwd) {
                wrapEncrypted(workOutput, output, password);
            }
            reportArchive(reporter, 1f, Messages.get("status.archiving"));
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
     * 上报归档阶段进度。
     *
     * @param reporter 进度回调，可为 null
     * @param fraction 完成比例
     * @param status   状态文案
     */
    private static void reportArchive(ProgressReporter reporter, float fraction, String status) {
        if (reporter == null) {
            return;
        }
        reporter.setStatus(status, ProgressPhase.ARCHIVE);
        reporter.setProgress(fraction, "", ProgressPhase.ARCHIVE);
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
        ZipParameters params = newZipAesParameters();
        try (ZipFile zipFile = new ZipFile(output.toFile(), password.toCharArray())) {
            if (Files.isDirectory(input)) {
                zipFile.addFolder(input.toFile(), params);
            } else {
                zipFile.addFile(input.toFile(), params);
            }
        }
        assertZipNativelyEncrypted(output);
    }

    /**
     * 使用 zip4j 创建 AES-256 原生加密 ZIP（多文件），并上报进度。
     *
     * @param output   输出路径
     * @param baseDir  相对路径基准
     * @param entries  条目列表
     * @param password 密码
     * @param reporter 进度回调，可为 null
     * @throws IOException 打包失败
     */
    private static void packZipEntriesNative(Path output, Path baseDir, List<Path> entries,
                                             String password, ProgressReporter reporter)
            throws IOException {
        int total = entries.size();
        int done = 0;
        try (ZipFile zipFile = new ZipFile(output.toFile(), password.toCharArray())) {
            for (Path file : entries) {
                ZipParameters params = newZipAesParameters();
                params.setFileNameInZip(entryName(baseDir, file));
                if (Files.isDirectory(file)) {
                    zipFile.addFolder(file.toFile(), params);
                } else {
                    zipFile.addFile(file.toFile(), params);
                }
                done++;
                reportArchive(reporter, (float) done / total,
                        Messages.format("status.archiving.progress", done, total));
            }
        }
        assertZipNativelyEncrypted(output);
    }

    /**
     * 构造 WinZip-AES-256 加密参数（DEFLATE，兼容 7-Zip / Bandizip）。
     *
     * @return zip4j 参数
     */
    private static ZipParameters newZipAesParameters() {
        ZipParameters params = new ZipParameters();
        params.setCompressionMethod(CompressionMethod.DEFLATE);
        params.setEncryptFiles(true);
        params.setEncryptionMethod(EncryptionMethod.AES);
        params.setAesKeyStrength(AesKeyStrength.KEY_STRENGTH_256);
        return params;
    }

    /**
     * 打包后自检：确认 ZIP 确实带有原生加密标志，防止静默生成明文包。
     *
     * @param zip ZIP 路径
     * @throws IOException 未加密或无法检测
     */
    private static void assertZipNativelyEncrypted(Path zip) throws IOException {
        try (ZipFile zf = new ZipFile(zip.toFile())) {
            if (!zf.isEncrypted()) {
                throw new IOException("ZIP native encryption failed: archive is not encrypted");
            }
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException("ZIP native encryption verification failed: " + e.getMessage(), e);
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
     * 使用 commons-compress 创建明文 ZIP（多文件），并上报进度。
     *
     * @param output   输出路径
     * @param baseDir  相对路径基准
     * @param entries  条目列表
     * @param reporter 进度回调，可为 null
     * @throws Exception 打包失败
     */
    private static void packZipEntriesPlain(Path output, Path baseDir, List<Path> entries,
                                            ProgressReporter reporter) throws Exception {
        int total = entries.size();
        int done = 0;
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
                done++;
                reportArchive(reporter, (float) done / total,
                        Messages.format("status.archiving.progress", done, total));
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
     * 将多个文件条目写入 TAR.GZ 归档，并上报进度。
     *
     * @param output   输出路径
     * @param baseDir  相对路径基准
     * @param entries  条目列表
     * @param reporter 进度回调，可为 null
     * @throws Exception 打包失败
     */
    private static void packTarGzEntries(Path output, Path baseDir, List<Path> entries,
                                         ProgressReporter reporter) throws Exception {
        int total = entries.size();
        int done = 0;
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
                done++;
                reportArchive(reporter, (float) done / total,
                        Messages.format("status.archiving.progress", done, total));
            }
            tos.finish();
        }
    }

    // ==================== 7Z 明文打包 ====================

    /**
     * 打包单文件为 7z 归档（明文，不含原生密码）。
     *
     * <p>7Z 已放弃原生 AES：若需要密码，由外层 {@link #wrapEncrypted} 整体包裹。
     * 内容方法用 COPY，避免对已加密载荷再做 LZMA2 造成极慢/膨胀。
     *
     * @param output 输出路径
     * @param input  输入文件
     * @throws IOException 打包失败
     */
    private static void pack7z(Path output, Path input) throws IOException {
        try (SevenZOutputFile szos = new SevenZOutputFile(output.toFile())) {
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
     * 将多个文件条目写入 7z 归档（明文），并上报进度。
     *
     * @param output   输出路径
     * @param baseDir  相对路径基准
     * @param entries  条目列表
     * @param reporter 进度回调，可为 null
     * @throws IOException 打包失败
     */
    private static void pack7zEntries(Path output, Path baseDir, List<Path> entries,
                                      ProgressReporter reporter) throws IOException {
        int total = entries.size();
        int done = 0;
        try (SevenZOutputFile szos = new SevenZOutputFile(output.toFile())) {
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
                done++;
                reportArchive(reporter, (float) done / total,
                        Messages.format("status.archiving.progress", done, total));
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
        String name = raw.toUpperCase().replace('.', '_');
        // "7Z" maps to _7Z 枚举常量（Java 标识符不能以数字开头）
        if ("7Z".equals(name)) {
            return Format._7Z;
        }
        return Format.valueOf(name);
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
