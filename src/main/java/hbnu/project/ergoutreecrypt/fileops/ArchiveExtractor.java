package hbnu.project.ergoutreecrypt.fileops;

import net.lingala.zip4j.ZipFile;
import net.lingala.zip4j.model.FileHeader;
import org.apache.commons.compress.archivers.ArchiveEntry;
import org.apache.commons.compress.archivers.ArchiveInputStream;
import org.apache.commons.compress.archivers.sevenz.SevenZArchiveEntry;
import org.apache.commons.compress.archivers.sevenz.SevenZFile;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;
import org.apache.commons.compress.archivers.zip.ZipArchiveInputStream;
import org.apache.commons.compress.compressors.gzip.GzipCompressorInputStream;

import hbnu.project.ergoutreecrypt.i18n.Messages;
import hbnu.project.ergoutreecrypt.volume.ProgressPhase;
import hbnu.project.ergoutreecrypt.volume.ProgressReporter;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * 归档解压工具，支持自动检测并解密加密归档。
 *
 * <p>支持多种加密模式：
 * <ul>
 *   <li><b>原生加密（ZIP）：</b>使用 zip4j 自带 AES-256 加密，
 *       外部工具（Bandizip / 7-Zip）可正确提示密码并解压。</li>
 *   <li><b>整体包裹加密（GZ / TAR.GZ / 7Z）：</b>文件以魔数头
 *       {@code EGTC_ARCHV1} 开头，整体解密后得到明文归档再解压，
 *       需本工具解密。7Z 已不再使用原生 AES。</li>
 *   <li><b>旧版逐条目加密：</b>归档内包含 {@code .enc} 后缀条目，
 *       每个条目单独解密（向后兼容）。</li>
 *   <li><b>旧版 7Z 原生加密：</b>仍向后兼容，解压时可传入密码尝试打开。</li>
 * </ul>
 *
 * @author ErgouTree
 */
public final class ArchiveExtractor {

    /**
     * 加密文件魔数标识（12 字节）。
     */
    private static final byte[] MAGIC = "EGTC_ARCHV1\0".getBytes();

    /**
     * AES 密钥长度（32 字节，AES-256）。
     */
    private static final int KEY_SIZE = 32;

    /**
     * PBKDF2-HMAC-SHA256 迭代次数。
     */
    private static final int PBKDF2_ITERATIONS = 100_000;

    private ArchiveExtractor() {
    }

    /**
     * 判断文件是否为支持的归档格式（根据扩展名）。
     *
     * @param file 文件路径
     * @return 若扩展名匹配支持的归档格式则返回 true
     */
    public static boolean isArchive(Path file) {
        String name = file.getFileName().toString().toLowerCase();
        return name.endsWith(".zip")
                || name.endsWith(".gz") || name.endsWith(".tgz")
                || name.endsWith(".tar.gz")
                || name.endsWith(".rar")
                || name.endsWith(".7z");
    }

    /**
     * 检测文件是否以 EGTC_ARCHV1 魔数开头，即是否为本工具整体包裹加密的文件。
     *
     * @param file 待检测的文件路径
     * @return 若文件头匹配魔数则返回 true
     */
    public static boolean isEncryptedFile(Path file) {
        try (InputStream in = Files.newInputStream(file)) {
            byte[] buf = new byte[MAGIC.length];
            int n = in.read(buf);
            return n == MAGIC.length && Arrays.equals(buf, MAGIC);
        } catch (IOException e) {
            return false;
        }
    }

    /**
     * 快速检测归档是否需要密码。
     *
     * <p>检测顺序：
     * <ol>
     *   <li>若文件以 MAGIC 开头 → 整体包裹加密</li>
     *   <li>ZIP：zip4j 原生加密检测 + .enc 条目检测</li>
     *   <li>7z：尝试无密码打开 → 原生加密检测 + .enc 条目检测</li>
     *   <li>TAR.GZ / GZ：扫描 .enc 条目</li>
     * </ol>
     *
     * @param archive 归档文件路径
     * @return 若需要密码则返回 true
     * @throws IOException 读取错误
     */
    public static boolean hasEncryptedEntries(Path archive) throws IOException {
        // 整体加密包裹检测
        if (isEncryptedFile(archive)) {
            return true;
        }

        String name = archive.getFileName().toString().toLowerCase();
        if (name.endsWith(".zip")) {
            return hasEncryptedZipEntries(archive);
        }
        if (name.endsWith(".tar.gz") || name.endsWith(".tgz")) {
            return hasEncryptedTarGzEntries(archive);
        }
        if (name.endsWith(".7z")) {
            return hasEncrypted7zEntries(archive);
        }
        if (name.endsWith(".gz")) {
            String outName = name;
            if (outName.endsWith(".gz")) {
                outName = outName.substring(0, outName.length() - 3);
            }
            return outName.toLowerCase().endsWith(".enc");
        }
        return false;
    }

    /**
     * ZIP 加密检测：先通过 zip4j 检测原生加密，再检测旧版 .enc 条目。
     */
    private static boolean hasEncryptedZipEntries(Path archive) throws IOException {
        // 新版：zip4j 原生加密
        try {
            try (ZipFile zf = new ZipFile(archive.toFile())) {
                if (zf.isEncrypted()) {
                    return true;
                }
            }
        } catch (Exception ignored) {
            // 无法打开可能是损坏或加密，保守返回 true
            return true;
        }
        // 旧版：.enc 条目（commons-compress 扫描）
        try (java.util.zip.ZipFile zf = new java.util.zip.ZipFile(archive.toFile())) {
            java.util.Enumeration<? extends java.util.zip.ZipEntry> entries = zf.entries();
            while (entries.hasMoreElements()) {
                if (entries.nextElement().getName().toLowerCase().endsWith(".enc")) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * TAR.GZ 流式扫描：边解压边遍历，找到第一个 .enc 后缀条目即返回。
     */
    private static boolean hasEncryptedTarGzEntries(Path archive) throws IOException {
        try (InputStream fin = Files.newInputStream(archive);
             GzipCompressorInputStream gzis = new GzipCompressorInputStream(fin);
             TarArchiveInputStream tais = new TarArchiveInputStream(gzis)) {
            ArchiveEntry entry;
            while ((entry = tais.getNextEntry()) != null) {
                if (entry.getName().toLowerCase().endsWith(".enc")) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * 7z 加密检测。
     *
     * <p>新版加密的 7Z 以 MAGIC 头整体包裹，已在 {@link #hasEncryptedEntries} 前置命中。
     * 此处针对明文 7Z：检测旧版原生 AES（向后兼容）与旧版 {@code .enc} 条目。
     *
     * @param archive 7z 路径
     * @return 是否需要密码
     * @throws IOException 读取错误
     */
    private static boolean hasEncrypted7zEntries(Path archive) throws IOException {
        try {
            return isLegacyNative7zEncrypted(archive)
                    || scan7zLegacyEncEntries(archive);
        } catch (IOException e) {
            // 无法判定时按需密码处理，避免静默失败
            return true;
        }
    }

    /**
     * 检测旧版原生 AES 加密的 7Z（向后兼容）：原生 AES 下可无密码列出条目，
     * 需尝试读取内容流；读取抛异常则视为加密。
     *
     * @param archive 7z 路径
     * @return 是否为旧版原生加密 7Z
     */
    private static boolean isLegacyNative7zEncrypted(Path archive) {
        try (SevenZFile szf = SevenZFile.builder().setFile(archive.toFile()).get()) {
            for (SevenZArchiveEntry entry : szf.getEntries()) {
                if (entry.isDirectory() || !entry.hasStream()) {
                    continue;
                }
                try (InputStream in = szf.getInputStream(entry)) {
                    in.readAllBytes();
                    return false;
                } catch (IOException e) {
                    return true;
                }
            }
            return false;
        } catch (IOException e) {
            return true;
        }
    }

    /**
     * 扫描 7z 内是否存在旧版 .enc 条目名。
     *
     * @param archive 7z 路径
     * @return 是否含 .enc 后缀条目
     * @throws IOException 打开失败
     */
    private static boolean scan7zLegacyEncEntries(Path archive) throws IOException {
        try (SevenZFile szf = SevenZFile.builder().setFile(archive.toFile()).get()) {
            for (SevenZArchiveEntry entry : szf.getEntries()) {
                if (entry.getName().toLowerCase().endsWith(".enc")) {
                    return true;
                }
            }
        }
        return false;
    }

    // ==================== 公共解压入口 ====================

    /**
     * 解压归档到目标目录，保留内部条目名与目录结构（无进度反馈）。
     *
     * @param archive  归档文件路径
     * @param destDir  解压目标目录
     * @param password 解密密码（可为 null/空）
     * @return 解压后的文件路径列表
     * @throws IOException               I/O 错误或密码错误
     * @throws PasswordNeededException   若遇到加密文件但未提供密码
     */
    public static List<Path> extractPreserving(Path archive, Path destDir, String password) throws IOException {
        return extractPreserving(archive, destDir, password, null);
    }

    /**
     * 解压归档到目标目录（带进度反馈）。
     */
    public static List<Path> extractPreserving(Path archive, Path destDir, String password,
                                               ProgressReporter reporter) throws IOException {
        Files.createDirectories(destDir);

        // 检测整体加密包裹（GZ / TAR.GZ）
        Path actualArchive = archive;
        Path tempDecrypted = null;
        if (isEncryptedFile(archive)) {
            if (password == null || password.isEmpty()) {
                throw PasswordNeededException.of(archive);
            }
            tempDecrypted = Files.createTempFile("ergou-outer-dec-", archiveExt(archive));
            decryptFileTo(archive, tempDecrypted, password);
            actualArchive = tempDecrypted;
        }

        try {
            String name = actualArchive.getFileName().toString().toLowerCase();
            List<Path> rawFiles;
            if (name.endsWith(".zip")) {
                rawFiles = extractZip(actualArchive, destDir, password, reporter);
            } else if (name.endsWith(".tar.gz") || name.endsWith(".tgz")) {
                rawFiles = extractTarGz(actualArchive, destDir, reporter);
            } else if (name.endsWith(".7z")) {
                rawFiles = extract7z(actualArchive, destDir, password, reporter);
            } else if (name.endsWith(".gz")) {
                rawFiles = extractGz(actualArchive, destDir, reporter);
            } else {
                throw new IOException("Unsupported archive format: " + name);
            }

            // 对旧版 .enc 逐条目加密进行解密（向后兼容）
            return decryptLegacyEntries(rawFiles, password, reporter);
        } finally {
            if (tempDecrypted != null) {
                Files.deleteIfExists(tempDecrypted);
            }
        }
    }

    /**
     * 解压归档到目标目录。
     */
    public static List<Path> extract(Path archive, Path destDir, String password) throws IOException {
        Files.createDirectories(destDir);

        // 检测整体加密包裹（GZ / TAR.GZ）
        Path actualArchive = archive;
        Path tempDecrypted = null;
        if (isEncryptedFile(archive)) {
            if (password == null || password.isEmpty()) {
                throw PasswordNeededException.of(archive);
            }
            tempDecrypted = Files.createTempFile("ergou-outer-dec-", archiveExt(archive));
            decryptFileTo(archive, tempDecrypted, password);
            actualArchive = tempDecrypted;
        }

        try {
            String name = actualArchive.getFileName().toString().toLowerCase();
            List<Path> rawFiles;
            if (name.endsWith(".zip")) {
                rawFiles = extractZip(actualArchive, destDir, password);
            } else if (name.endsWith(".tar.gz") || name.endsWith(".tgz")) {
                rawFiles = extractTarGz(actualArchive, destDir);
            } else if (name.endsWith(".7z")) {
                rawFiles = extract7z(actualArchive, destDir, password);
            } else if (name.endsWith(".gz")) {
                rawFiles = extractGz(actualArchive, destDir);
            } else if (name.endsWith(".rar")) {
                throw new IOException("RAR extraction requires additional setup.");
            } else {
                throw new IOException("Unsupported archive format: " + name);
            }

            // 旧版 .enc 解密
            List<Path> result = new ArrayList<>();
            for (Path f : rawFiles) {
                if (isEncryptedFile(f)) {
                    if (password == null || password.isEmpty()) {
                        throw PasswordNeededException.of(f);
                    }
                    Path decrypted = decryptFile(f, password);
                    Files.deleteIfExists(f);
                    result.add(decrypted);
                } else {
                    result.add(f);
                }
            }
            return result;
        } finally {
            if (tempDecrypted != null) {
                Files.deleteIfExists(tempDecrypted);
            }
        }
    }

    // ==================== ZIP 解压 ====================

    /**
     * 解压 ZIP 归档（无进度）。
     */
    private static List<Path> extractZip(Path archive, Path destDir, String password) throws IOException {
        return extractZip(archive, destDir, password, null);
    }

    /**
     * 解压 ZIP 归档（带进度）。
     *
     * <p>有密码时优先使用 zip4j 解压（支持原生 AES-256 加密 ZIP）；
     * 无密码时使用 commons-compress 流式解压。
     */
    private static List<Path> extractZip(Path archive, Path destDir, String password,
                                         ProgressReporter reporter) throws IOException {
        boolean hasPwd = password != null && !password.isEmpty();
        if (hasPwd) {
            try {
                return extractZipWithZip4j(archive, destDir, password, reporter);
            } catch (Exception e) {
                // zip4j 失败（可能是旧版 .enc 格式或损坏），回退到 commons-compress
                if (e instanceof IOException ioe) {
                    throw ioe;
                }
            }
        }
        return extractZipWithCompress(archive, destDir, reporter);
    }

    /**
     * 使用 zip4j 解压 ZIP（支持原生 AES-256 加密）。
     */
    private static List<Path> extractZipWithZip4j(Path archive, Path destDir, String password,
                                                   ProgressReporter reporter) throws IOException {
        List<Path> files = new ArrayList<>();
        try (ZipFile zipFile = new ZipFile(archive.toFile(), password.toCharArray())) {
            List<FileHeader> headers = zipFile.getFileHeaders();
            int total = headers.size();
            int extracted = 0;
            for (FileHeader header : headers) {
                if (header.isDirectory()) {
                    Files.createDirectories(destDir.resolve(header.getFileName()));
                    extracted++;
                    continue;
                }
                Path outPath = destDir.resolve(header.getFileName()).normalize();
                if (!outPath.startsWith(destDir)) {
                    throw new IOException("Bad archive entry (zip-slip): " + header.getFileName());
                }
                Files.createDirectories(outPath.getParent());
                try (InputStream in = zipFile.getInputStream(header);
                     OutputStream fos = Files.newOutputStream(outPath)) {
                    in.transferTo(fos);
                }
                files.add(outPath);
                extracted++;
                if (reporter != null && total > 0) {
                    reporter.setStatus(Messages.format("status.extracting.progress", extracted, total),
                            ProgressPhase.ARCHIVE);
                    reporter.setProgress((float) extracted / total, "", ProgressPhase.ARCHIVE);
                }
            }
        }
        return files;
    }

    /**
     * 使用 commons-compress 流式解压 ZIP（无加密）。
     */
    private static List<Path> extractZipWithCompress(Path archive, Path destDir,
                                                      ProgressReporter reporter) throws IOException {
        List<Path> files = new ArrayList<>();
        int totalEntries = 0;
        try (java.util.zip.ZipFile zf = new java.util.zip.ZipFile(archive.toFile())) {
            totalEntries = zf.size();
        }
        int extracted = 0;
        try (InputStream fin = Files.newInputStream(archive);
             BufferedInputStream bis = new BufferedInputStream(fin);
             ArchiveInputStream<?> ais = new ZipArchiveInputStream(bis, "UTF-8", false, true)) {
            ArchiveEntry entry;
            while ((entry = ais.getNextEntry()) != null) {
                if (ais.canReadEntryData(entry)) {
                    Path outPath = extractSingleEntry(ais, entry, destDir);
                    if (outPath != null) {
                        files.add(outPath);
                    }
                }
                extracted++;
                if (reporter != null && totalEntries > 0) {
                    reporter.setStatus(Messages.format("status.extracting.progress", extracted, totalEntries),
                            ProgressPhase.ARCHIVE);
                    reporter.setProgress((float) extracted / totalEntries, "", ProgressPhase.ARCHIVE);
                }
            }
        }
        return files;
    }

    // ==================== TAR.GZ 解压 ====================

    private static List<Path> extractTarGz(Path archive, Path destDir) throws IOException {
        return extractTarGz(archive, destDir, null);
    }

    private static List<Path> extractTarGz(Path archive, Path destDir, ProgressReporter reporter) throws IOException {
        List<Path> files = new ArrayList<>();
        try (InputStream fin = Files.newInputStream(archive);
             GzipCompressorInputStream gzis = new GzipCompressorInputStream(fin);
             TarArchiveInputStream tais = new TarArchiveInputStream(gzis)) {
            ArchiveEntry entry;
            int extracted = 0;
            while ((entry = tais.getNextEntry()) != null) {
                if (tais.canReadEntryData(entry)) {
                    Path outPath = extractSingleEntry(tais, entry, destDir);
                    if (outPath != null) {
                        files.add(outPath);
                    }
                }
                extracted++;
                if (reporter != null && extracted % 5 == 0) {
                    reporter.setStatus(Messages.format("status.extracting.count", extracted),
                            ProgressPhase.ARCHIVE);
                }
            }
        }
        return files;
    }

    // ==================== GZ 解压 ====================

    private static List<Path> extractGz(Path archive, Path destDir) throws IOException {
        return extractGz(archive, destDir, null);
    }

    private static List<Path> extractGz(Path archive, Path destDir, ProgressReporter reporter) throws IOException {
        List<Path> files = new ArrayList<>();
        String outName = archive.getFileName().toString();
        if (outName.endsWith(".gz")) {
            outName = outName.substring(0, outName.length() - 3);
        }
        Path outFile = destDir.resolve(outName);
        if (reporter != null) {
            reporter.setStatus(Messages.get("status.extracting"), ProgressPhase.ARCHIVE);
            reporter.setProgress(0f, "", ProgressPhase.ARCHIVE);
        }
        try (InputStream fin = Files.newInputStream(archive);
             GzipCompressorInputStream gzis = new GzipCompressorInputStream(fin);
             OutputStream fos = Files.newOutputStream(outFile)) {
            gzis.transferTo(fos);
        }
        files.add(outFile);
        return files;
    }

    // ==================== 7Z 解压 ====================

    private static List<Path> extract7z(Path archive, Path destDir, String password) throws IOException {
        return extract7z(archive, destDir, password, null);
    }

    private static List<Path> extract7z(Path archive, Path destDir, String password,
                                        ProgressReporter reporter) throws IOException {
        List<Path> files = new ArrayList<>();
        SevenZFile.Builder builder = SevenZFile.builder().setFile(archive.toFile());
        if (password != null && !password.isEmpty()) {
            builder = builder.setPassword(password.toCharArray());
        }
        try (SevenZFile szf = builder.get()) {
            List<SevenZArchiveEntry> entries = new ArrayList<>();
            for (SevenZArchiveEntry e : szf.getEntries()) {
                entries.add(e);
            }
            int total = entries.size();
            int extracted = 0;
            for (SevenZArchiveEntry entry : entries) {
                if (entry.isDirectory()) {
                    Files.createDirectories(destDir.resolve(entry.getName()));
                    extracted++;
                    continue;
                }
                Path outPath = destDir.resolve(entry.getName()).normalize();
                if (!outPath.startsWith(destDir)) {
                    throw new IOException("Bad archive entry (zip-slip): " + entry.getName());
                }
                Files.createDirectories(outPath.getParent());
                try (InputStream in = szf.getInputStream(entry);
                     OutputStream fos = Files.newOutputStream(outPath)) {
                    in.transferTo(fos);
                }
                files.add(outPath);
                extracted++;
                if (reporter != null && total > 0) {
                    reporter.setStatus(Messages.format("status.extracting.progress", extracted, total),
                            ProgressPhase.ARCHIVE);
                    reporter.setProgress((float) extracted / total, "", ProgressPhase.ARCHIVE);
                }
            }
        }
        return files;
    }

    // ==================== 旧版逐条目加密解密 ====================

    /**
     * 对旧版 .enc 逐条目加密的文件进行解密。
     */
    private static List<Path> decryptLegacyEntries(List<Path> rawFiles, String password,
                                                    ProgressReporter reporter) throws IOException {
        int totalEncrypted = countEncrypted(rawFiles);
        int decrypted = 0;
        List<Path> result = new ArrayList<>();
        for (Path f : rawFiles) {
            if (isEncryptedFile(f)) {
                if (password == null || password.isEmpty()) {
                    throw PasswordNeededException.of(f);
                }
                if (reporter != null) {
                    decrypted++;
                    reporter.setStatus(Messages.format("status.decrypting.progress",
                            decrypted, totalEncrypted));
                    if (totalEncrypted > 0) {
                        reporter.setProgress((float) decrypted / (totalEncrypted + rawFiles.size()), "");
                    }
                }
                String fn = f.getFileName().toString();
                String outName = fn.endsWith(".enc") ? fn.substring(0, fn.length() - 4) : fn + ".dec";
                Path out = f.resolveSibling(outName);
                decryptFileTo(f, out, password);
                Files.deleteIfExists(f);
                result.add(out);
            } else {
                result.add(f);
            }
        }
        return result;
    }

    private static int countEncrypted(List<Path> files) {
        int count = 0;
        for (Path f : files) {
            if (isEncryptedFile(f)) {
                count++;
            }
        }
        return count;
    }

    // ==================== AES-256-CTR 解密 ====================

    private static Path decryptFile(Path file, String password) throws IOException {
        try (InputStream fin = Files.newInputStream(file)) {
            byte[] magic = new byte[MAGIC.length];
            fin.readNBytes(magic, 0, MAGIC.length);
            if (!Arrays.equals(magic, MAGIC)) {
                throw new IOException("Not an encrypted archive file");
            }
            byte[] salt = new byte[16];
            byte[] iv = new byte[16];
            fin.readNBytes(salt, 0, 16);
            fin.readNBytes(iv, 0, 16);

            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, PBKDF2_ITERATIONS, KEY_SIZE * 8);
            SecretKeySpec key = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");

            Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));

            Path out = Files.createTempFile("ergou-extract-", ".tmp");
            try (CipherInputStream cis = new CipherInputStream(fin, cipher);
                 OutputStream fos = Files.newOutputStream(out)) {
                cis.transferTo(fos);
            }
            return out;
        } catch (Exception e) {
            throw new IOException("Archive password incorrect or file corrupted: " + e.getMessage(), e);
        }
    }

    private static void decryptFileTo(Path file, Path output, String password) throws IOException {
        try (InputStream fin = Files.newInputStream(file)) {
            byte[] magic = new byte[MAGIC.length];
            fin.readNBytes(magic, 0, MAGIC.length);
            if (!Arrays.equals(magic, MAGIC)) {
                throw new IOException("Not an encrypted archive file");
            }
            byte[] salt = new byte[16];
            byte[] iv = new byte[16];
            fin.readNBytes(salt, 0, 16);
            fin.readNBytes(iv, 0, 16);

            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, PBKDF2_ITERATIONS, KEY_SIZE * 8);
            SecretKeySpec key = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");

            Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));

            try (CipherInputStream cis = new CipherInputStream(fin, cipher);
                 OutputStream fos = Files.newOutputStream(output)) {
                cis.transferTo(fos);
            }
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException("Archive password incorrect or file corrupted: " + e.getMessage(), e);
        }
    }

    // ==================== 工具方法 ====================

    /**
     * 提取单个归档条目到目标目录，防护 Zip-Slip 路径穿越。
     */
    private static Path extractSingleEntry(ArchiveInputStream<?> ais, ArchiveEntry entry,
                                           Path destDir) throws IOException {
        String entryName = entry.getName();
        Path outPath = destDir.resolve(entryName).normalize();
        if (!outPath.startsWith(destDir)) {
            throw new IOException("Bad archive entry (zip-slip): " + entryName);
        }
        if (entry.isDirectory()) {
            Files.createDirectories(outPath);
            return null;
        }
        Files.createDirectories(outPath.getParent());
        try (OutputStream fos = Files.newOutputStream(outPath)) {
            ais.transferTo(fos);
        }
        return outPath;
    }

    /**
     * 从归档文件名中提取扩展名（用于保持临时解密文件的扩展名以正确检测格式）。
     */
    private static String archiveExt(Path archive) {
        String name = archive.getFileName().toString().toLowerCase();
        if (name.endsWith(".tar.gz")) {
            return ".tar.gz";
        } else if (name.endsWith(".gz")) {
            return ".gz";
        } else if (name.endsWith(".zip")) {
            return ".zip";
        } else if (name.endsWith(".7z")) {
            return ".7z";
        }
        return ".tmp";
    }

    // ==================== 密码需求异常 ====================

    /**
     * 归档密码缺失异常，携带需要密码的加密文件路径。
     */
    public static final class PasswordNeededException extends IOException {

        private final Path encryptedFile;

        PasswordNeededException(Path f) {
            super("Archive password required");
            this.encryptedFile = f;
        }

        public static PasswordNeededException of(Path f) {
            return new PasswordNeededException(f);
        }

        public Path getEncryptedFile() {
            return encryptedFile;
        }
    }
}
