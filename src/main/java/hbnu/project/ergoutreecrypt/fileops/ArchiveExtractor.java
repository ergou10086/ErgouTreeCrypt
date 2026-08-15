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
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.RandomAccessFile;
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

    /**
     * 解压进度上报步长（字节）：约每完成 1 MiB 上报一次，避免回调过于频繁。
     */
    private static final long PROGRESS_STEP_BYTES = 1L << 20;

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
     * 解压归档到目标目录（带字节级进度反馈）。
     *
     * <p>进度映射：整体加密包裹文件的解密阶段占 0→0.3，随后的解压阶段占
     * 0.3→1；无整体加密时解压阶段占 0→1。
     *
     * @param archive  归档文件路径
     * @param destDir  解压目标目录
     * @param password 解密密码（可为 null/空）
     * @param reporter 进度回调（可为 null）
     * @return 解压后的文件路径列表
     * @throws IOException             I/O 错误或密码错误
     * @throws PasswordNeededException 若遇到加密文件但未提供密码
     */
    public static List<Path> extractPreserving(Path archive, Path destDir, String password,
                                               ProgressReporter reporter) throws IOException {
        Files.createDirectories(destDir);

        // 检测整体加密包裹（GZ / TAR.GZ / 7Z）
        Path actualArchive = archive;
        Path tempDecrypted = null;
        float extractionFrom = 0f;
        if (isEncryptedFile(archive)) {
            if (password == null || password.isEmpty()) {
                throw PasswordNeededException.of(archive);
            }
            tempDecrypted = Files.createTempFile("ergou-outer-dec-", archiveExt(archive));
            // 整体解密占 0→0.3，随后的解压占 0.3→1
            decryptFileTo(archive, tempDecrypted, password, reporter, 0f, 0.3f);
            actualArchive = tempDecrypted;
            extractionFrom = 0.3f;
        }

        try {
            String name = actualArchive.getFileName().toString().toLowerCase();
            List<Path> rawFiles;
            if (name.endsWith(".zip")) {
                rawFiles = extractZip(actualArchive, destDir, password, reporter, extractionFrom, 1f);
            } else if (name.endsWith(".tar.gz") || name.endsWith(".tgz")) {
                rawFiles = extractTarGz(actualArchive, destDir, reporter, extractionFrom, 1f);
            } else if (name.endsWith(".7z")) {
                rawFiles = extract7z(actualArchive, destDir, password, reporter, extractionFrom, 1f);
            } else if (name.endsWith(".gz")) {
                rawFiles = extractGz(actualArchive, destDir, reporter, extractionFrom, 1f);
            } else {
                throw new IOException("Unsupported archive format: " + name);
            }
            if (reporter != null) {
                reportArchive(reporter, 1f, Messages.get("status.extracting"));
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
        return extractZip(archive, destDir, password, null, 0f, 1f);
    }

    /**
     * 解压 ZIP 归档（带进度，进度映射到 [from, to] 区间）。
     *
     * <p>有密码时优先使用 zip4j 解压（支持原生 AES-256 加密 ZIP）；
     * 无密码时使用 commons-compress 流式解压。
     *
     * @param archive  归档文件路径
     * @param destDir  解压目标目录
     * @param password 解密密码（可为 null/空）
     * @param reporter 进度回调（可为 null）
     * @param from     进度映射起点
     * @param to       进度映射终点
     * @return 解压后的文件路径列表
     * @throws IOException 解压失败
     */
    private static List<Path> extractZip(Path archive, Path destDir, String password,
                                         ProgressReporter reporter, float from, float to)
            throws IOException {
        boolean hasPwd = password != null && !password.isEmpty();
        if (hasPwd) {
            try {
                return extractZipWithZip4j(archive, destDir, password, reporter, from, to);
            } catch (Exception e) {
                // zip4j 失败（可能是旧版 .enc 格式或损坏），回退到 commons-compress
                if (e instanceof IOException ioe) {
                    throw ioe;
                }
            }
        }
        return extractZipWithCompress(archive, destDir, reporter, from, to);
    }

    /**
     * 使用 zip4j 解压 ZIP（支持原生 AES-256 加密），并按字节级粒度回调进度。
     *
     * <p>总字节数取各条目未压缩大小之和，进度为已解压字节数占总字节数的比例；
     * 总字节数不可知时退回按条目数上报。
     *
     * @param archive  归档文件路径
     * @param destDir  解压目标目录
     * @param password 解密密码
     * @param reporter 进度回调（可为 null）
     * @param from     进度映射起点
     * @param to       进度映射终点
     * @return 解压后的文件路径列表
     * @throws IOException 解压失败
     */
    private static List<Path> extractZipWithZip4j(Path archive, Path destDir, String password,
                                                   ProgressReporter reporter, float from, float to)
            throws IOException {
        List<Path> files = new ArrayList<>();
        try (ZipFile zipFile = new ZipFile(archive.toFile(), password.toCharArray())) {
            List<FileHeader> headers = zipFile.getFileHeaders();
            int total = headers.size();
            long totalBytes = 0;
            for (FileHeader header : headers) {
                if (!header.isDirectory()) {
                    totalBytes += Math.max(0, header.getUncompressedSize());
                }
            }
            int extracted = 0;
            long doneBytes = 0;
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
                    copyWithProgress(in, fos, doneBytes, totalBytes, reporter,
                            Messages.get("status.extracting"), from, to);
                }
                files.add(outPath);
                doneBytes += Math.max(0, header.getUncompressedSize());
                extracted++;
                reportEntryProgress(reporter, extracted, total, totalBytes, from, to);
            }
        }
        return files;
    }

    /**
     * 使用 commons-compress 流式解压 ZIP（无加密），并按字节级粒度回调进度。
     *
     * <p>总字节数取中央目录中各条目未压缩大小之和；不可知时退回按条目数上报。
     *
     * @param archive  归档文件路径
     * @param destDir  解压目标目录
     * @param reporter 进度回调（可为 null）
     * @param from     进度映射起点
     * @param to       进度映射终点
     * @return 解压后的文件路径列表
     * @throws IOException 解压失败
     */
    private static List<Path> extractZipWithCompress(Path archive, Path destDir,
                                                      ProgressReporter reporter, float from, float to)
            throws IOException {
        List<Path> files = new ArrayList<>();
        int totalEntries = 0;
        long totalBytes = 0;
        try (java.util.zip.ZipFile zf = new java.util.zip.ZipFile(archive.toFile())) {
            totalEntries = zf.size();
            java.util.Enumeration<? extends java.util.zip.ZipEntry> entries = zf.entries();
            while (entries.hasMoreElements()) {
                java.util.zip.ZipEntry e = entries.nextElement();
                if (!e.isDirectory()) {
                    totalBytes += Math.max(0, e.getSize());
                }
            }
        }
        int extracted = 0;
        long doneBytes = 0;
        try (InputStream fin = Files.newInputStream(archive);
             BufferedInputStream bis = new BufferedInputStream(fin);
             ArchiveInputStream<?> ais = new ZipArchiveInputStream(bis, "UTF-8", false, true)) {
            ArchiveEntry entry;
            while ((entry = ais.getNextEntry()) != null) {
                if (ais.canReadEntryData(entry)) {
                    Path outPath = extractSingleEntry(ais, entry, destDir, doneBytes, totalBytes,
                            reporter, from, to);
                    if (outPath != null) {
                        files.add(outPath);
                    }
                }
                doneBytes += Math.max(0, entry.getSize());
                extracted++;
                reportEntryProgress(reporter, extracted, totalEntries, totalBytes, from, to);
            }
        }
        return files;
    }

    // ==================== TAR.GZ 解压 ====================

    private static List<Path> extractTarGz(Path archive, Path destDir) throws IOException {
        return extractTarGz(archive, destDir, null, 0f, 1f);
    }

    /**
     * 解压 TAR.GZ 归档（带进度，进度映射到 [from, to] 区间）。
     *
     * <p>总字节数取 GZIP 尾部 ISIZE 字段（未压缩总字节数，4 GiB 内精确），
     * 通过对解压流计数实现包含 tar 头在内的字节级进度；ISIZE 不可得时仅上报条目数。
     *
     * @param archive  归档文件路径
     * @param destDir  解压目标目录
     * @param reporter 进度回调（可为 null）
     * @param from     进度映射起点
     * @param to       进度映射终点
     * @return 解压后的文件路径列表
     * @throws IOException 解压失败
     */
    private static List<Path> extractTarGz(Path archive, Path destDir, ProgressReporter reporter,
                                           float from, float to) throws IOException {
        List<Path> files = new ArrayList<>();
        long totalBytes = gzipUncompressedSize(archive);
        try (InputStream fin = Files.newInputStream(archive);
             GzipCompressorInputStream gzis = new GzipCompressorInputStream(fin);
             CountingInputStream counter = new CountingInputStream(gzis);
             TarArchiveInputStream tais = new TarArchiveInputStream(counter)) {
            ArchiveEntry entry;
            int extracted = 0;
            while ((entry = tais.getNextEntry()) != null) {
                if (tais.canReadEntryData(entry)) {
                    Path outPath = extractSingleEntryCounted(tais, entry, destDir, counter, totalBytes,
                            reporter, from, to);
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
        return extractGz(archive, destDir, null, 0f, 1f);
    }

    /**
     * 解压单文件 GZ 归档（带进度，进度映射到 [from, to] 区间）。
     *
     * <p>总字节数取 GZIP 尾部 ISIZE 字段（未压缩总字节数，4 GiB 内精确），
     * 与解压流实际输出字节数精确对应；ISIZE 不可得时仅上报状态。
     *
     * @param archive  归档文件路径
     * @param destDir  解压目标目录
     * @param reporter 进度回调（可为 null）
     * @param from     进度映射起点
     * @param to       进度映射终点
     * @return 解压后的文件路径列表
     * @throws IOException 解压失败
     */
    private static List<Path> extractGz(Path archive, Path destDir, ProgressReporter reporter,
                                        float from, float to) throws IOException {
        List<Path> files = new ArrayList<>();
        String outName = archive.getFileName().toString();
        if (outName.endsWith(".gz")) {
            outName = outName.substring(0, outName.length() - 3);
        }
        Path outFile = destDir.resolve(outName);
        long totalBytes = gzipUncompressedSize(archive);
        if (reporter != null) {
            reportArchive(reporter, from, Messages.get("status.extracting"));
        }
        try (InputStream fin = Files.newInputStream(archive);
             GzipCompressorInputStream gzis = new GzipCompressorInputStream(fin);
             OutputStream fos = Files.newOutputStream(outFile)) {
            copyWithProgress(gzis, fos, 0, totalBytes, reporter,
                    Messages.get("status.extracting"), from, to);
        }
        files.add(outFile);
        return files;
    }

    // ==================== 7Z 解压 ====================

    private static List<Path> extract7z(Path archive, Path destDir, String password) throws IOException {
        return extract7z(archive, destDir, password, null, 0f, 1f);
    }

    /**
     * 解压 7Z 归档（带进度，进度映射到 [from, to] 区间）。
     *
     * <p>总字节数取各条目大小之和；总字节数不可知时退回按条目数上报。
     *
     * @param archive  归档文件路径
     * @param destDir  解压目标目录
     * @param password 解密密码（可为 null/空）
     * @param reporter 进度回调（可为 null）
     * @param from     进度映射起点
     * @param to       进度映射终点
     * @return 解压后的文件路径列表
     * @throws IOException 解压失败
     */
    private static List<Path> extract7z(Path archive, Path destDir, String password,
                                        ProgressReporter reporter, float from, float to)
            throws IOException {
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
            long totalBytes = 0;
            for (SevenZArchiveEntry e : entries) {
                if (!e.isDirectory()) {
                    totalBytes += Math.max(0, e.getSize());
                }
            }
            int extracted = 0;
            long doneBytes = 0;
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
                    copyWithProgress(in, fos, doneBytes, totalBytes, reporter,
                            Messages.get("status.extracting"), from, to);
                }
                files.add(outPath);
                doneBytes += Math.max(0, entry.getSize());
                extracted++;
                reportEntryProgress(reporter, extracted, total, totalBytes, from, to);
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
        decryptFileTo(file, output, password, null, 0f, 1f);
    }

    /**
     * 解密整体包裹文件到指定路径，并按字节级粒度回调进度。
     *
     * <p>密文长度为文件总长减去 MAGIC(12) + salt(16) + IV(16) 头，进度为
     * 已解密字节数占密文总长的比例。
     *
     * @param file     加密文件路径
     * @param output   输出路径
     * @param password 密码
     * @param reporter 进度回调（可为 null）
     * @param from     进度映射起点
     * @param to       进度映射终点
     * @throws IOException 解密失败或密码错误
     */
    private static void decryptFileTo(Path file, Path output, String password,
                                      ProgressReporter reporter, float from, float to) throws IOException {
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

            long totalBytes = Math.max(0, Files.size(file) - MAGIC.length - 32);
            try (CipherInputStream cis = new CipherInputStream(fin, cipher);
                 OutputStream fos = Files.newOutputStream(output)) {
                copyWithProgress(cis, fos, 0, totalBytes, reporter,
                        Messages.get("status.decrypting"), from, to);
            }
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException("Archive password incorrect or file corrupted: " + e.getMessage(), e);
        }
    }

    // ==================== 工具方法 ====================

    /**
     * 提取单个归档条目到目标目录（带字节级进度），防护 Zip-Slip 路径穿越。
     *
     * @param ais      归档输入流
     * @param entry    当前条目
     * @param destDir  解压目标目录
     * @param done     本次提取前已完成的累计字节数
     * @param total    全程总字节数（<=0 时不上报）
     * @param reporter 进度回调（可为 null）
     * @param from     进度映射起点
     * @param to       进度映射终点
     * @return 提取出的文件路径；目录条目返回 null
     * @throws IOException 读写失败
     */
    private static Path extractSingleEntry(ArchiveInputStream<?> ais, ArchiveEntry entry,
                                           Path destDir, long done, long total,
                                           ProgressReporter reporter, float from, float to)
            throws IOException {
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
            copyWithProgress(ais, fos, done, total, reporter,
                    Messages.get("status.extracting"), from, to);
        }
        return outPath;
    }

    /**
     * 提取单个归档条目到目标目录（带字节级进度，以外部计数流为进度基准），
     * 防护 Zip-Slip 路径穿越。
     *
     * <p>用于 TAR.GZ：tar 头与填充字节同样计入总进度，进度基准为包裹 GZIP
     * 解压流的 {@link CountingInputStream}，与 ISIZE 总量精确对应。
     *
     * @param ais      归档输入流
     * @param entry    当前条目
     * @param destDir  解压目标目录
     * @param counter  计数流（位于 GZIP 解压流与 tar 流之间）
     * @param total    全程总字节数（<=0 时不上报）
     * @param reporter 进度回调（可为 null）
     * @param from     进度映射起点
     * @param to       进度映射终点
     * @return 提取出的文件路径；目录条目返回 null
     * @throws IOException 读写失败
     */
    private static Path extractSingleEntryCounted(ArchiveInputStream<?> ais, ArchiveEntry entry,
                                                  Path destDir, CountingInputStream counter, long total,
                                                  ProgressReporter reporter, float from, float to)
            throws IOException {
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
            copyWithProgressCounted(ais, fos, counter, total, reporter,
                    Messages.get("status.extracting"), from, to);
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

    // ==================== 进度上报工具 ====================

    /**
     * 上报解压阶段进度。
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

    /**
     * 将已处理字节数映射为区间 [from, to] 内的进度比例并上报。
     *
     * @param done     已处理字节数
     * @param total    全程总字节数（<=0 时不上报）
     * @param reporter 进度回调，可为 null
     * @param status   状态文案
     * @param from     进度映射起点
     * @param to       进度映射终点
     */
    private static void reportScaledProgress(long done, long total, ProgressReporter reporter,
                                             String status, float from, float to) {
        if (reporter != null && total > 0) {
            float fraction = Math.min(from + (to - from) * (float) done / total, to);
            reportArchive(reporter, fraction, status);
        }
    }

    /**
     * 上报按条目计数的解压状态；总字节数未知时同时以条目比例更新进度。
     *
     * @param reporter   进度回调（可为 null）
     * @param extracted  已完成条目数
     * @param total      总条目数
     * @param totalBytes 总字节数（<=0 表示不可知）
     * @param from       进度映射起点
     * @param to         进度映射终点
     */
    private static void reportEntryProgress(ProgressReporter reporter, int extracted, int total,
                                            long totalBytes, float from, float to) {
        if (reporter == null || total <= 0) {
            return;
        }
        if (totalBytes <= 0) {
            reporter.setProgress(from + (to - from) * (float) extracted / total, "",
                    ProgressPhase.ARCHIVE);
        }
        reporter.setStatus(Messages.format("status.extracting.progress", extracted, total),
                ProgressPhase.ARCHIVE);
    }

    /**
     * 带字节级进度回调的流式拷贝，约每完成 1 MiB 上报一次。
     *
     * @param in       输入流
     * @param out      输出流
     * @param done     本次拷贝前已完成的累计字节数
     * @param total    全程总字节数（<=0 时不上报）
     * @param reporter 进度回调，可为 null
     * @param status   状态文案
     * @param from     进度映射起点
     * @param to       进度映射终点
     * @return 本次拷贝的字节数
     * @throws IOException 读写失败
     */
    private static long copyWithProgress(InputStream in, OutputStream out, long done, long total,
                                         ProgressReporter reporter, String status,
                                         float from, float to) throws IOException {
        byte[] buf = new byte[8192];
        long copied = 0;
        long nextReport = done + PROGRESS_STEP_BYTES;
        int n;
        while ((n = in.read(buf)) > 0) {
            out.write(buf, 0, n);
            copied += n;
            if (done + copied >= nextReport) {
                reportScaledProgress(done + copied, total, reporter, status, from, to);
                nextReport += PROGRESS_STEP_BYTES;
            }
        }
        return copied;
    }

    /**
     * 以外部计数流为进度基准的流式拷贝，约每完成 1 MiB 上报一次。
     *
     * <p>与 {@link #copyWithProgress} 的区别：进度取自计数流的当前位置而非
     * 本循环的拷贝计数，适用于 tar 头等不在拷贝循环内的字节同样计入进度的场景。
     *
     * @param in       输入流
     * @param out      输出流
     * @param counter  进度计数流（当前位置即已完成字节数）
     * @param total    全程总字节数（<=0 时不上报）
     * @param reporter 进度回调，可为 null
     * @param status   状态文案
     * @param from     进度映射起点
     * @param to       进度映射终点
     * @throws IOException 读写失败
     */
    private static void copyWithProgressCounted(InputStream in, OutputStream out,
                                                CountingInputStream counter, long total,
                                                ProgressReporter reporter, String status,
                                                float from, float to) throws IOException {
        byte[] buf = new byte[8192];
        long nextReport = PROGRESS_STEP_BYTES;
        int n;
        while ((n = in.read(buf)) > 0) {
            out.write(buf, 0, n);
            long done = counter.getCount();
            if (done >= nextReport) {
                reportScaledProgress(done, total, reporter, status, from, to);
                nextReport = done + PROGRESS_STEP_BYTES;
            }
        }
    }

    /**
     * 读取 GZIP 尾部 ISIZE 字段得到未压缩总字节数。
     *
     * <p>ISIZE 为 32 位小端无符号整数：4 GiB 内精确，超出时按 2^32 回绕，
     * 此时进度在尾部会被钳制在终点（见 {@link #reportScaledProgress}）。
     *
     * @param archive GZIP 文件路径
     * @return 未压缩字节数；读取失败或文件过小返回 -1
     */
    private static long gzipUncompressedSize(Path archive) {
        try (RandomAccessFile raf = new RandomAccessFile(archive.toFile(), "r")) {
            if (raf.length() < 4) {
                return -1;
            }
            raf.seek(raf.length() - 4);
            long isize = raf.read() & 0xFFL;
            isize |= (raf.read() & 0xFFL) << 8;
            isize |= (raf.read() & 0xFFL) << 16;
            isize |= (raf.read() & 0xFFL) << 24;
            return isize;
        } catch (IOException e) {
            return -1;
        }
    }

    /**
     * 计数输入流：统计实际流经的字节数（用于 TAR.GZ 字节级进度）。
     */
    private static final class CountingInputStream extends FilterInputStream {

        /**
         * 已流经的字节数。
         */
        private long count;

        /**
         * 包装底层输入流。
         *
         * @param in 底层输入流
         */
        CountingInputStream(InputStream in) {
            super(in);
        }

        @Override
        public int read() throws IOException {
            int b = super.read();
            if (b >= 0) {
                count++;
            }
            return b;
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            int n = super.read(b, off, len);
            if (n > 0) {
                count += n;
            }
            return n;
        }

        /**
         * 返回已流经的字节数。
         *
         * @return 已流经的字节数
         */
        long getCount() {
            return count;
        }
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
