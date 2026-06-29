package hbnu.project.ergoutreecrypt.fileops;

import org.apache.commons.compress.archivers.ArchiveEntry;
import org.apache.commons.compress.archivers.ArchiveInputStream;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;
import org.apache.commons.compress.archivers.zip.ZipArchiveInputStream;
import org.apache.commons.compress.compressors.gzip.GzipCompressorInputStream;

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
import java.util.Enumeration;
import java.util.List;

/**
 * 归档解压工具，支持自动检测并解密内部 AES-256-CTR 加密的文件条目。
 *
 * <p>支持的归档格式：ZIP、GZ、TAR.GZ。加密文件以 12 字节魔数头 {@code EGTC_ARCHV1} 标识。
 *
 * @author ErgouTree
 */
public final class ArchiveExtractor {

    /**
     * 加密文件魔数标识（12 字节）。
     */
    private static final byte[] MAGIC = "EGTC_ARCHV1\0".getBytes();

    /**
     * 加密文件头总大小：魔数(12) + salt(16) + IV(16) = 44 字节。
     */
    private static final int HEADER_SIZE = 12 + 16 + 16;

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
     * @return 若扩展名为 .zip / .gz / .tgz / .tar.gz / .rar / .7z 则返回 true
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
     * 检测文件是否以 EGTC_ARCHV1 魔数开头，即是否为本工具 AES 加密的文件。
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
     * 快速检测归档是否包含需要密码的加密条目。
     *
     * <p>对 ZIP 通过读取中央目录（不解压数据）快速判断；对 TAR.GZ 采用流式扫描，
     * 找到第一个加密条目即返回 true。此方法用于在解压前提示用户输入归档密码，避免无密码解压失败。
     *
     * @param archive 归档文件路径
     * @return 若归档内至少有一个 .enc 后缀条目则返回 true
     * @throws IOException 读取错误
     */
    public static boolean hasEncryptedEntries(Path archive) throws IOException {
        String name = archive.getFileName().toString().toLowerCase();
        if (name.endsWith(".zip")) {
            return hasEncryptedZipEntries(archive);
        }
        if (name.endsWith(".tar.gz") || name.endsWith(".tgz")) {
            return hasEncryptedTarGzEntries(archive);
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
     * ZIP 快速扫描：通过 {@link java.util.zip.ZipFile} 读取中央目录（不解析数据流），
     * 检测是否有 .enc 后缀的条目。
     */
    private static boolean hasEncryptedZipEntries(Path archive) throws IOException {
        try (java.util.zip.ZipFile zf = new java.util.zip.ZipFile(archive.toFile())) {
            Enumeration<? extends java.util.zip.ZipEntry> entries = zf.entries();
            while (entries.hasMoreElements()) {
                if (entries.nextElement().getName().toLowerCase().endsWith(".enc")) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * TAR.GZ 流式扫描：边解压边遍历条目，找到第一个 .enc 后缀条目即返回。
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
     * 解压归档到目标目录，保留内部条目名与目录结构（无进度反馈）。
     *
     * <p>对内部 AES 加密条目（{@code .enc} 后缀）就地解密并去除后缀，不生成临时文件。
     * 用于文件夹/分卷场景的二次解密。
     *
     * @param archive  归档文件路径
     * @param destDir  解压目标目录
     * @param password 解密密码（可为 null/空）
     * @return 解压（并去 AES 层）后的文件路径列表
     * @throws IOException               I/O 错误或密码错误
     * @throws PasswordNeededException   若遇到加密文件但未提供密码
     */
    public static List<Path> extractPreserving(Path archive, Path destDir, String password) throws IOException {
        return extractPreserving(archive, destDir, password, null);
    }

    /**
     * 解压归档到目标目录（带进度反馈）。
     *
     * <p>与 {@link #extractPreserving(Path, Path, String)} 相同，但通过 {@code reporter}
     * 报告解压进度。若 {@code reporter} 为 null 则不报告。
     *
     * @param archive  归档文件路径
     * @param destDir  解压目标目录
     * @param password 解密密码（可为 null/空）
     * @param reporter 进度回调（可为 null）
     * @return 解压后的文件路径列表
     * @throws IOException               I/O 错误或密码错误
     * @throws PasswordNeededException   若遇到加密文件但未提供密码
     */
    public static List<Path> extractPreserving(Path archive, Path destDir, String password,
                                               ProgressReporter reporter) throws IOException {
        Files.createDirectories(destDir);
        String name = archive.getFileName().toString().toLowerCase();

        // 根据扩展名选择对应的解压方法
        List<Path> rawFiles;
        if (name.endsWith(".zip")) {
            rawFiles = extractZip(archive, destDir, reporter);
        } else if (name.endsWith(".tar.gz") || name.endsWith(".tgz")) {
            rawFiles = extractTarGz(archive, destDir, reporter);
        } else if (name.endsWith(".gz")) {
            rawFiles = extractGz(archive, destDir, reporter);
        } else {
            throw new IOException("Unsupported archive format: " + name);
        }

        // 对加密条目去除 .enc 后缀并就地解密
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
                    reporter.setStatus("Extracting (" + decrypted + "/" + totalEncrypted + ")...");
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

    /**
     * 统计列表中加密文件的数量。
     */
    private static int countEncrypted(List<Path> files) {
        int count = 0;
        for (Path f : files) {
            if (isEncryptedFile(f)) {
                count++;
            }
        }
        return count;
    }

    /**
     * 解压归档到目标目录。
     *
     * <p>内部加密条目解密后输出为临时文件（非原地解密）。
     *
     * @param archive  归档文件路径
     * @param destDir  解压目标目录
     * @param password 解密密码（可为 null/空）
     * @return 解压后的文件路径列表
     * @throws IOException               I/O 错误或密码错误
     * @throws PasswordNeededException   若遇到加密文件但未提供密码
     */
    public static List<Path> extract(Path archive, Path destDir, String password) throws IOException {
        Files.createDirectories(destDir);
        String name = archive.getFileName().toString().toLowerCase();

        List<Path> rawFiles;
        if (name.endsWith(".zip")) {
            rawFiles = extractZip(archive, destDir);
        } else if (name.endsWith(".tar.gz") || name.endsWith(".tgz")) {
            rawFiles = extractTarGz(archive, destDir);
        } else if (name.endsWith(".gz")) {
            rawFiles = extractGz(archive, destDir);
        } else if (name.endsWith(".rar") || name.endsWith(".7z")) {
            throw new IOException("RAR/7z extraction requires additional setup.");
        } else {
            throw new IOException("Unsupported archive format: " + name);
        }

        // 对每个提取出的文件检测是否需要解密
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
    }

    /**
     * 解密单个 AES-256-CTR 加密文件到临时文件。
     *
     * @param file     加密文件路径
     * @param password 解密密码
     * @return 解密后的临时文件路径
     * @throws IOException 密码错误或文件损坏
     */
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

            // PBKDF2-HMAC-SHA256 派生 AES 密钥
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, PBKDF2_ITERATIONS, KEY_SIZE * 8);
            SecretKeySpec key = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");

            // AES-256-CTR 解密
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

    /**
     * 将 AES 加密文件解密到指定的输出路径。
     *
     * @param file     加密文件路径
     * @param output   解密输出路径
     * @param password 解密密码
     * @throws IOException 密码错误或文件损坏
     */
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

    // ==================== ZIP 解压 ====================

    /**
     * 解压 ZIP 归档，返回所有提取文件路径。
     */
    private static List<Path> extractZip(Path archive, Path destDir) throws IOException {
        return extractZip(archive, destDir, null);
    }

    /**
     * 解压 ZIP 归档（带进度）。通过 {@link java.util.zip.ZipFile} 预读条目数以计算进度。
     */
    private static List<Path> extractZip(Path archive, Path destDir, ProgressReporter reporter) throws IOException {
        List<Path> files = new ArrayList<>();

        // 通过中央目录预取条目总数（快速，不解压数据）
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
                    reporter.setStatus(
                            "Extracting " + extracted + "/" + totalEntries + "...");
                    reporter.setProgress((float) extracted / (totalEntries * 2), "");
                }
            }
        }
        return files;
    }

    /**
     * 解压 TAR.GZ（或 TGZ）归档，返回所有提取文件路径。
     */
    private static List<Path> extractTarGz(Path archive, Path destDir) throws IOException {
        return extractTarGz(archive, destDir, null);
    }

    /**
     * 解压 TAR.GZ（或 TGZ）归档（带进度）。
     */
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
                    reporter.setStatus("Extracting (" + extracted + " entries)...");
                }
            }
        }
        return files;
    }

    /**
     * 解压单文件 GZ 压缩包，返回提取的文件路径。
     */
    private static List<Path> extractGz(Path archive, Path destDir) throws IOException {
        return extractGz(archive, destDir, null);
    }

    /**
     * 解压单文件 GZ 压缩包（带进度）。
     */
    private static List<Path> extractGz(Path archive, Path destDir, ProgressReporter reporter) throws IOException {
        List<Path> files = new ArrayList<>();
        String outName = archive.getFileName().toString();
        if (outName.endsWith(".gz")) {
            outName = outName.substring(0, outName.length() - 3);
        }
        Path outFile = destDir.resolve(outName);
        if (reporter != null) {
            reporter.setStatus("Extracting...");
        }
        try (InputStream fin = Files.newInputStream(archive);
             GzipCompressorInputStream gzis = new GzipCompressorInputStream(fin);
             OutputStream fos = Files.newOutputStream(outFile)) {
            gzis.transferTo(fos);
        }
        files.add(outFile);
        return files;
    }

    /**
     * 提取单个归档条目到目标目录，防护 Zip-Slip 路径穿越。
     *
     * @return 提取的文件路径，若为目录则返回 null
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

    // ==================== 密码需求异常 ====================

    /**
     * 归档密码缺失异常，携带需要密码的加密文件路径。
     */
    public static final class PasswordNeededException extends IOException {

        /**
         * 需要密码才能解密的文件路径。
         */
        private final Path encryptedFile;

        /**
         * @param f 加密文件路径
         */
        PasswordNeededException(Path f) {
            super("Archive password required");
            this.encryptedFile = f;
        }

        /**
         * 创建密码缺失异常。
         *
         * @param f 加密文件路径
         * @return 异常实例
         */
        public static PasswordNeededException of(Path f) {
            return new PasswordNeededException(f);
        }

        /**
         * 返回需要密码的加密文件路径。
         */
        public Path getEncryptedFile() {
            return encryptedFile;
        }
    }
}
