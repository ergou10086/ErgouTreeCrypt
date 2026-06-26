package hbnu.project.ergoutreecrypt.fileops;

import org.apache.commons.compress.archivers.ArchiveEntry;
import org.apache.commons.compress.archivers.ArchiveInputStream;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;
import org.apache.commons.compress.archivers.zip.ZipArchiveInputStream;
import org.apache.commons.compress.compressors.gzip.GzipCompressorInputStream;

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
 * 归档解压 + 自动检测/解密密码保护的内部文件。
 *
 * @author ErgouTree
 */
public final class ArchiveExtractor {

    private static final byte[] MAGIC = "EGTC_ARCHV1\0".getBytes(); // 12 bytes
    private static final int HEADER_SIZE = 12 + 16 + 16; // magic + salt + IV = 44 bytes
    private static final int KEY_SIZE = 32;
    private static final int PBKDF2_ITERATIONS = 100_000;

    private ArchiveExtractor() {
    }

    public static boolean isArchive(Path file) {
        String name = file.getFileName().toString().toLowerCase();
        return name.endsWith(".zip")
                || name.endsWith(".gz") || name.endsWith(".tgz")
                || name.endsWith(".tar.gz")
                || name.endsWith(".rar")
                || name.endsWith(".7z");
    }

    /**
     * 检测文件是否为本工具 AES 加密过的（头部有 EGTC_ARCHV1 魔数）。
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
     * 解压归档到目标目录，保留归档内的条目名与目录结构；对内部 AES 加密条目就地解密
     * （去除 {@code .enc} 后缀），不生成临时文件。用于文件夹/分卷场景的二次解密。
     *
     * @return 解压（并去 AES 层）后的文件路径列表
     */
    public static List<Path> extractPreserving(Path archive, Path destDir, String password) throws IOException {
        Files.createDirectories(destDir);
        String name = archive.getFileName().toString().toLowerCase();

        List<Path> rawFiles;
        if (name.endsWith(".zip")) {
            rawFiles = extractZip(archive, destDir);
        } else if (name.endsWith(".tar.gz") || name.endsWith(".tgz")) {
            rawFiles = extractTarGz(archive, destDir);
        } else if (name.endsWith(".gz")) {
            rawFiles = extractGz(archive, destDir);
        } else {
            throw new IOException("Unsupported archive format: " + name);
        }

        List<Path> result = new ArrayList<>();
        for (Path f : rawFiles) {
            if (isEncryptedFile(f)) {
                if (password == null || password.isEmpty()) {
                    throw PasswordNeededException.of(f);
                }
                // 去除 .enc 后缀，就地解密保留原名与目录结构
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
     * 解密单个 AES 加密文件，返回解密后路径。
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

    /**
     * 将 AES 加密文件解密到指定输出路径。
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

    // ---- ZIP ----
    private static List<Path> extractZip(Path archive, Path destDir) throws IOException {
        List<Path> files = new ArrayList<>();
        try (InputStream fin = Files.newInputStream(archive);
             BufferedInputStream bis = new BufferedInputStream(fin);
             ArchiveInputStream<?> ais = new ZipArchiveInputStream(bis, "UTF-8", false, true)) {
            extractEntries(ais, destDir, files);
        }
        return files;
    }

    // ---- TAR.GZ ----
    private static List<Path> extractTarGz(Path archive, Path destDir) throws IOException {
        List<Path> files = new ArrayList<>();
        try (InputStream fin = Files.newInputStream(archive);
             GzipCompressorInputStream gzis = new GzipCompressorInputStream(fin);
             TarArchiveInputStream tais = new TarArchiveInputStream(gzis)) {
            extractEntries(tais, destDir, files);
        }
        return files;
    }

    // ---- GZ ----
    private static List<Path> extractGz(Path archive, Path destDir) throws IOException {
        List<Path> files = new ArrayList<>();
        String outName = archive.getFileName().toString();
        if (outName.endsWith(".gz")) {
            outName = outName.substring(0, outName.length() - 3);
        }
        Path outFile = destDir.resolve(outName);
        try (InputStream fin = Files.newInputStream(archive);
             GzipCompressorInputStream gzis = new GzipCompressorInputStream(fin);
             OutputStream fos = Files.newOutputStream(outFile)) {
            gzis.transferTo(fos);
        }
        files.add(outFile);
        return files;
    }

    private static void extractEntries(ArchiveInputStream<?> ais, Path destDir, List<Path> files) throws IOException {
        ArchiveEntry entry;
        while ((entry = ais.getNextEntry()) != null) {
            if (ais.canReadEntryData(entry)) {
                String entryName = entry.getName();
                Path outPath = destDir.resolve(entryName).normalize();
                if (!outPath.startsWith(destDir)) {
                    throw new IOException("Bad archive entry (zip-slip): " + entryName);
                }
                if (entry.isDirectory()) {
                    Files.createDirectories(outPath);
                } else {
                    Files.createDirectories(outPath.getParent());
                    try (OutputStream fos = Files.newOutputStream(outPath)) {
                        ais.transferTo(fos);
                    }
                    files.add(outPath);
                }
            }
        }
    }

    // ================================================================
    // 密码需求异常
    // ================================================================
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
