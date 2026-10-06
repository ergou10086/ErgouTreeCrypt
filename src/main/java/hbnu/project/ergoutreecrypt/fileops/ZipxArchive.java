package hbnu.project.ergoutreecrypt.fileops;

import hbnu.project.ergoutreecrypt.i18n.Messages;
import hbnu.project.ergoutreecrypt.volume.ProgressPhase;
import hbnu.project.ergoutreecrypt.volume.ProgressReporter;
import org.apache.commons.compress.archivers.zip.*;
import org.apache.commons.compress.compressors.bzip2.*;
import org.apache.commons.compress.compressors.deflate64.Deflate64CompressorInputStream;
import org.tukaani.xz.*;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.zip.*;

/**
 * Portable ZIPX core shared by desktop and Android.
 * Writes BZip2/LZMA/XZ and reads Store/Deflate/Deflate64/BZip2/LZMA/XZ,
 * including WinZip AE-1/AE-2 AES-128/192/256. Unsupported methods fail explicitly.
 * All entries are validated before extracted files replace user-visible outputs.
 */
public final class ZipxArchive {
    private static final int MEMORY_LIMIT_KIB = 64 * 1024;
    private static final ZipShort AES_ID = new ZipShort(0x9901);

    /** Prevents construction. */
    private ZipxArchive() { }

    /**
     * Parsed compression and encryption metadata for an entry.
     * @param code actual compression method
     * @param aesVersion AES format version, or zero for plain entries
     * @param strength AES strength code, or zero for plain entries
     */
    private record Method(int code, int aesVersion, int strength) { }

    /**
     * Packs explicit file and directory entries as a standard ZIPX archive.
     * @param output archive path
     * @param entries source paths
     * @param names corresponding archive names
     * @param method compression method
     * @param password optional UTF-8 WinZip AES password
     * @param reporter progress and cancellation callback
     * @throws IOException invalid entries, cancellation or archive failure
     */
    public static void pack(Path output, List<Path> entries, List<String> names, ZipxMethod method,
                            String password, ProgressReporter reporter) throws IOException {
        if (entries.isEmpty() || entries.size() != names.size()) throw new IOException("ZIPX entry count mismatch");
        List<Path> expanded = new ArrayList<>(entries);
        List<String> expandedNames = new ArrayList<>(names);
        Set<Path> supplied = new HashSet<>();
        for (Path source : entries) supplied.add(source.toAbsolutePath().normalize());
        for (int i = 0; i < entries.size(); i++) {
            Path source = entries.get(i);
            if (Files.isDirectory(source) && !Files.isSymbolicLink(source)) {
                String prefix = safeName(names.get(i)).replaceAll("/$", "") + "/";
                try (var children = Files.walk(source)) {
                    for (Path child : children.filter(p -> !supplied.contains(p.toAbsolutePath().normalize())).sorted().toList()) {
                        expanded.add(child);
                        expandedNames.add(prefix + source.relativize(child).toString().replace('\\', '/'));
                    }
                }
            }
        }
        entries = expanded;
        names = expandedNames;
        Path target = output.toAbsolutePath().normalize();
        List<String> safeNames = new ArrayList<>();
        Set<String> used = new HashSet<>();
        for (int i = 0; i < entries.size(); i++) {
            Path source = entries.get(i);
            if (Files.isSymbolicLink(source) || (!Files.isRegularFile(source) && !Files.isDirectory(source))) {
                throw new IOException("Unsupported ZIPX source: " + source);
            }
            if (source.toAbsolutePath().normalize().equals(target)) throw new IOException("ZIPX output equals source");
            String name = safeName(names.get(i));
            if (Files.isDirectory(source) && !name.endsWith("/")) name += "/";
            if (!used.add(name.replaceAll("/$", "").toLowerCase(Locale.ROOT))) throw new IOException("Duplicate ZIPX entry: " + name);
            safeNames.add(name);
        }
        Files.createDirectories(target.getParent());
        Path work = Files.createTempDirectory(target.getParent(), ".zipx-pack-");
        Path staged = work.resolve("archive.zipx");
        try {
            long total = 0;
            for (Path source : entries) if (!Files.isDirectory(source)) total = Math.addExact(total, Files.size(source));
            long done = 0;
            try (ZipxOutput zip = new ZipxOutput(staged)) {
                for (int i = 0; i < entries.size(); i++) {
                    checkCancelled(reporter);
                    Path source = entries.get(i);
                    if (Files.isDirectory(source)) {
                        zip.add(safeNames.get(i), null, 0, 0, 0, false);
                        continue;
                    }
                    Path compressed = work.resolve("compressed");
                    CRC32 crc = new CRC32();
                    long size;
                    try (InputStream in = new CheckedInputStream(Files.newInputStream(source), crc);
                         OutputStream raw = new BufferedOutputStream(Files.newOutputStream(compressed), 65536);
                         OutputStream encoder = encoder(raw, method)) {
                        size = copy(in, encoder, Files.size(source), done, total, reporter, false);
                    }
                    // Store empty XZ files so external decoders do not stop before consuming their codec stream.
                    int entryMethod = method.code();
                    if (size == 0 && method == ZipxMethod.XZ) {
                        Files.write(compressed, new byte[0]);
                        entryMethod = 0;
                    }
                    boolean encrypted = password != null && !password.isEmpty();
                    Path payload = compressed;
                    if (encrypted) {
                        payload = work.resolve("encrypted");
                        ZipxAes.encrypt(compressed, payload, password, reporter);
                    }
                    checkCancelled(reporter);
                    zip.add(safeNames.get(i), payload, entryMethod, size, crc.getValue(), encrypted);
                    done += size;
                    Files.deleteIfExists(compressed);
                    if (encrypted) Files.deleteIfExists(payload);
                }
                zip.finish();
            }
            checkCancelled(reporter);
            Files.move(staged, target, StandardCopyOption.REPLACE_EXISTING);
            progress(reporter, 1f, false);
        } finally {
            deleteWork(work);
        }
    }

    /**
     * Detects native encryption and legacy encrypted entries without decoding data.
     * @param archive ZIP or ZIPX path
     * @return whether any entry requires a password
     * @throws IOException malformed archive
     */
    public static boolean isEncrypted(Path archive) throws IOException {
        try (org.apache.commons.compress.archivers.zip.ZipFile zip = open(archive)) {
            Enumeration<ZipArchiveEntry> entries = zip.getEntries();
            while (entries.hasMoreElements()) {
                ZipArchiveEntry entry = entries.nextElement();
                if (entry.getGeneralPurposeBit().usesEncryption() || entry.getName().endsWith(".enc")) return true;
            }
            return false;
        }
    }

    /**
     * Identifies advanced methods even when the archive has a .zip extension.
     * @param archive ZIP path
     * @return whether the extended reader is required
     * @throws IOException malformed central directory
     */
    static boolean needsExtendedReader(Path archive) throws IOException {
        try (org.apache.commons.compress.archivers.zip.ZipFile zip = open(archive)) {
            Enumeration<ZipArchiveEntry> entries = zip.getEntries();
            while (entries.hasMoreElements()) {
                ZipArchiveEntry entry = entries.nextElement();
                int code = entry.getMethod();
                if (code == 99) {
                    ZipExtraField field = entry.getExtraField(AES_ID);
                    if (field == null || field.getCentralDirectoryData().length < 7) return true;
                    code = ZipShort.getValue(field.getCentralDirectoryData(), 5);
                }
                if (code != 0 && code != 8) return true;
            }
            return false;
        }
    }

    /**
     * Authenticates AES ciphertext and checks decoded sizes and CRCs without exporting plaintext.
     * @param archive ZIP or ZIPX path
     * @param password optional archive password
     * @throws IOException authentication, integrity or unsupported-method failure
     */
    public static void verify(Path archive, String password) throws IOException {
        read(archive, null, password, null);
    }

    /**
     * Extracts validated entries, retaining the original archive.
     * @param archive ZIP or ZIPX path
     * @param destination output directory
     * @param password optional archive password
     * @param reporter progress and cancellation callback
     * @return extracted regular files
     * @throws IOException authentication, integrity or unsafe-path failure
     */
    public static List<Path> extract(Path archive, Path destination, String password,
                                     ProgressReporter reporter) throws IOException {
        return read(archive, destination, password, reporter);
    }

    /**
     * Validates the complete archive in a private staging directory before publication.
     * @param archive archive path
     * @param destination output directory, or null for verification
     * @param password optional password
     * @param reporter progress callback
     * @return exported regular file paths
     * @throws IOException archive validation failed
     */
    private static List<Path> read(Path archive, Path destination, String password,
                                   ProgressReporter reporter) throws IOException {
        Path dest = destination == null ? null : destination.toAbsolutePath().normalize();
        if (dest != null) {
            if (Files.isSymbolicLink(dest)) throw new IOException("ZIPX destination itself is a symbolic link: " + dest);
            Files.createDirectories(dest);
            dest = dest.toRealPath();
        }
        Path work = dest == null ? Files.createTempDirectory("ergou-zipx-verify-")
                : Files.createTempDirectory(dest, ".zipx-extract-");
        try (org.apache.commons.compress.archivers.zip.ZipFile zip = open(archive)) {
            List<ZipArchiveEntry> entries = Collections.list(zip.getEntries());
            Set<String> used = new HashSet<>();
            Set<String> regularNames = new HashSet<>();
            long total = 0;
            for (ZipArchiveEntry entry : entries) {
                safeRawName(entry.getRawName());
                String name = safeName(entry.getName());
                if (!used.add(name.replaceAll("/$", "").toLowerCase(Locale.ROOT))) throw new IOException("Duplicate ZIPX entry: " + name);
                if (!entry.isDirectory()) regularNames.add(name.toLowerCase(Locale.ROOT));
                if (entry.isUnixSymlink()) throw new IOException("ZIPX symbolic links are unsupported: " + name);
                if (dest != null) rejectLinks(dest.resolve(name));
                Method metadata = method(entry);
                if (metadata.strength != 0 && (password == null || password.isEmpty())) {
                    throw ArchiveExtractor.PasswordNeededException.of(archive);
                }
                if (entry.getSize() < 0 || entry.getCompressedSize() < 0) throw new IOException("Missing ZIPX entry size");
                total = Math.addExact(total, entry.getSize());
            }
            for (ZipArchiveEntry entry : entries) {
                String name = safeName(entry.getName()).replaceAll("/$", "");
                for (int slash = name.indexOf('/'); slash >= 0; slash = name.indexOf('/', slash + 1)) {
                    String parent = name.substring(0, slash);
                    if (regularNames.contains(parent.toLowerCase(Locale.ROOT))) throw new IOException("ZIPX file/directory name collision: " + parent);
                }
                if (dest != null) {
                    Path target = dest.resolve(name);
                    if (target.equals(archive.toRealPath())) throw new IOException("ZIPX extraction would replace its source archive");
                    if (Files.exists(target) && Files.isDirectory(target) != entry.isDirectory()) throw new IOException("ZIPX destination type conflict: " + target);
                    for (Path parent = target.getParent(); parent != null && parent.startsWith(dest); parent = parent.getParent()) {
                        if (Files.exists(parent) && !Files.isDirectory(parent)) throw new IOException("ZIPX destination parent is a file: " + parent);
                    }
                }
            }
            long done = 0;
            List<Path> files = new ArrayList<>();
            List<Path> directories = new ArrayList<>();
            for (ZipArchiveEntry entry : entries) {
                checkCancelled(reporter);
                Method metadata = method(entry);
                Path staged = work.resolve("files").resolve(safeName(entry.getName()));
                if (entry.isDirectory()) directories.add(staged);
                else if (dest != null) {
                    Files.createDirectories(staged.getParent());
                    files.add(staged);
                }
                Path compressed = work.resolve("authenticated");
                try {
                    if (metadata.strength != 0) {
                        try (InputStream raw = zip.getRawInputStream(entry)) {
                            ZipxAes.decrypt(raw, compressed, entry.getCompressedSize(), metadata.strength, password, reporter);
                        }
                    }
                    CRC32 crc = new CRC32();
                    try (InputStream raw = metadata.strength == 0 ? zip.getRawInputStream(entry) : Files.newInputStream(compressed);
                         InputStream decoded = decoder(raw, entry, metadata.code);
                         InputStream checked = new CheckedInputStream(decoded, crc);
                         OutputStream out = dest == null || entry.isDirectory() ? OutputStream.nullOutputStream() : Files.newOutputStream(staged)) {
                        long size = copy(checked, out, entry.getSize(), done, total, reporter, true);
                        if (size != entry.getSize()) throw new IOException("ZIPX uncompressed size mismatch: " + entry.getName());
                        if (metadata.aesVersion != 2 && crc.getValue() != entry.getCrc()) throw new IOException("ZIPX CRC mismatch: " + entry.getName());
                        done += size;
                    }
                } finally {
                    Files.deleteIfExists(compressed);
                }
            }
            checkCancelled(reporter);
            List<Path> exported = new ArrayList<>();
            if (dest != null) {
                Path stagedRoot = work.resolve("files");
                for (Path directory : directories) Files.createDirectories(dest.resolve(stagedRoot.relativize(directory)));
                for (Path file : files) {
                    Path target = dest.resolve(stagedRoot.relativize(file));
                    rejectLinks(target);
                    Files.createDirectories(target.getParent());
                    Files.move(file, target, StandardCopyOption.REPLACE_EXISTING);
                    exported.add(target);
                }
            }
            progress(reporter, 1f, true);
            return exported;
        } catch (ArithmeticException | IllegalArgumentException e) {
            throw new IOException("Invalid ZIPX metadata", e);
        } finally {
            deleteWork(work);
        }
    }

    /**
     * Opens the central directory, including ZIP64 entries and data descriptors.
     * @param archive archive path
     * @return archive reader
     * @throws IOException malformed ZIP records
     */
    private static org.apache.commons.compress.archivers.zip.ZipFile open(Path archive) throws IOException {
        return org.apache.commons.compress.archivers.zip.ZipFile.builder().setPath(archive).get();
    }

    /**
     * Validates AES metadata and resolves the actual compression method.
     * @param entry central-directory entry
     * @return validated method information
     * @throws IOException unsupported method or inconsistent AES headers
     */
    private static Method method(ZipArchiveEntry entry) throws IOException {
        int code = entry.getMethod(), version = 0, strength = 0;
        if (entry.getGeneralPurposeBit().usesStrongEncryption()) throw new IOException("ZIPX PKWARE strong encryption is unsupported");
        if (code == 99) {
            ZipExtraField field = entry.getExtraField(AES_ID);
            if (field == null || !entry.getGeneralPurposeBit().usesEncryption()) throw new IOException("Missing ZIPX AES metadata");
            byte[] aes = field.getCentralDirectoryData();
            if (aes.length < 7 || !Arrays.equals(aes, field.getLocalFileDataData()) || aes[2] != 'A' || aes[3] != 'E') {
                throw new IOException("Invalid ZIPX AES extra field");
            }
            version = ZipShort.getValue(aes, 0);
            strength = aes[4] & 255;
            if ((version != 1 && version != 2) || strength < 1 || strength > 3 || (version == 2 && entry.getCrc() != 0)) {
                throw new IOException("Invalid ZIPX AES version, strength or CRC");
            }
            code = ZipShort.getValue(aes, 5);
        } else if (entry.getGeneralPurposeBit().usesEncryption()) {
            throw new IOException("ZIPX traditional/strong encryption is unsupported; use WinZip AES");
        }
        if (!Set.of(0, 8, 9, 12, 14, 95).contains(code)) {
            String name = switch (code) {
                case 94 -> "MP3"; case 96 -> "JPEG"; case 97 -> "WavPack"; case 98 -> "PPMd";
                default -> "unknown";
            };
            throw new IOException("Unsupported ZIPX compression method " + code + " (" + name + "): " + entry.getName());
        }
        return new Method(code, version, strength);
    }

    /**
     * Creates a bounded-memory compressor, writing the ZIP-specific LZMA header when needed.
     * @param raw output payload stream
     * @param method selected compressor
     * @return compression stream
     * @throws IOException compressor setup failed
     */
    private static OutputStream encoder(OutputStream raw, ZipxMethod method) throws IOException {
        LZMA2Options options = new LZMA2Options(3);
        return switch (method) {
            case BZIP2 -> new BZip2CompressorOutputStream(raw);
            case XZ -> new XZOutputStream(raw, options);
            case LZMA -> {
                LZMAOutputStream lzma = new LZMAOutputStream(raw, options, true);
                raw.write(new byte[]{9, 20, 5, 0, (byte) lzma.getProps()});
                raw.write(ZipLong.getBytes(options.getDictSize()));
                yield lzma;
            }
        };
    }

    /**
     * Creates a decoder for a raw compressed entry.
     * @param raw bounded compressed payload stream
     * @param entry ZIP metadata including size and EOS flag
     * @param code actual method number
     * @return decoding stream
     * @throws IOException invalid compressed stream or excessive dictionary
     */
    private static InputStream decoder(InputStream raw, ZipArchiveEntry entry, int code) throws IOException {
        raw = new BufferedInputStream(raw, 65536);
        return switch (code) {
            case 0 -> raw;
            case 8 -> new org.apache.commons.compress.compressors.deflate.DeflateCompressorInputStream(raw,
                    rawDeflateParameters());
            case 9 -> new Deflate64CompressorInputStream(raw);
            case 12 -> new BZip2CompressorInputStream(raw);
            case 95 -> new XZInputStream(raw, MEMORY_LIMIT_KIB);
            case 14 -> {
                byte[] header = raw.readNBytes(9);
                if (header.length != 9 || ZipShort.getValue(header, 2) != 5) throw new IOException("Invalid ZIP LZMA properties header");
                long dictionary = ZipLong.getValue(header, 5);
                if (dictionary > Integer.MAX_VALUE || LZMAInputStream.getMemoryUsage((int) dictionary, header[4]) > MEMORY_LIMIT_KIB) {
                    throw new IOException("ZIPX LZMA dictionary exceeds 64 MiB memory limit");
                }
                yield new LZMAInputStream(raw, (entry.getRawFlag() & 2) != 0 ? -1 : entry.getSize(), header[4], (int) dictionary);
            }
            default -> throw new IOException("Unsupported ZIPX method: " + code);
        };
    }

    /**
     * Configures raw RFC 1951 Deflate as used in ZIP entries.
     * @return raw Deflate parameters
     */
    private static org.apache.commons.compress.compressors.deflate.DeflateParameters rawDeflateParameters() {
        var parameters = new org.apache.commons.compress.compressors.deflate.DeflateParameters();
        parameters.setWithZlibHeader(false);
        return parameters;
    }

    /**
     * Copies bytes while enforcing declared size and reporting archive progress.
     * @param in source stream
     * @param out destination stream
     * @param expected maximum declared size
     * @param done bytes completed in preceding entries
     * @param total total uncompressed bytes
     * @param reporter progress and cancellation callback
     * @param extracting whether this is extraction
     * @return bytes copied
     * @throws IOException size mismatch, cancellation or I/O failure
     */
    private static long copy(InputStream in, OutputStream out, long expected, long done, long total,
                              ProgressReporter reporter, boolean extracting) throws IOException {
        byte[] buffer = new byte[65536];
        long count = 0, reported = 0;
        int length;
        while ((length = in.read(buffer)) != -1) {
            checkCancelled(reporter);
            count += length;
            if (count > expected) throw new IOException("ZIPX data exceeds declared size");
            out.write(buffer, 0, length);
            if (count - reported >= 1048576) {
                progress(reporter, total == 0 ? 0f : Math.min(0.99f, (float) (done + count) / total), extracting);
                reported = count;
            }
        }
        return count;
    }

    /**
     * Rejects paths that cannot be extracted safely and consistently on both platforms.
     * @param name archive entry name
     * @return validated relative name
     * @throws IOException unsafe name
     */
    private static String safeName(String name) throws IOException {
        if (name == null || name.isEmpty() || name.startsWith("/") || name.endsWith("//")
                || name.contains("\\") || name.contains(":") || name.indexOf('\0') >= 0) {
            throw new IOException("Unsafe ZIPX entry name: " + name);
        }
        for (String component : name.split("/")) {
            if (component.isEmpty() || component.equals(".") || component.equals("..")) throw new IOException("Unsafe ZIPX entry name: " + name);
            if (component.endsWith(".") || component.endsWith(" ") || component.matches(".*[<>\"|?*\\p{Cntrl}].*")) {
                throw new IOException("Non-portable ZIPX entry name: " + name);
            }
            String stem = component.split("\\.", 2)[0].toUpperCase(Locale.ROOT);
            if (stem.matches("CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9]")) throw new IOException("Reserved ZIPX entry name: " + name);
        }
        return name;
    }

    /**
     * Checks original path bytes before a ZIP library can normalize backslashes or drive prefixes.
     * @param bytes raw ZIP filename bytes
     * @throws IOException unsafe original path
     */
    private static void safeRawName(byte[] bytes) throws IOException {
        String raw = new String(bytes, java.nio.charset.StandardCharsets.ISO_8859_1);
        if (raw.startsWith("/") || raw.contains("\\") || raw.contains(":") || raw.indexOf('\0') >= 0) {
            throw new IOException("Unsafe raw ZIPX entry name");
        }
        for (String component : raw.split("/")) {
            if (component.equals(".") || component.equals("..")) throw new IOException("Unsafe raw ZIPX traversal");
        }
    }

    /**
     * Rejects symlinks in the destination and its existing ancestors.
     * @param path destination path
     * @throws IOException symbolic-link destination
     */
    private static void rejectLinks(Path path) throws IOException {
        for (Path parent = path; parent != null; parent = parent.getParent()) {
            if (Files.isSymbolicLink(parent)) throw new IOException("ZIPX destination contains a symbolic link: " + parent);
        }
    }

    /**
     * Stops before further output when the user requests cancellation.
     * @param reporter optional callback
     * @throws IOException operation cancelled
     */
    private static void checkCancelled(ProgressReporter reporter) throws IOException {
        if (Thread.currentThread().isInterrupted() || (reporter != null && reporter.isCancelled())) throw new IOException("ZIPX operation cancelled");
    }

    /**
     * Reports progress on the archive phase.
     * @param reporter optional callback
     * @param fraction completion fraction
     * @param extracting whether this is extraction
     */
    private static void progress(ProgressReporter reporter, float fraction, boolean extracting) {
        if (reporter != null) {
            reporter.setStatus(Messages.get(extracting ? "status.extracting" : "status.archiving"), ProgressPhase.ARCHIVE);
            reporter.setProgress(fraction, "", ProgressPhase.ARCHIVE);
        }
    }

    /**
     * Removes only the private staging directory created by this operation.
     * @param work operation-owned directory
     * @throws IOException temporary cleanup failed
     */
    private static void deleteWork(Path work) throws IOException {
        try (var paths = Files.walk(work)) {
            for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) Files.deleteIfExists(path);
        }
    }
}
