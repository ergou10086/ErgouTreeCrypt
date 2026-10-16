package hbnu.project.ergoutreecrypt.fileops;

import hbnu.project.ergoutreecrypt.i18n.Messages;
import hbnu.project.ergoutreecrypt.volume.ProgressPhase;
import hbnu.project.ergoutreecrypt.volume.ProgressReporter;
import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;
import org.apache.commons.compress.archivers.zip.ZipExtraField;
import org.apache.commons.compress.archivers.zip.ZipLong;
import org.apache.commons.compress.archivers.zip.ZipShort;
import org.apache.commons.compress.compressors.bzip2.BZip2CompressorInputStream;
import org.apache.commons.compress.compressors.bzip2.BZip2CompressorOutputStream;
import org.apache.commons.compress.compressors.deflate64.Deflate64CompressorInputStream;
import org.tukaani.xz.*;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.*;
import java.util.zip.CRC32;
import java.util.zip.CheckedInputStream;

/**
 * 桌面与 Android 共享的可移植 ZIPX 核心。
 * 写入 BZip2/LZMA/XZ，读取存储、Deflate、Deflate64、BZip2、LZMA、XZ，并支持 WinZip AE-1/AE-2 AES-128/192/256；不支持的方法明确报错。
 * 提取文件替换用户可见输出之前，先验证所有条目。
 */
public final class ZipxArchive {
    private static final int MEMORY_LIMIT_KIB = 64 * 1024;
    private static final ZipShort AES_ID = new ZipShort(0x9901);

    /**
     * 禁止实例化。
     */
    private ZipxArchive() {
    }

    /**
     * 将明确指定的文件和目录打包为标准 ZIPX 归档。
     *
     * @param output 归档路径
     * @param entries 源路径
     * @param names 对应的归档条目名
     * @param method 压缩方法
     * @param password 可选的 UTF-8 编码 WinZip AES 密码
     * @param reporter 进度与取消回调
     * @throws IOException 条目无效、操作取消或归档失败
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
            if (!used.add(name.replaceAll("/$", "").toLowerCase(Locale.ROOT)))
                throw new IOException("Duplicate ZIPX entry: " + name);
            safeNames.add(name);
        }
        Files.createDirectories(target.getParent());
        Path work = Files.createTempDirectory(target.getParent(), ".zipx-pack-");
        Path staged = work.resolve("archive.zipx");
        try {
            long total = 0;
            for (Path source : entries)
                if (!Files.isDirectory(source)) total = Math.addExact(total, Files.size(source));
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
                    // 空 XZ 文件采用存储方式，避免外部解码器尚未消费编解码流就停止。
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
     * 不解码数据，仅检测原生加密和旧版加密条目。
     *
     * @param archive ZIP 或 ZIPX 路径
     * @return 是否有条目需要密码
     * @throws IOException 归档格式损坏
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
     * 即使扩展名为 .zip，也识别高级压缩方法。
     *
     * @param archive ZIP 路径
     * @return 是否需要扩展读取器
     * @throws IOException 中央目录格式损坏
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
     * 认证 AES 密文并检查解码大小和 CRC，不导出明文。
     *
     * @param archive ZIP 或 ZIPX 路径
     * @param password 可选归档密码
     * @throws IOException 认证、完整性校验失败或方法不受支持
     */
    public static void verify(Path archive, String password) throws IOException {
        read(archive, null, password, null);
    }

    /**
     * 提取已验证条目，并保留原始归档。
     *
     * @param archive ZIP 或 ZIPX 路径
     * @param destination 输出目录
     * @param password 可选归档密码
     * @param reporter 进度与取消回调
     * @return 提取的普通文件
     * @throws IOException 认证、完整性校验失败或路径不安全
     */
    public static List<Path> extract(Path archive, Path destination, String password,
                                     ProgressReporter reporter) throws IOException {
        return read(archive, destination, password, reporter);
    }

    /**
     * 在私有暂存目录中验证完整归档，然后才发布。
     *
     * @param archive 归档路径
     * @param destination 输出目录；仅认证时为 null
     * @param password 可选密码
     * @param reporter 进度回调
     * @return 导出的普通文件路径
     * @throws IOException 归档验证失败
     */
    private static List<Path> read(Path archive, Path destination, String password,
                                   ProgressReporter reporter) throws IOException {
        Path dest = destination == null ? null : destination.toAbsolutePath().normalize();
        if (dest != null) {
            if (Files.isSymbolicLink(dest))
                throw new IOException("ZIPX destination itself is a symbolic link: " + dest);
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
                if (!used.add(name.replaceAll("/$", "").toLowerCase(Locale.ROOT)))
                    throw new IOException("Duplicate ZIPX entry: " + name);
                if (!entry.isDirectory()) regularNames.add(name.toLowerCase(Locale.ROOT));
                if (entry.isUnixSymlink()) throw new IOException("ZIPX symbolic links are unsupported: " + name);
                if (dest != null) rejectLinks(dest.resolve(name));
                Method metadata = method(entry);
                if (metadata.strength != 0 && (password == null || password.isEmpty())) {
                    throw ArchiveExtractor.PasswordNeededException.of(archive);
                }
                if (entry.getSize() < 0 || entry.getCompressedSize() < 0)
                    throw new IOException("Missing ZIPX entry size");
                total = Math.addExact(total, entry.getSize());
            }
            for (ZipArchiveEntry entry : entries) {
                String name = safeName(entry.getName()).replaceAll("/$", "");
                for (int slash = name.indexOf('/'); slash >= 0; slash = name.indexOf('/', slash + 1)) {
                    String parent = name.substring(0, slash);
                    if (regularNames.contains(parent.toLowerCase(Locale.ROOT)))
                        throw new IOException("ZIPX file/directory name collision: " + parent);
                }
                if (dest != null) {
                    Path target = dest.resolve(name);
                    if (target.equals(archive.toRealPath()))
                        throw new IOException("ZIPX extraction would replace its source archive");
                    if (Files.exists(target) && Files.isDirectory(target) != entry.isDirectory())
                        throw new IOException("ZIPX destination type conflict: " + target);
                    for (Path parent = target.getParent(); parent != null && parent.startsWith(dest); parent = parent.getParent()) {
                        if (Files.exists(parent) && !Files.isDirectory(parent))
                            throw new IOException("ZIPX destination parent is a file: " + parent);
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
                        if (size != entry.getSize())
                            throw new IOException("ZIPX uncompressed size mismatch: " + entry.getName());
                        if (metadata.aesVersion != 2 && crc.getValue() != entry.getCrc())
                            throw new IOException("ZIPX CRC mismatch: " + entry.getName());
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
                for (Path directory : directories)
                    Files.createDirectories(dest.resolve(stagedRoot.relativize(directory)));
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
     * 打开中央目录，支持 ZIP64 条目和数据描述符。
     *
     * @param archive 归档路径
     * @return 归档读取器
     * @throws IOException ZIP 记录格式损坏
     */
    private static org.apache.commons.compress.archivers.zip.ZipFile open(Path archive) throws IOException {
        return org.apache.commons.compress.archivers.zip.ZipFile.builder().setPath(archive).get();
    }

    /**
     * 验证 AES 元数据并确定实际压缩方法。
     *
     * @param entry 中央目录条目
     * @return 已验证的方法信息
     * @throws IOException 方法不支持或 AES 头不一致
     */
    private static Method method(ZipArchiveEntry entry) throws IOException {
        int code = entry.getMethod(), version = 0, strength = 0;
        if (entry.getGeneralPurposeBit().usesStrongEncryption())
            throw new IOException("ZIPX PKWARE strong encryption is unsupported");
        if (code == 99) {
            ZipExtraField field = entry.getExtraField(AES_ID);
            if (field == null || !entry.getGeneralPurposeBit().usesEncryption())
                throw new IOException("Missing ZIPX AES metadata");
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
                case 94 -> "MP3";
                case 96 -> "JPEG";
                case 97 -> "WavPack";
                case 98 -> "PPMd";
                default -> "unknown";
            };
            throw new IOException("Unsupported ZIPX compression method " + code + " (" + name + "): " + entry.getName());
        }
        return new Method(code, version, strength);
    }

    /**
     * 创建有界内存的压缩器，必要时写入 ZIP 专用 LZMA 头。
     *
     * @param raw 载荷输出流
     * @param method 所选压缩器
     * @return 压缩输出流
     * @throws IOException 压缩器初始化失败
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
     * 创建原始压缩条目的解码器。
     *
     * @param raw 有界压缩载荷输入流
     * @param entry 包含大小与结束标志的 ZIP 元数据
     * @param code 实际方法编号
     * @return 解码输入流
     * @throws IOException 压缩流无效或字典超限
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
                if (header.length != 9 || ZipShort.getValue(header, 2) != 5)
                    throw new IOException("Invalid ZIP LZMA properties header");
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
     * 配置 ZIP 条目使用的 RFC 1951 原始 Deflate。
     *
     * @return 原始 Deflate 参数
     */
    private static org.apache.commons.compress.compressors.deflate.DeflateParameters rawDeflateParameters() {
        var parameters = new org.apache.commons.compress.compressors.deflate.DeflateParameters();
        parameters.setWithZlibHeader(false);
        return parameters;
    }

    /**
     * 复制字节，同时限制声明大小并报告归档进度。
     *
     * @param in 源输入流
     * @param out 目标输出流
     * @param expected 声明的最大大小
     * @param done 前面条目已完成的字节数
     * @param total 未压缩的总字节数
     * @param reporter 进度与取消回调
     * @param extracting 是否正在提取
     * @return 已复制的字节数
     * @throws IOException 大小不一致、操作取消或输入输出失败
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
     * 拒绝无法在双端安全且一致提取的路径。
     *
     * @param name 归档条目名
     * @return 已验证的相对名称
     * @throws IOException 名称不安全
     */
    private static String safeName(String name) throws IOException {
        if (name == null || name.isEmpty() || name.startsWith("/") || name.endsWith("//")
                || name.contains("\\") || name.contains(":") || name.indexOf('\0') >= 0) {
            throw new IOException("Unsafe ZIPX entry name: " + name);
        }
        for (String component : name.split("/")) {
            if (component.isEmpty() || component.equals(".") || component.equals(".."))
                throw new IOException("Unsafe ZIPX entry name: " + name);
            if (component.endsWith(".") || component.endsWith(" ") || component.matches(".*[<>\"|?*\\p{Cntrl}].*")) {
                throw new IOException("Non-portable ZIPX entry name: " + name);
            }
            String stem = component.split("\\.", 2)[0].toUpperCase(Locale.ROOT);
            if (stem.matches("CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9]"))
                throw new IOException("Reserved ZIPX entry name: " + name);
        }
        return name;
    }

    /**
     * 在 ZIP 库规范化反斜杠或驱动器前缀之前，检查原始路径字节。
     *
     * @param bytes ZIP 文件名原始字节
     * @throws IOException 原始路径不安全
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
     * 拒绝目标及其已有祖先目录中的符号链接。
     *
     * @param path 目标路径
     * @throws IOException 目标是符号链接
     */
    private static void rejectLinks(Path path) throws IOException {
        for (Path parent = path; parent != null; parent = parent.getParent()) {
            if (Files.isSymbolicLink(parent))
                throw new IOException("ZIPX destination contains a symbolic link: " + parent);
        }
    }

    /**
     * 用户请求取消后，停止继续输出。
     *
     * @param reporter 可选回调
     * @throws IOException 操作取消
     */
    private static void checkCancelled(ProgressReporter reporter) throws IOException {
        if (Thread.currentThread().isInterrupted() || (reporter != null && reporter.isCancelled()))
            throw new IOException("ZIPX operation cancelled");
    }

    /**
     * 报告归档阶段进度。
     *
     * @param reporter 可选回调
     * @param fraction 完成比例
     * @param extracting 是否正在提取
     */
    private static void progress(ProgressReporter reporter, float fraction, boolean extracting) {
        if (reporter != null) {
            reporter.setStatus(Messages.get(extracting ? "status.extracting" : "status.archiving"), ProgressPhase.ARCHIVE);
            reporter.setProgress(fraction, "", ProgressPhase.ARCHIVE);
        }
    }

    /**
     * 仅删除本次操作创建的私有暂存目录。
     *
     * @param work 当前操作拥有的目录
     * @throws IOException 临时文件清理失败
     */
    private static void deleteWork(Path work) throws IOException {
        try (var paths = Files.walk(work)) {
            for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) Files.deleteIfExists(path);
        }
    }

    /**
     * 条目的压缩与加密元数据解析结果。
     *
     * @param code 实际压缩方法
     * @param aesVersion AES 格式版本；普通条目为零
     * @param strength AES 强度代码；普通条目为零
     */
    private record Method(int code, int aesVersion, int strength) {
    }
}
