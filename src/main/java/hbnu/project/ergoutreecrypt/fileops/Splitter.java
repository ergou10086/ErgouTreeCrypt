package hbnu.project.ergoutreecrypt.fileops;

import hbnu.project.ergoutreecrypt.crypto.CryptoConstants;
import hbnu.project.ergoutreecrypt.i18n.Messages;
import hbnu.project.ergoutreecrypt.log.LogService;
import hbnu.project.ergoutreecrypt.volume.ProgressReporter;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.CancellationException;
import java.util.regex.Pattern;

/**
 * 原始字节分卷与合并；附带可移动的 .volumes 清单，兼容无清单的旧分卷。
 * 清单只记录数量和大小，密文认证和 RS 修复仍由解密器完成。
 */
public final class Splitter {
    private static final Pattern SPLIT_CHUNK_RE = Pattern.compile("(?i)\\.(pcv|ergou)\\.[0-9]+$");
    private static final int MAX_CHUNKS = 1_000_000;
    private static final String FORMAT = "EGTC-SPLIT-1";

    /** 不允许实例化工具类。 */
    private Splitter() { }

    /**
     * 一组分卷的预检查结果。编号与文件名一致，从 0 开始。
     * @param base 基础路径
     * @param expectedCount 总卷数（旧分卷为已观察到的最大编号加一）
     * @param totalKnown 是否从清单得到准确总卷数
     * @param chunks 实际存在的有效编号文件
     * @param missing 缺失的编号
     * @param damaged 大小不符或非普通文件的编号
     * @param unexpected 超出清单范围的编号
     */
    public record Inspection(Path base, int expectedCount, boolean totalKnown,
                             List<Path> chunks, List<Integer> missing,
                             List<Integer> damaged, List<Integer> unexpected) {
        /** @return 可显示的卷数和缺卷提示。 */
        public String summary() {
            String text = totalKnown
                    ? Messages.format("split.summary", base.getFileName(), expectedCount, chunks.size())
                    : Messages.format("split.legacy", base.getFileName(), chunks.size());
            if (!missing.isEmpty()) text += Messages.format("split.missing", numbers(missing));
            if (!damaged.isEmpty()) text += Messages.format("split.damaged", numbers(damaged));
            if (!unexpected.isEmpty()) text += Messages.format("split.unexpected", numbers(unexpected));
            return text;
        }

        /** @throws IOException 缺卷、清单不符或无分卷时拒绝合并。 */
        public void requireComplete() throws IOException {
            if (expectedCount == 0 || !missing.isEmpty() || !damaged.isEmpty() || !unexpected.isEmpty()) {
                throw new IOException(summary());
            }
        }
    }

    /**
     * 获取分卷清单路径。
     * @param base 分卷基础路径
     * @return 与碎片放在同一目录的清单
     */
    public static Path manifestPath(Path base) { return Path.of(base + ".volumes"); }

    /**
     * 识别加密分卷清单文件。
     * @param path 文件路径
     * @return 是否为 .ergou.volumes 或 .pcv.volumes
     */
    public static boolean isManifestPath(String path) {
        String name = Path.of(path).getFileName().toString().toLowerCase(Locale.ROOT);
        return name.endsWith(".ergou.volumes") || name.endsWith(".pcv.volumes");
    }

    /**
     * 检查同目录所有分卷，发现缺卷（包括末卷）、大小异常和多余卷。
     * 无清单时保留旧格式读取，但无法确认是否缺末卷。
     * @param base 分卷基础路径
     * @return 预检查结果，不修改任何文件
     * @throws IOException 清单非法或目录无法读取
     */
    public static Inspection inspect(Path base) throws IOException {
        Path dir = base.getParent() == null ? Path.of(".") : base.getParent();
        String prefix = base.getFileName() + ".";
        SortedMap<Integer, Path> found = new TreeMap<>();
        try (DirectoryStream<Path> ds = Files.newDirectoryStream(dir)) {
            for (Path p : ds) {
                String name = p.getFileName().toString();
                if (!name.startsWith(prefix)) continue;
                String suffix = name.substring(prefix.length());
                if (!suffix.matches("[0-9]+")) continue;
                try {
                    int index = Integer.parseInt(suffix);
                    if (index >= MAX_CHUNKS || !suffix.equals(Integer.toString(index))) {
                        throw new NumberFormatException();
                    }
                    found.put(index, p);
                } catch (NumberFormatException e) {
                    throw new IOException(Messages.format("split.invalidIndex", name), e);
                }
            }
        }
        Path manifest = manifestPath(base);
        boolean known = Files.exists(manifest);
        int count = found.isEmpty() ? 0 : found.lastKey() + 1;
        long total = -1, size = -1;
        if (known) {
            Properties props = new Properties();
            try (InputStream in = Files.newInputStream(manifest)) {
                byte[] bytes = in.readNBytes(4097);
                if (bytes.length > 4096) throw new IOException("manifest too large");
                props.load(new java.io.ByteArrayInputStream(bytes));
                if (!FORMAT.equals(props.getProperty("format"))) throw new IOException("unknown format");
                count = Integer.parseInt(props.getProperty("count"));
                total = Long.parseLong(props.getProperty("bytes"));
                size = Long.parseLong(props.getProperty("chunkSize"));
                long computed = total == 0 ? 1 : 1 + (total - 1) / Math.max(1, size);
                if (size <= 0 || total < 0 || count <= 0 || count > MAX_CHUNKS || computed != count) {
                    throw new IOException("inconsistent manifest");
                }
            } catch (IOException | IllegalArgumentException e) {
                throw new IOException(Messages.format("split.invalidManifest", manifest.getFileName()), e);
            }
        }
        List<Integer> missing = new ArrayList<>(), damaged = new ArrayList<>(), extra = new ArrayList<>();
        List<Path> chunks = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            Path p = found.get(i);
            if (p == null) missing.add(i);
            else if (!Files.isRegularFile(p)) damaged.add(i);
            else {
                chunks.add(p);
                if (known && Files.size(p) != (i == count - 1 ? total - (long) i * size : size)) {
                    damaged.add(i);
                }
            }
        }
        for (Integer i : found.keySet()) if (i >= count) extra.add(i);
        return new Inspection(base, count, known, List.copyOf(chunks), List.copyOf(missing),
                List.copyOf(damaged), List.copyOf(extra));
    }

    /**
     * 为所选碎片、清单或目录生成预览；普通输入返回空字符串。
     * @param input 用户选择的路径
     * @return 卷数与缺卷提示，可包含多组分卷
     * @throws IOException 读取失败
     */
    public static String describeInput(Path input) throws IOException {
        return describeInputs(List.of(input));
    }

    /**
     * 批量预览按基础路径去重，避免多选 N 个碎片时重复扫描 N 次。
     * @param inputs 选择的路径 @return 各组卷数与缺卷信息 @throws IOException 目录扫描失败
     */
    public static String describeInputs(Collection<Path> inputs) throws IOException {
        Set<Path> bases = new LinkedHashSet<>();
        for (Path input : inputs) {
            if (Files.isDirectory(input)) {
                ArrayDeque<Path> folders = new ArrayDeque<>();
                folders.add(input);
                int entries = 0;
                while (!folders.isEmpty()) {
                    try (DirectoryStream<Path> children = Files.newDirectoryStream(folders.removeFirst())) {
                        for (Path child : children) {
                            if (++entries > MAX_CHUNKS) throw new IOException("too many directory entries");
                            if (Files.isDirectory(child, LinkOption.NOFOLLOW_LINKS)) folders.add(child);
                            else addInputBase(child, bases);
                        }
                    }
                }
            } else addInputBase(input, bases);
        }
        StringJoiner descriptions = new StringJoiner("\n");
        for (Path base : bases) {
            try { descriptions.add(inspect(base).summary()); }
            catch (IOException e) { descriptions.add(e.getMessage()); }
        }
        return descriptions.toString();
    }

    /** @param input 路径 @param bases 收集到的分卷基础路径。 */
    private static void addInputBase(Path input, Set<Path> bases) {
        String path = input.toString();
        if (isSplitChunkPath(path)) bases.add(Path.of(splitChunkBase(path)).toAbsolutePath().normalize());
        else if (isManifestPath(path)) bases.add(Path.of(path.substring(0, path.length() - ".volumes".length())).toAbsolutePath().normalize());
    }

    /**
     * 分卷文件，完成后写入清单。
     * @param inputPath 原始文件
     * @param chunkSize 每卷最大字节数，必须为正数
     * @throws IOException 读写失败
     */
    public static void split(Path inputPath, long chunkSize) throws IOException {
        split(inputPath, chunkSize, null);
    }

    /**
     * 支持进度与取消的分卷，空文件也产生一卷。
     * @param inputPath 原始文件
     * @param chunkSize 每卷最大字节数
     * @param reporter 进度回调，可为 null
     * @throws IOException 读写失败、原文件中途变化或数量过大
     */
    public static void split(Path inputPath, long chunkSize, ProgressReporter reporter) throws IOException {
        if (chunkSize <= 0) throw new IllegalArgumentException("chunkSize must be positive");
        long total = Files.size(inputPath);
        long count = total == 0 ? 1 : 1 + (total - 1) / chunkSize;
        if (count > MAX_CHUNKS) throw new IOException("too many split volumes");
        checkCancelled(reporter);
        Path manifest = manifestPath(inputPath);
        Files.deleteIfExists(manifest);
        Files.deleteIfExists(Path.of(manifest + ".incomplete"));
        Path dir = inputPath.getParent() == null ? Path.of(".") : inputPath.getParent();
        String prefix = inputPath.getFileName() + ".";
        try (DirectoryStream<Path> ds = Files.newDirectoryStream(dir)) {
            for (Path p : ds) {
                String name = p.getFileName().toString();
                if (name.startsWith(prefix) && name.substring(prefix.length()).matches("[0-9]+(?:\\.incomplete)?")) {
                    if (!Files.isRegularFile(p)) throw new IOException("split target is not a file: " + p);
                    Files.delete(p);
                }
            }
        }
        LogService.info("Splitter", "分卷 " + inputPath.getFileName() + " → " + count);
        try (InputStream in = Files.newInputStream(inputPath)) {
            byte[] buf = new byte[CryptoConstants.MIB];
            for (int i = 0; i < count; i++) {
                Path tmp = Path.of(inputPath + "." + i + ".incomplete");
                try {
                    long remaining = Math.min(chunkSize, total - (long) i * chunkSize);
                    try (OutputStream out = Files.newOutputStream(tmp)) {
                        while (remaining > 0) {
                            checkCancelled(reporter);
                            int n = in.read(buf, 0, (int) Math.min(buf.length, remaining));
                            if (n < 0) throw new IOException("source changed during splitting");
                            out.write(buf, 0, n);
                            remaining -= n;
                        }
                    }
                    checkCancelled(reporter);
                    moveCompleted(tmp, Path.of(inputPath + "." + i));
                    report(reporter, "split.writing", i + 1, (int) count);
                } finally { Files.deleteIfExists(tmp); }
            }
            if (in.read() != -1) throw new IOException("source changed during splitting");
        }
        Path tmpManifest = Path.of(manifest + ".incomplete");
        try {
            checkCancelled(reporter);
            Files.write(tmpManifest, ("format=" + FORMAT + "\ncount=" + count
                    + "\nbytes=" + total + "\nchunkSize=" + chunkSize + "\n").getBytes(java.nio.charset.StandardCharsets.UTF_8));
            moveCompleted(tmpManifest, manifest);
        } finally { Files.deleteIfExists(tmpManifest); }
    }

    /**
     * 校验后顺序合并，失败时保留既有输出。
     * @param outputPath 合并输出
     * @param inputBase 分卷基础路径
     * @throws IOException 缺卷或读写失败
     */
    public static void recombine(Path outputPath, String inputBase) throws IOException {
        recombine(outputPath, inputBase, null);
    }

    /**
     * 支持进度与取消的合并；在输出目录暂存，成功后原子替换。
     * @param outputPath 合并输出，不得覆盖碎片或清单
     * @param inputBase 分卷基础路径
     * @param reporter 进度回调，可为 null
     * @throws IOException 分卷异常或读写失败
     */
    public static void recombine(Path outputPath, String inputBase, ProgressReporter reporter) throws IOException {
        Inspection inspection = inspect(Path.of(inputBase));
        if (reporter != null) reporter.setStatus(inspection.summary());
        inspection.requireComplete();
        Path output = outputPath.toAbsolutePath().normalize();
        requireSeparateOutput(outputPath,Path.of(inputBase));
        checkCancelled(reporter);
        Path tmp = Files.createTempFile(output.getParent(), ".ergou-merge-", ".incomplete");
        try {
            try (OutputStream out = Files.newOutputStream(tmp)) {
                byte[] buf = new byte[CryptoConstants.MIB];
                int i = 0;
                for (Path source : inspection.chunks()) {
                    try (InputStream in = Files.newInputStream(source)) {
                        int n;
                        while ((n = in.read(buf)) != -1) {
                            checkCancelled(reporter);
                            out.write(buf, 0, n);
                        }
                    }
                    report(reporter, "split.reading", ++i, inspection.expectedCount());
                }
            }
            checkCancelled(reporter);
            inspect(Path.of(inputBase)).requireComplete();
            moveCompleted(tmp, output);
        } finally { Files.deleteIfExists(tmp); }
    }

    /**
     * 防止合并或解密的结果覆盖本组任一输入碎片或清单。
     * @param outputPath 结果路径 @param base 分卷基础路径
     * @throws IOException 输出与输入相同或扫描失败
     */
    public static void requireSeparateOutput(Path outputPath,Path base) throws IOException {
        Path output=outputPath.toAbsolutePath().normalize();
        for(Path source:artifacts(base)) {
            if(source.toAbsolutePath().normalize().equals(output)
                    ||(Files.exists(output)&&Files.isSameFile(source,output))) {
                throw new IOException("cannot overwrite split input: "+source);
            }
        }
    }

    /**
     * 列出已存在的碎片，不返回不存在的占位路径。
     * @param basePath 分卷基础路径
     * @return 按编号排序的碎片
     * @throws IOException 扫描失败
     */
    public static List<Path> listChunks(Path basePath) throws IOException { return inspect(basePath).chunks(); }

    /**
     * 列出完整的可传输产物，包括清单。
     * @param base 分卷基础路径
     * @return 分卷及清单
     * @throws IOException 扫描失败
     */
    public static List<Path> artifacts(Path base) throws IOException {
        List<Path> result = new ArrayList<>(listChunks(base));
        if (Files.isRegularFile(manifestPath(base))) result.add(manifestPath(base));
        return result;
    }

    /** @param path 文件路径 @return 是否为受支持的分卷碎片。 */
    public static boolean isSplitChunkPath(String path) {
        return SPLIT_CHUNK_RE.matcher(Path.of(path).getFileName().toString()).find();
    }

    /** @param path 分卷路径 @return 基础路径，不是分卷时为 null。 */
    public static String splitChunkBase(String path) {
        if (!isSplitChunkPath(path)) return null;
        return path.substring(0, path.lastIndexOf('.'));
    }

    /** @param values 卷编号 @return 限长的文件名后缀列表。 */
    private static String numbers(List<Integer> values) {
        StringJoiner join = new StringJoiner(", ");
        values.stream().limit(30).forEach(i -> join.add("." + i));
        if (values.size() > 30) join.add("… (" + values.size() + ")");
        return join.toString();
    }

    /** @param reporter 回调 @throws CancellationException 用户取消或线程中断。 */
    private static void checkCancelled(ProgressReporter reporter) {
        if (Thread.currentThread().isInterrupted() || reporter != null && reporter.isCancelled()) {
            throw new CancellationException("split cancelled");
        }
    }

    /** @param reporter 回调 @param key 文案 @param current 已处理卷 @param total 总卷数。 */
    private static void report(ProgressReporter reporter, String key, int current, int total) {
        if (reporter != null) {
            reporter.setStatus(Messages.format(key, current, total));
            reporter.setProgress((float) current / total, current + "/" + total);
            reporter.update();
        }
    }

    /** @param from 临时文件 @param to 最终文件 @throws IOException 移动失败。 */
    private static void moveCompleted(Path from, Path to) throws IOException {
        try { Files.move(from, to, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING); }
        catch (AtomicMoveNotSupportedException e) { Files.move(from, to, StandardCopyOption.REPLACE_EXISTING); }
    }
}