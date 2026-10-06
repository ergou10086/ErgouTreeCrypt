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
 * 带内嵌元数据的分卷与合并，兼容旧原始字节分卷和 .volumes 清单。
 * 每卷记录总数、编号、长度和批次；密文认证和 RS 修复仍由解密器完成。
 */
public final class Splitter {
    /** 每卷内嵌元数据长度；用户设置的卷大小应包含此开销。 */
    public static final int METADATA_BYTES = 64;
    private static final Pattern SPLIT_CHUNK_RE = Pattern.compile("(?i)\\.(pcv|ergou)\\.[0-9]+$");
    static final int MAX_CHUNKS = 1_000_000;
    private static final String FORMAT = "EGTC-SPLIT-1";

    /** 不允许实例化工具类。 */
    private Splitter() { }

    /**
     * * 一组分卷的预检查结果。编号与文件名一致，从 0 开始。
     * @param base 基础路径
     * @param expectedCount 总卷数（无元数据的旧分卷为已观察到的最大编号加一）
     * @param totalKnown 是否从内嵌元数据或旧清单得到准确总卷数
     * @param chunks 实际存在的有效编号文件
     * @param missing 缺失的编号
     * @param damaged 大小、元数据或批次不符，或非普通文件的编号
     * @param unexpected 超出总卷数范围的编号
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

        /** @throws IOException 缺卷、元数据不符或无分卷时拒绝合并。 */
        public void requireComplete() throws IOException {
            if (expectedCount == 0 || !missing.isEmpty() || !damaged.isEmpty() || !unexpected.isEmpty()) {
                throw new IOException(summary());
            }
        }
    }

    /**
     * * 获取分卷清单路径。
     * @param base 分卷基础路径
     * @return 与碎片放在同一目录的清单
     */
    public static Path manifestPath(Path base) { return Path.of(base + ".volumes"); }

    /**
     * * 识别加密分卷清单文件。
     * @param path 文件路径
     * @return 是否为 .ergou.volumes 或 .pcv.volumes
     */
    public static boolean isManifestPath(String path) {
        String name = Path.of(path).getFileName().toString().toLowerCase(Locale.ROOT);
        return name.endsWith(".ergou.volumes") || name.endsWith(".pcv.volumes");
    }

    /**
     * * 从任意剩余卷检查总数、缺卷、大小、编号和批次；兼容旧清单及无清单格式。
     * @param base 分卷基础路径
     * @return 预检查结果
     * @throws IOException 非法清单、编号或目录读取失败。
     */
    public static Inspection inspect(Path base) throws IOException { return scan(base).inspection(); }

    /** 分卷检查与合并共同使用的元数据快照，避免合并过程中切换到另一批次。 */
    private record Scan(Inspection inspection, Map<Integer, SplitMetadata> metadata) { }

    /**
     * @param base 分卷基础路径
     * @return 检查与元数据快照
     * @throws IOException 读取失败。
     */
    private static Scan scan(Path base) throws IOException {
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
                    if (index >= MAX_CHUNKS || !suffix.equals(Integer.toString(index))) throw new NumberFormatException();
                    found.put(index, p);
                } catch (NumberFormatException e) {
                    throw new IOException(Messages.format("split.invalidIndex", name), e);
                }
            }
        }
        Map<Integer, SplitMetadata> metadata = new TreeMap<>();
        Set<Integer> invalid = new HashSet<>();
        for (var entry : found.entrySet()) {
            if (!Files.isRegularFile(entry.getValue())) { invalid.add(entry.getKey()); continue; }
            try {
                SplitMetadata value = SplitMetadata.read(entry.getValue());
                if (value != null) metadata.put(entry.getKey(), value);
            } catch (IOException e) { invalid.add(entry.getKey()); }
        }
        SplitMetadata group = metadata.isEmpty() ? null : metadata.values().iterator().next();
        int count = group == null ? (found.isEmpty() ? 0 : found.lastKey() + 1) : group.count();
        boolean known = group != null;
        long total = group == null ? -1 : group.total(), size = group == null ? -1 : group.chunkSize();
        Path manifest = manifestPath(base);
        if (Files.exists(manifest)) {
            Properties props = new Properties();
            try (InputStream in = Files.newInputStream(manifest)) {
                byte[] bytes = in.readNBytes(4097);
                if (bytes.length > 4096) throw new IOException("manifest too large");
                props.load(new java.io.ByteArrayInputStream(bytes));
                if (!FORMAT.equals(props.getProperty("format"))) throw new IOException("unknown format");
                int oldCount = Integer.parseInt(props.getProperty("count"));
                long oldTotal = Long.parseLong(props.getProperty("bytes")), oldSize = Long.parseLong(props.getProperty("chunkSize"));
                long computed = oldTotal == 0 ? 1 : 1 + (oldTotal - 1) / Math.max(1, oldSize);
                if (oldSize <= 0 || oldTotal < 0 || oldCount <= 0 || oldCount > MAX_CHUNKS || computed != oldCount
                        || group != null && (oldCount != count || oldTotal != total || oldSize != size)) {
                    throw new IOException("inconsistent manifest");
                }
                count = oldCount; total = oldTotal; size = oldSize; known = true;
            } catch (IOException | IllegalArgumentException e) {
                throw new IOException(Messages.format("split.invalidManifest", manifest.getFileName()), e);
            }
        }
        List<Integer> missing = new ArrayList<>(), damaged = new ArrayList<>(), extra = new ArrayList<>();
        List<Path> chunks = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            Path p = found.get(i);
            if (p == null) { missing.add(i); continue; }
            if (!Files.isRegularFile(p)) { damaged.add(i); continue; }
            chunks.add(p);
            SplitMetadata member = metadata.get(i);
            boolean bad = invalid.contains(i);
            if (group != null) bad |= !group.sameGroup(member) || member != null && member.index() != i;
            if (known) {
                long payload = i == count - 1 ? total - (long) i * size : size;
                long overhead = group == null ? 0 : SplitMetadata.SIZE;
                bad |= payload > Long.MAX_VALUE - overhead || Files.size(p) != payload + overhead;
            }
            if (bad) damaged.add(i);
        }
        for (Integer i : found.keySet()) if (i >= count) extra.add(i);
        return new Scan(new Inspection(base, count, known, List.copyOf(chunks), List.copyOf(missing),
                List.copyOf(damaged), List.copyOf(extra)), Map.copyOf(metadata));
    }

    /**
     * * 为所选碎片、清单或目录生成预览；普通输入返回空字符串。
     * @param input 用户选择的路径
     * @return 卷数与缺卷提示，可包含多组分卷
     * @throws IOException 读取失败
     */
    public static String describeInput(Path input) throws IOException {
        return describeInputs(List.of(input));
    }

    /**
     * * 批量预览按基础路径去重，避免多选 N 个碎片时重复扫描 N 次。
     * @param inputs 选择的路径
     * @return 各组卷数与缺卷信息
     * @throws IOException 目录扫描失败
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

    /**
     * @param input 路径
     * @param bases 收集到的分卷基础路径。
     */
    private static void addInputBase(Path input, Set<Path> bases) {
        String path = input.toString();
        if (isSplitChunkPath(path)) bases.add(Path.of(splitChunkBase(path)).toAbsolutePath().normalize());
        else if (isManifestPath(path)) bases.add(Path.of(path.substring(0, path.length() - ".volumes".length())).toAbsolutePath().normalize());
    }

    /**
     * * 分卷文件，在每卷尾部写入相同批次的完整元数据。
     * @param inputPath 原始文件
     * @param chunkSize 每卷密文字节数（另加 64 字节元数据），必须为正数
     * @throws IOException 读写失败
     */
    public static void split(Path inputPath, long chunkSize) throws IOException {
        split(inputPath, chunkSize, null);
    }

    /**
     * * 支持进度与取消的分卷，空文件也产生一卷。
     * @param inputPath 原始文件
     * @param chunkSize 每卷密文字节数（另加 64 字节元数据）
     * @param reporter 进度回调，可为 null
     * @throws IOException 读写失败、原文件中途变化或数量过大
     */
    public static void split(Path inputPath, long chunkSize, ProgressReporter reporter) throws IOException {
        split(inputPath, chunkSize, reporter, true);
    }

    /**
     * * 保留原始随机载荷字节的传统伪装分卷，以独立清单提供准确卷数。
     * @param inputPath 原始文件
     * @param chunkSize 每卷最大字节数
     * @param reporter 进度回调
     * @throws IOException 读写失败或原文件变化。
     */
    public static void splitWithManifest(Path inputPath, long chunkSize, ProgressReporter reporter) throws IOException {
        split(inputPath, chunkSize, reporter, false);
    }

    /**
     * @param inputPath 原始文件
     * @param chunkSize 载荷大小
     * @param reporter 回调
     * @param embedded 是否内嵌元数据
     * @throws IOException 写入失败。
     */
    private static void split(Path inputPath, long chunkSize, ProgressReporter reporter, boolean embedded) throws IOException {
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
        UUID group = UUID.randomUUID();
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
                        if (embedded) out.write(new SplitMetadata(i, (int) count, total, chunkSize, group).encode());
                    }
                    if (i == count - 1 && in.read() != -1) throw new IOException("source changed during splitting");
                    checkCancelled(reporter);
                    moveCompleted(tmp, Path.of(inputPath + "." + i));
                    report(reporter, "split.writing", i + 1, (int) count);
                } finally { Files.deleteIfExists(tmp); }
            }
        }
        if (!embedded) {
            Path tmp = Path.of(manifest + ".incomplete");
            try {
                checkCancelled(reporter);
                Files.write(tmp, ("format=" + FORMAT + "\ncount=" + count + "\nbytes=" + total
                        + "\nchunkSize=" + chunkSize + "\n").getBytes(java.nio.charset.StandardCharsets.UTF_8));
                moveCompleted(tmp, manifest);
            } finally { Files.deleteIfExists(tmp); }
        }
    }

    /**
     * * 校验后顺序合并，失败时保留既有输出。
     * @param outputPath 合并输出
     * @param inputBase 分卷基础路径
     * @throws IOException 缺卷或读写失败
     */
    public static void recombine(Path outputPath, String inputBase) throws IOException {
        recombine(outputPath, inputBase, null);
    }

    /**
     * * 支持进度与取消的合并；在输出目录暂存，成功后原子替换。
     * @param outputPath 合并输出，不得覆盖碎片或清单
     * @param inputBase 分卷基础路径
     * @param reporter 进度回调，可为 null
     * @throws IOException 分卷异常或读写失败
     */
    public static void recombine(Path outputPath, String inputBase, ProgressReporter reporter) throws IOException {
        Scan initial = scan(Path.of(inputBase));
        Inspection inspection = initial.inspection();
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
                        SplitMetadata member = initial.metadata().get(i);
                        if (member == null) {
                            int n;
                            while ((n = in.read(buf)) != -1) {
                                checkCancelled(reporter);
                                out.write(buf, 0, n);
                            }
                        } else {
                            long remaining = member.payloadSize();
                            while (remaining > 0) {
                                checkCancelled(reporter);
                                int n = in.read(buf, 0, (int) Math.min(buf.length, remaining));
                                if (n < 0) throw new IOException("split volume changed during recombination");
                                out.write(buf, 0, n);
                                remaining -= n;
                            }
                            SplitMetadata tail = SplitMetadata.decode(in.readNBytes(SplitMetadata.SIZE));
                            if (!member.equals(tail) || in.read() != -1) throw new IOException("split metadata changed during recombination");
                        }
                    }
                    report(reporter, "split.reading", ++i, inspection.expectedCount());
                }
            }
            checkCancelled(reporter);
            Scan finished = scan(Path.of(inputBase));
            finished.inspection().requireComplete();
            if (!initial.metadata().equals(finished.metadata()) || !inspection.chunks().equals(finished.inspection().chunks())) {
                throw new IOException("split group changed during recombination");
            }
            moveCompleted(tmp, output);
        } finally { Files.deleteIfExists(tmp); }
    }

    /**
     * * 防止合并或解密的结果覆盖本组任一输入碎片或清单。
     * @param outputPath 结果路径
     * @param base 分卷基础路径
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
     * * 列出已存在的碎片，不返回不存在的占位路径。
     * @param basePath 分卷基础路径
     * @return 按编号排序的碎片
     * @throws IOException 扫描失败
     */
    public static List<Path> listChunks(Path basePath) throws IOException { return inspect(basePath).chunks(); }

    /**
     * * 列出可传输产物；仅旧格式可能包括清单。
     * @param base 分卷基础路径
     * @return 分卷及存在的旧清单
     * @throws IOException 扫描失败
     */
    public static List<Path> artifacts(Path base) throws IOException {
        List<Path> result = new ArrayList<>(listChunks(base));
        if (Files.isRegularFile(manifestPath(base))) result.add(manifestPath(base));
        return result;
    }

    /**
     * @param path 文件路径
     * @return 是否为受支持的分卷碎片。
     */
    public static boolean isSplitChunkPath(String path) {
        return SPLIT_CHUNK_RE.matcher(Path.of(path).getFileName().toString()).find();
    }

    /**
     * @param path 分卷路径
     * @return 基础路径，不是分卷时为 null。
     */
    public static String splitChunkBase(String path) {
        if (!isSplitChunkPath(path)) return null;
        return path.substring(0, path.lastIndexOf('.'));
    }

    /**
     * @param values 卷编号
     * @return 限长的文件名后缀列表。
     */
    private static String numbers(List<Integer> values) {
        StringJoiner join = new StringJoiner(", ");
        values.stream().limit(30).forEach(i -> join.add("." + i));
        if (values.size() > 30) join.add("… (" + values.size() + ")");
        return join.toString();
    }

    /**
     * @param reporter 回调
     * @throws CancellationException 用户取消或线程中断。
     */
    private static void checkCancelled(ProgressReporter reporter) {
        if (Thread.currentThread().isInterrupted() || reporter != null && reporter.isCancelled()) {
            throw new CancellationException("split cancelled");
        }
    }

    /**
     * @param reporter 回调
     * @param key 文案
     * @param current 已处理卷
     * @param total 总卷数。
     */
    private static void report(ProgressReporter reporter, String key, int current, int total) {
        if (reporter != null) {
            reporter.setStatus(Messages.format(key, current, total));
            reporter.setProgress((float) current / total, current + "/" + total);
            reporter.update();
        }
    }

    /**
     * @param from 临时文件
     * @param to 最终文件
     * @throws IOException 移动失败。
     */
    private static void moveCompleted(Path from, Path to) throws IOException {
        try { Files.move(from, to, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING); }
        catch (AtomicMoveNotSupportedException e) { Files.move(from, to, StandardCopyOption.REPLACE_EXISTING); }
    }
}