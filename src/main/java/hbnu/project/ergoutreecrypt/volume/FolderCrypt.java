package hbnu.project.ergoutreecrypt.volume;

import hbnu.project.ergoutreecrypt.encoding.RsCodecs;
import hbnu.project.ergoutreecrypt.fileops.ArchiveExtractor;
import hbnu.project.ergoutreecrypt.fileops.ArchivePacker;
import hbnu.project.ergoutreecrypt.fileops.ArchivePostExtract;
import hbnu.project.ergoutreecrypt.fileops.Splitter;
import hbnu.project.ergoutreecrypt.i18n.Messages;
import hbnu.project.ergoutreecrypt.log.LogService;
import hbnu.project.ergoutreecrypt.settings.SettingsManager;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.*;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * 文件夹 / 分卷 / 归档 的高层加解密编排。
 *
 * <p>在 {@link Encryptor} / {@link Decryptor}（处理单卷）之上提供面向"文件夹与多文件"的能力：
 *
 * <h2>加密</h2>
 * <ul>
 *   <li>输入文件夹，递归加密其中所有文件，镜像保留子目录结构。</li>
 *   <li>未勾选压缩：输出到与输入同名的文件夹（位于输出目标位置）。</li>
 *   <li>勾选压缩：将所有加密结果整体打成"一个"压缩包（压缩永远是最后一步）。</li>
 *   <li>勾选分卷：每个文件先分卷成一块块加密碎片，碎片放入各自的同名子文件夹，便于解密自动识别；
 *       若同时勾选压缩，则把这些子文件夹整体打成一个压缩包。</li>
 * </ul>
 *
 * <h2>解密（自动识别输入类型）</h2>
 * <ul>
 *   <li>明文压缩包（解压后解密）：先解压再逐个解密其中的加密文件 / 分卷。</li>
 *   <li>分卷碎片文件夹（含 {@code name.0, name.1, ...}）：合并后解密为单个文件。</li>
 *   <li>普通文件夹：递归解密其中所有加密文件（含其下的分卷碎片子文件夹）。</li>
 *   <li>单个 {@code .ergou}/{@code .pcv} 文件：直接解密；
 *       若勾选解密后解压且产物为归档，再解压到同名文件夹并保留压缩包。</li>
 * </ul>
 *
 * @author ErgouTree
 */
public final class FolderCrypt {

    /**
     * 单卷加密文件扩展名。
     */
    public static final String ENC_EXT = ".ergou";

    private static final Pattern CHUNK_RE = Pattern.compile("^(.*)\\.([0-9]+)$");

    private FolderCrypt() {
    }

    // ================================================================
    // 加密：文件夹
    // ================================================================

    /**
     * 加密整个文件夹，按 {@link EncryptOptions#encryptDepth} 控制迭代深度。
     *
     * <p>深度内的文件逐一加密为 .ergou；超出深度的目录先打成 ZIP 压缩包再加密为单个 .ergou。
     *
     * @param inputDir  输入文件夹
     * @param outputDir 输出位置（最终结果文件夹/压缩包将放在此目录下）
     * @param opts      公共加密选项（密码、RS、分卷、压缩等）
     */
    public static void encryptFolder(Path inputDir, Path outputDir, EncryptOptions opts) throws Exception {
        String folderName = inputDir.getFileName().toString();
        int maxDepth = opts.encryptDepth;

        // Step 1: 按深度收集待加密文件与"深目录"
        List<Path> filesToEncrypt = new ArrayList<>();
        List<Path> deepDirs = new ArrayList<>();
        collectByDepth(inputDir, inputDir, 0, maxDepth, filesToEncrypt, deepDirs);

        // 过滤掉空的深目录
        deepDirs = deepDirs.stream()
                .filter(d -> hasFiles(d))
                .toList();

        if (filesToEncrypt.isEmpty() && deepDirs.isEmpty()) {
            throw new IOException("input folder is empty: " + inputDir);
        }

        // 加密结果先落到一个工作目录（与输入同名），再视情况打包
        Path workDir = outputDir.resolve(folderName);
        Files.createDirectories(workDir);

        ProgressReporter reporter = opts.reporter;
        int total = filesToEncrypt.size() + deepDirs.size();

        // 预创建所有目标目录（单线程，避免竞态）
        for (Path src : filesToEncrypt) {
            Path rel = inputDir.relativize(src);
            Path destEnc = workDir.resolve(rel.toString() + ENC_EXT);
            Files.createDirectories(destEnc.getParent());
            if (opts.split) {
                Path chunkDir = destEnc.getParent().resolve(stripExt(destEnc.getFileName().toString()));
                Files.createDirectories(chunkDir);
            }
        }
        for (Path deepDir : deepDirs) {
            Path rel = inputDir.relativize(deepDir);
            // 深目录的加密输出放在其父目录镜像位置下：例如 sub1/deep/ → sub1/deep.zip.ergou
            Path parentInWork = rel.getParent() != null
                    ? workDir.resolve(rel.getParent().toString())
                    : workDir;
            Path destEnc = parentInWork.resolve(rel.getFileName().toString() + ".zip.ergou");
            Files.createDirectories(destEnc.getParent());
            if (opts.split) {
                Path chunkDir = destEnc.getParent().resolve(stripExt(destEnc.getFileName().toString()));
                Files.createDirectories(chunkDir);
            }
        }

        // 线程数：总大小达阈值则单线程；并行时用聚合器以最慢任务为基准
        BatchResult result = new BatchResult();
        opts.batchResult = result;
        long totalBytes = sumFileSizes(filesToEncrypt) + sumDirSizes(deepDirs);
        int threads = Math.max(1, Math.min(
                resolveThreadCount(opts.threadCount, totalBytes, false, result), total));
        result.setThreadCountUsed(threads);
        LogService.info("FolderCrypt", "开始加密文件夹 " + folderName
                + " files=" + filesToEncrypt.size()
                + " deepDirs=" + deepDirs.size()
                + " size=" + LogService.humanSize(totalBytes)
                + " threads=" + threads);
        ParallelProgressAggregator progress = (reporter != null && threads > 1)
                ? new ParallelProgressAggregator(reporter, total) : null;
        AtomicInteger completed = new AtomicInteger(0);

        List<BatchJob> jobs = new ArrayList<>(total);
        for (Path src : filesToEncrypt) {
            final Path file = src;
            jobs.add(new BatchJob(inputDir.relativize(file).toString(), taskReporter ->
                    encryptPlainFile(file, inputDir, workDir, opts, taskReporter)));
        }
        for (Path deepDir : deepDirs) {
            final Path dir = deepDir;
            Path rel = inputDir.relativize(dir);
            String label = rel.getFileName() + " (archived)";
            jobs.add(new BatchJob(label, taskReporter ->
                    encryptDeepDirectory(dir, inputDir, workDir, opts, taskReporter)));
        }

        processJobs(jobs, threads, true, reporter, progress, completed, total, result);

        if (result.succeededCount() == 0 && result.failedCount() > 0) {
            BatchResult.Failure first = result.failures().get(0);
            throw new IOException("全部文件加密失败：" + first.name() + " — " + first.message());
        }

        // 若启用压缩：只打包工作目录中已成功写出的文件（失败文件不会落盘）。
        if (opts.archiveFormat != null && !opts.archiveFormat.isEmpty()
                && result.succeededCount() > 0) {
            if (reporter != null) {
                reporter.setStatus(Messages.get("status.archiving"), ProgressPhase.ARCHIVE);
                reporter.setProgress(0f, "", ProgressPhase.ARCHIVE);
            }
            ArchivePacker.Format fmt = ArchivePacker.parseFormat(opts.archiveFormat);
            Path archivePath = outputDir.resolve(folderName + ArchivePacker.extOf(fmt));
            List<Path> entries;
            try (Stream<Path> walk = Files.walk(workDir)) {
                entries = walk.filter(Files::isRegularFile).sorted().toList();
            }
            if (!entries.isEmpty()) {
                ArchivePacker.packEntries(archivePath, workDir, entries, fmt,
                        ArchivePacker.resolveArchivePassword(opts.archivePassword, opts.password, fmt),
                        reporter);
                deleteRecursively(workDir);
            }
            if (reporter != null) {
                reporter.setProgress(1f, "", ProgressPhase.ARCHIVE);
            }
        }

        if (reporter != null) {
            reporter.setProgress(1f, "");
        }
        result.logSummary("FolderCrypt");
        LogService.info("FolderCrypt", "文件夹加密完成: " + folderName);
    }

    // ================================================================
    // 解密：自动识别输入类型
    // ================================================================

    /**
     * 解密任意输入：自动识别压缩包 / 分卷碎片文件夹 / 普通文件夹 / 单个加密文件。
     *
     * @param input     输入路径
     * @param outputDir 输出目录
     * @param opts      解密选项
     */
    public static void decryptAuto(Path input, Path outputDir, DecryptOptions opts) throws Exception {
        LogService.info("FolderCrypt", "开始自动解密 " + input.getFileName());
        BatchResult result = new BatchResult();
        opts.batchResult = result;
        DecryptStats stats = new DecryptStats();
        if (Files.isDirectory(input)) {
            // 输入文件夹：可能是单文件分卷碎片夹，或普通文件夹
            String chunkBase = detectChunkBase(input);
            if (chunkBase != null) {
                Files.createDirectories(outputDir);
                Path out = outputDir.resolve(stripEncExt(chunkBase));
                decryptRecombine(input.resolve(chunkBase), out, opts);
                stats.decrypted.incrementAndGet();
                result.addSuccess(chunkBase);
                maybePostExtractSingle(out, opts, stats);
            } else {
                decryptDirectory(input, outputDir, input.getFileName().toString(), opts, stats, 0, false);
            }
        } else if (ArchiveExtractor.isArchive(input)) {
            if (opts.extractThenDecrypt) {
                decryptArchive(input, outputDir, opts, stats, 0);
            } else {
                throw new NoDecryptableFilesException(
                        "未勾选解压后解密，无法将明文压缩包作为加密文件处理：" + input.getFileName());
            }
        } else {
            // 单个文件：可能是分卷碎片、加密文件、或不可解密文件
            String fn = input.getFileName().toString();
            if (Splitter.isSplitChunkPath(input.toString())) {
                // 单个分卷碎片：在所在目录查找所有兄弟碎片，合并解密
                String base = Splitter.splitChunkBase(input.toString());
                if (base == null) {
                    throw new NoDecryptableFilesException(
                            "无法识别分卷碎片文件：" + fn);
                }
                Files.createDirectories(outputDir);
                Path out = outputDir.resolve(stripEncExt(Path.of(base).getFileName().toString()));
                decryptRecombine(Path.of(base), out, opts);
                stats.decrypted.incrementAndGet();
                result.addSuccess(Path.of(base).getFileName().toString());
                maybePostExtractSingle(out, opts, stats);
            } else if (!isEncryptedName(fn)) {
                throw new NoDecryptableFilesException(
                        "无法解密：文件后缀不是受支持的加密格式（.ergou/.pcv）：" + input.getFileName());
            } else {
                Files.createDirectories(outputDir);
                Path out = outputDir.resolve(stripEncExt(fn));
                decryptSingle(input, out, opts);
                stats.decrypted.incrementAndGet();
                result.addSuccess(fn);
                maybePostExtractSingle(out, opts, stats);
            }
        }

        // 全部输入都没有产生任何输出时报错；否则（哪怕只解密了 1 个，或仅原样输出了嵌套压缩包）视为成功。
        result.addSkipped(stats.skipped);
        result.logSummary("FolderCrypt");
        if (stats.decrypted.get() == 0 && stats.archivesPassthrough.get() == 0) {
            throw new NoDecryptableFilesException(
                    "未找到任何可解密的文件（.ergou/.pcv）；已跳过 " + stats.skipped + " 个不可解密文件"
                            + (result.failedCount() > 0
                            ? "，失败 " + result.failedCount() + " 个。"
                            : "。"));
        }
    }

    /**
     * 解密压缩包：解压（可带密码）后逐个解密内部加密文件。
     *
     * <p>嵌套压缩包的处理深度由 {@link DecryptOptions#recursiveExtract} 决定：
     * 未勾选最多 {@link ArchivePostExtract#DEFAULT_MAX_DEPTH} 层，
     * 勾选最多 {@link ArchivePostExtract#RECURSIVE_MAX_DEPTH} 层。
     *
     * @param depth 当前解压深度（最外层为 0）
     */
    private static void decryptArchive(Path archive, Path outputDir, DecryptOptions opts,
                                       DecryptStats stats, int depth) throws Exception {
        Files.createDirectories(outputDir);
        ProgressReporter reporter = opts.reporter;

        String base = stripArchiveExt(archive.getFileName().toString());
        Path extractDir = Files.createTempDirectory("ergou-extract-");
        try {
            if (reporter != null) {
                reporter.setStatus(Messages.get("status.extracting"), ProgressPhase.ARCHIVE);
                reporter.setProgress(0f, "", ProgressPhase.ARCHIVE);
            }
            String archPwd = ArchivePacker.resolveArchivePassword(
                    opts.archivePassword, opts.password);
            ArchiveExtractor.extractPreserving(archive, extractDir, archPwd, reporter);
            // 解压结果可能是普通加密文件、分卷碎片子目录、嵌套压缩包或多层目录结构，统一交给目录解密逻辑。
            decryptDirectory(extractDir, outputDir, base, opts, stats, depth, true);
        } finally {
            deleteRecursively(extractDir);
        }
    }

    /**
     * 解密一个目录，镜像保留结构输出到 {@code outputDir/<mirrorName>}：
     * 分卷碎片子目录合并解密为单文件；普通加密文件逐个解密；嵌套压缩包递归处理。
     * 不可解密后缀的文件将被跳过（计入 {@code stats.skipped}）。
     *
     * @param forceSerial 为 true 时忽略配置线程数与大小阈值，始终单线程
     *                    （压缩包解压后解密、以及嵌套归档）
     */
    private static void decryptDirectory(Path dir, Path outputDir, String mirrorName,
                                         DecryptOptions opts, DecryptStats stats,
                                         int depth, boolean forceSerial) throws Exception {
        // 若 dir 本身就是单个文件的分卷碎片集合（如解压后顶层即碎片），合并解密为单文件。
        String selfBase = detectChunkBase(dir);
        if (selfBase != null) {
            Files.createDirectories(outputDir);
            Path out = outputDir.resolve(stripEncExt(selfBase));
            decryptRecombine(dir.resolve(selfBase), out, opts);
            stats.decrypted.incrementAndGet();
            ensureDecryptResult(opts).addSuccess(selfBase);
            maybePostExtractSingle(out, opts, stats);
            return;
        }

        Path mirrorRoot = outputDir.resolve(mirrorName);
        Files.createDirectories(mirrorRoot);

        boolean allowNested = (depth + 1) < archiveDepthLimit(opts);
        List<Unit> units = collectUnits(dir, stats, allowNested);
        ProgressReporter reporter = opts.reporter;
        int total = units.size();
        if (total == 0) {
            if (reporter != null) {
                reporter.setProgress(1f, "");
            }
            return;
        }

        for (Unit u : units) {
            Path relParent = dir.relativize(u.relativeTo);
            Path destParent = mirrorRoot.resolve(relParent.toString());
            Files.createDirectories(destParent);
        }

        BatchResult result = ensureDecryptResult(opts);
        boolean serial = forceSerial || depth > 0;
        long totalBytes = sumUnitSizes(units);
        int threads = Math.max(1, Math.min(
                resolveThreadCount(opts.threadCount, totalBytes, serial, result), total));
        result.setThreadCountUsed(threads);
        LogService.info("FolderCrypt", "解密目录 " + mirrorName
                + " units=" + total
                + " size=" + LogService.humanSize(totalBytes)
                + " threads=" + threads
                + (serial ? " serial=true" : ""));

        ParallelProgressAggregator progress = (reporter != null && threads > 1)
                ? new ParallelProgressAggregator(reporter, total) : null;
        AtomicInteger completed = new AtomicInteger(0);

        List<BatchJob> jobs = new ArrayList<>(total);
        for (Unit u : units) {
            final Unit unit = u;
            jobs.add(new BatchJob(unit.outputName, taskReporter -> {
                DecryptOptions taskOpts = opts;
                if (taskReporter != opts.reporter) {
                    taskOpts = cloneDecryptOptions(opts);
                    taskOpts.reporter = taskReporter;
                }
                decryptOneUnit(unit, dir, mirrorRoot, taskOpts, stats, depth, allowNested);
            }));
        }

        processJobs(jobs, threads, false, reporter, progress, completed, total, result);

        if (wantsDecryptThenExtract(opts)) {
            postExtractNewArchives(mirrorRoot, opts, stats, depth, reporter);
        }

        if (reporter != null) {
            reporter.setProgress(1f, "");
        }
    }

    /**
     * 扫描解密输出中新出现的明文归档，解压到同名文件夹并保留压缩包。
     *
     * <p>不解密解压出来的 {@code .ergou}。带密码归档快速失败并保留原文件。
     *
     * @param mirrorRoot 解密镜像根目录
     * @param opts       解密选项
     * @param stats      统计
     * @param depth      当前归档层数
     * @param reporter   进度回调
     * @throws Exception 用户取消
     */
    private static void postExtractNewArchives(Path mirrorRoot, DecryptOptions opts,
                                                DecryptStats stats, int depth,
                                                ProgressReporter reporter) throws Exception {
        int limit = archiveDepthLimit(opts);
        ArchivePostExtract.extractNewArchives(mirrorRoot, depth, limit, reporter,
                postExtractListener(opts, stats, reporter));
    }

    /**
     * 单文件 / 分卷合并解密完成后，若勾选解密后解压且产物为归档，则解压到同名文件夹。
     *
     * @param decrypted 解密输出文件
     * @param opts      解密选项
     * @param stats     统计
     * @throws Exception 解压失败或用户取消
     */
    private static void maybePostExtractSingle(Path decrypted, DecryptOptions opts,
                                               DecryptStats stats) throws Exception {
        if (!wantsDecryptThenExtract(opts) || decrypted == null) {
            return;
        }
        try {
            ArchivePostExtract.extractIfArchive(decrypted, 0, archiveDepthLimit(opts),
                    opts.reporter, postExtractListener(opts, stats, opts.reporter));
        } catch (InterruptedException e) {
            throw e;
        } catch (Exception e) {
            ensureDecryptResult(opts).addFailure(decrypted.getFileName().toString(), e.getMessage());
            LogService.warn("FolderCrypt", "解密后解压失败，已保留 " + decrypted.getFileName()
                    + ": " + e.getMessage());
        }
    }

    /**
     * 将解密后解压结果写入批处理统计。
     *
     * @param opts     解密选项
     * @param stats    统计
     * @param reporter 进度回调
     * @return 监听器
     */
    private static ArchivePostExtract.Listener postExtractListener(DecryptOptions opts,
                                                                   DecryptStats stats,
                                                                   ProgressReporter reporter) {
        return new ArchivePostExtract.Listener() {
            @Override
            public void onExtracted(Path archive, Path destDir) {
                stats.decrypted.incrementAndGet();
                ensureDecryptResult(opts).addSuccess(archive.getFileName().toString());
            }

            @Override
            public void onSkipped(Path archive, String reason) {
                stats.archivesPassthrough.incrementAndGet();
                ensureDecryptResult(opts).addSkipped(1);
                if (reporter != null) {
                    reporter.setStatus(Messages.format("status.skipped",
                            archive.getFileName(), reason), ProgressPhase.ARCHIVE);
                }
            }

            @Override
            public void onFailed(Path archive, String reason) {
                ensureDecryptResult(opts).addFailure(archive.getFileName().toString(), reason);
                if (reporter != null) {
                    reporter.setStatus(Messages.format("status.skipped",
                            archive.getFileName(), reason));
                }
            }
        };
    }

    /**
     * 收集目录下的解密单元，递归进入普通子目录，但分卷碎片子目录作为整体单元。
     * 不可解密后缀的普通文件将被跳过并计入 {@code stats.skipped}。
     * <p>
     * 对于零散的分卷碎片文件（.ergou.N / .pcv.N），会自动按 base 分组并作为分卷单元处理。
     *
     * @param allowNested 是否把内部嵌套压缩包作为可深入的归档单元（false 时仍作为单元，但后续仅原样拷贝）
     */
    private static List<Unit> collectUnits(Path dir, DecryptStats stats, boolean allowNested) throws IOException {
        List<Unit> units = new ArrayList<>();
        Map<String, List<Path>> chunkGroups = new LinkedHashMap<>(); // base -> chunk files
        List<Path> regularEncrypted = new ArrayList<>();

        try (Stream<Path> children = Files.list(dir)) {
            for (Path child : children.sorted().toList()) {
                if (Files.isDirectory(child)) {
                    String cb = detectChunkBase(child);
                    if (cb != null) {
                        units.add(Unit.chunkDir(child.resolve(cb), cb, child.getParent()));
                    } else {
                        units.addAll(collectUnits(child, stats, allowNested));
                    }
                } else {
                    String fn = child.getFileName().toString();
                    if (isEncryptedName(fn)) {
                        regularEncrypted.add(child);
                    } else if (Splitter.isSplitChunkPath(child.toString())) {
                        // 分卷碎片文件：按 base 分组
                        String base = Splitter.splitChunkBase(child.toString());
                        if (base != null) {
                            chunkGroups.computeIfAbsent(base, k -> new ArrayList<>()).add(child);
                        } else {
                            stats.skipped++;
                        }
                    } else if (ArchiveExtractor.isArchive(child)) {
                        // 嵌套压缩包：无论是否递归，都作为归档单元（递归→深入，否则→原样拷贝输出）
                        units.add(Unit.archive(child, child.getParent()));
                    } else {
                        // 不可解密后缀：跳过
                        stats.skipped++;
                    }
                }
            }
        }

        // 处理分组后的分卷碎片：每个 base 作为一个分卷解密单元
        for (Map.Entry<String, List<Path>> entry : chunkGroups.entrySet()) {
            String base = entry.getKey();
            String baseFileName = Path.of(base).getFileName().toString();
            units.add(Unit.chunkDir(Path.of(base), baseFileName, dir));
        }

        // 添加常规加密文件
        for (Path f : regularEncrypted) {
            units.add(Unit.file(f, f.getFileName().toString(), dir));
        }

        return units;
    }

    // ================================================================
    // 单文件解密辅助
    // ================================================================

    private static void decryptSingle(Path encFile, Path output, DecryptOptions opts) throws Exception {
        DecryptRequest req = buildDecryptRequest(encFile.toString(), output.toString(), opts);
        req.setRecombine(false);
        Decryptor.decrypt(req);
    }

    private static void decryptRecombine(Path chunkBase, Path output, DecryptOptions opts) throws Exception {
        // chunkBase 指向碎片的 base 路径（即 base.0, base.1 ... 的公共前缀）
        DecryptRequest req = buildDecryptRequest(chunkBase.toString(), output.toString(), opts);
        req.setRecombine(true);
        Decryptor.decrypt(req);
    }

    // ================================================================
    // 检测辅助
    // ================================================================

    /**
     * 检测某目录是否为"单个文件的分卷碎片文件夹"。
     * 判定：目录下存在形如 {@code base.0, base.1, ...} 的连续编号碎片，且所有碎片共享同一 base。
     *
     * @return base 文件名（不含 .序号），若不是碎片文件夹则返回 null
     */
    public static String detectChunkBase(Path dir) {
        if (!Files.isDirectory(dir)) {
            return null;
        }
        String foundBase = null;
        boolean hasZero = false;
        int count = 0;
        try (Stream<Path> children = Files.list(dir)) {
            List<Path> list = children.toList();
            for (Path p : list) {
                if (Files.isDirectory(p)) {
                    return null; // 含子目录，不是纯碎片文件夹
                }
                Matcher m = CHUNK_RE.matcher(p.getFileName().toString());
                if (!m.matches()) {
                    return null; // 含非碎片文件
                }
                String base = m.group(1);
                int idx = Integer.parseInt(m.group(2));
                if (foundBase == null) {
                    foundBase = base;
                } else if (!foundBase.equals(base)) {
                    return null; // 多个不同 base，不是单文件碎片夹
                }
                if (idx == 0) {
                    hasZero = true;
                }
                count++;
            }
        } catch (IOException e) {
            return null;
        }
        if (foundBase != null && count > 0 && hasZero) {
            return foundBase;
        }
        return null;
    }

    private static boolean isEncryptedName(String name) {
        String lower = name.toLowerCase();
        return lower.endsWith(".ergou") || lower.endsWith(".pcv");
    }

    private static String stripEncExt(String name) {
        if (name.toLowerCase().endsWith(".ergou")) {
            return name.substring(0, name.length() - ".ergou".length());
        }
        if (name.toLowerCase().endsWith(".pcv")) {
            return name.substring(0, name.length() - ".pcv".length());
        }
        return name;
    }

    private static String stripExt(String name) {
        int dot = name.lastIndexOf('.');
        return dot > 0 ? name.substring(0, dot) : name;
    }

    private static String stripArchiveExt(String name) {
        String lower = name.toLowerCase();
        if (lower.endsWith(".tar.gz")) {
            return name.substring(0, name.length() - ".tar.gz".length());
        }
        int dot = name.lastIndexOf('.');
        return dot > 0 ? name.substring(0, dot) : name;
    }

    // ================================================================
    // 迭代加密深度辅助
    // ================================================================

    /**
     * 按深度递归收集待加密的文件与超出深度的"深目录"。
     *
     * <p>深度从 {@code parentDepth} 开始计算：根目录为 0，其直接子项为 1，以此类推。
     * 文件仅在其深度 ≤ {@code maxDepth} 时加入 {@code files} 列表；
     * 目录在其深度 ≥ {@code maxDepth} 时加入 {@code deepDirs} 列表（不再递归进入），
     * 否则继续递归。
     *
     * @param dir         当前目录
     * @param inputRoot   加密根目录（用于保持引用，此处传参与递归无关）
     * @param parentDepth 当前目录的深度（根 = 0）
     * @param maxDepth    最大加密深度
     * @param files       输出：深度内的文件列表
     * @param deepDirs    输出：超出深度的目录列表
     * @throws IOException 列出目录内容失败时抛出
     */
    private static void collectByDepth(Path dir, Path inputRoot, int parentDepth, int maxDepth,
                                        List<Path> files, List<Path> deepDirs) throws IOException {
        try (Stream<Path> children = Files.list(dir)) {
            for (Path child : children.sorted().toList()) {
                int depth = parentDepth + 1;
                if (Files.isDirectory(child)) {
                    if (depth >= maxDepth) {
                        // 达到或超过最大深度：整个目录作为整体打包加密
                        deepDirs.add(child);
                    } else {
                        // 深度内：继续递归
                        collectByDepth(child, inputRoot, depth, maxDepth, files, deepDirs);
                    }
                } else {
                    if (depth <= maxDepth) {
                        files.add(child);
                    }
                    // 超出深度的零散文件不单独出现（正常都在深目录内），忽略
                }
            }
        }
    }

    /**
     * 判断目录下是否存在常规文件（非空目录）。
     *
     * @param dir 目录路径
     * @return 若目录包含至少一个常规文件则返回 true
     */
    private static boolean hasFiles(Path dir) {
        try (Stream<Path> walk = Files.walk(dir)) {
            return walk.anyMatch(Files::isRegularFile);
        } catch (IOException e) {
            return false;
        }
    }

    /**
     * 将目录内所有文件打包为临时 ZIP 归档，保留内部目录结构。
     *
     * <p>若目录为空则返回 null。调用方负责在使用后删除临时文件。
     *
     * @param dir 待打包的目录
     * @return 临时 ZIP 文件路径，若目录为空则返回 null
     * @throws IOException 打包失败时抛出
     */
    private static Path archiveDirectory(Path dir) throws IOException {
        List<Path> dirFiles;
        try (Stream<Path> walk = Files.walk(dir)) {
            dirFiles = walk.filter(Files::isRegularFile).sorted().toList();
        }
        if (dirFiles.isEmpty()) {
            return null;
        }
        Path tmp = Files.createTempFile("ergou-deep-", ".zip");
        ArchivePacker.packEntries(tmp, dir, dirFiles, ArchivePacker.Format.ZIP, null);
        return tmp;
    }

    // ================================================================
    // 请求构建
    // ================================================================

    private static EncryptRequest buildRequest(Path input, Path output, EncryptOptions opts,
                                               ProgressReporter reporter) {
        EncryptRequest req = new EncryptRequest();
        req.setInputFile(input.toString());
        req.setOutputFile(output.toString());
        req.setPassword(opts.password == null ? "" : opts.password);
        req.setComments(opts.comments == null ? "" : opts.comments);
        req.setParanoid(opts.paranoid);
        req.setReedSolomon(opts.reedSolomon);
        req.setDeniability(opts.deniability);
        req.setCompress(opts.compress);
        req.setCompressionLevel(opts.compressionLevel);
        req.setChunkSize(opts.chunkSize);
        req.setRsCodecs(opts.rsCodecs != null ? opts.rsCodecs : new RsCodecs());
        req.setArgon2MemoryKib(opts.argon2MemoryKib);
        req.setArgon2Passes(opts.argon2Passes);
        req.setArgon2Threads(opts.argon2Threads);
        if (opts.keyfiles != null && !opts.keyfiles.isEmpty()) {
            req.setKeyfiles(opts.keyfiles);
            req.setKeyfileOrdered(opts.keyfileOrdered);
        }
        req.setReporter(reporter);
        return req;
    }

    private static DecryptRequest buildDecryptRequest(String input, String output, DecryptOptions opts) {
        DecryptRequest req = new DecryptRequest();
        req.setInputFile(input);
        req.setOutputFile(output);
        req.setPassword(opts.password == null ? "" : opts.password);
        req.setForceDecrypt(opts.forceDecrypt);
        req.setRsCodecs(opts.rsCodecs != null ? opts.rsCodecs : new RsCodecs());
        if (opts.keyfiles != null && !opts.keyfiles.isEmpty()) {
            req.setKeyfiles(opts.keyfiles);
        }
        req.setReporter(opts.reporter);
        return req;
    }

    /**
     * 浅克隆解密选项，用于嵌套调用时覆写 threadCount 为 1。
     *
     * @param opts 源选项
     * @return 浅拷贝
     */
    private static DecryptOptions cloneDecryptOptions(DecryptOptions opts) {
        DecryptOptions cloned = new DecryptOptions();
        cloned.password = opts.password;
        cloned.archivePassword = opts.archivePassword;
        cloned.forceDecrypt = opts.forceDecrypt;
        cloned.recursiveExtract = opts.recursiveExtract;
        cloned.extractThenDecrypt = opts.extractThenDecrypt;
        cloned.decryptThenExtract = opts.decryptThenExtract;
        cloned.autoUnzip = opts.autoUnzip;
        cloned.keyfiles = opts.keyfiles;
        cloned.rsCodecs = opts.rsCodecs;
        cloned.reporter = opts.reporter;
        cloned.threadCount = opts.threadCount;
        cloned.batchResult = opts.batchResult;
        return cloned;
    }

    /**
     * 解压后解密 / 解密后解压共用的嵌套归档层数上限。
     *
     * @param opts 解密选项
     * @return 2 或 5
     */
    private static int archiveDepthLimit(DecryptOptions opts) {
        return ArchivePostExtract.maxDepth(opts != null && opts.recursiveExtract);
    }

    /**
     * 是否启用解密后解压（含已弃用的 {@link DecryptOptions#autoUnzip} 别名）。
     *
     * @param opts 解密选项
     * @return true 表示解密产物中的明文归档应解压到同名文件夹
     */
    private static boolean wantsDecryptThenExtract(DecryptOptions opts) {
        return opts != null && (opts.decryptThenExtract || opts.autoUnzip);
    }

    private static void deleteRecursively(Path dir) throws IOException {
        if (!Files.exists(dir)) {
            return;
        }
        try (Stream<Path> walk = Files.walk(dir)) {
            walk.sorted(Comparator.reverseOrder()).forEach(p -> {
                try {
                    Files.deleteIfExists(p);
                } catch (IOException ignored) {
                }
            });
        }
    }

    /**
     * 将并行任务失败原因规范为 {@link Exception}。
     *
     * <p>{@link OutOfMemoryError} 等 {@link Error} 不能强转为 Exception，
     * 否则会再抛出 {@link ClassCastException} 掩盖真实原因。
     *
     * @param t 失败原因，可为 null
     * @return 可存入并行错误槽的异常
     */
    private static Exception wrapTaskFailure(Throwable t) {
        if (t instanceof Exception e) {
            return e;
        }
        if (t == null) {
            return new IOException("parallel task failed");
        }
        String msg = t.getClass().getSimpleName();
        if (t.getMessage() != null && !t.getMessage().isBlank()) {
            msg = msg + ": " + t.getMessage();
        }
        return new IOException(msg, t);
    }

    // ================================================================
    // 批处理调度：阈值、跳过失败、OOM 降级
    // ================================================================

    /**
     * 取得或创建加密选项上的 {@link BatchResult}。
     *
     * @param opts 加密选项
     * @return 非 null 的汇总对象
     */
    private static BatchResult ensureEncryptResult(EncryptOptions opts) {
        if (opts.batchResult == null) {
            opts.batchResult = new BatchResult();
        }
        return opts.batchResult;
    }

    /**
     * 取得或创建解密选项上的 {@link BatchResult}。
     *
     * @param opts 解密选项
     * @return 非 null 的汇总对象
     */
    private static BatchResult ensureDecryptResult(DecryptOptions opts) {
        if (opts.batchResult == null) {
            opts.batchResult = new BatchResult();
        }
        return opts.batchResult;
    }

    /**
     * 按设置阈值与强制串行标志解析文件级线程数。
     *
     * @param configured  用户配置的线程数
     * @param totalBytes  本批输入总字节
     * @param forceSerial 强制单线程（解压后解密 / 嵌套）
     * @param result      写入策略原因
     * @return 实际线程数（≥ 1）
     */
    static int resolveThreadCount(int configured, long totalBytes,
                                  boolean forceSerial, BatchResult result) {
        return resolveThreadCount(configured, totalBytes, forceSerial, result,
                SettingsManager.getBatchSerialThresholdGiB());
    }

    /**
     * 解析文件级线程数（可注入阈值，便于测试）。
     *
     * @param configured   用户配置的线程数
     * @param totalBytes   本批输入总字节
     * @param forceSerial  强制单线程
     * @param result       写入策略原因
     * @param thresholdGiB 单线程阈值（GiB）
     * @return 实际线程数（≥ 1）
     */
    static int resolveThreadCount(int configured, long totalBytes, boolean forceSerial,
                                  BatchResult result, int thresholdGiB) {
        result.setTotalBytes(totalBytes);
        int threads = Math.max(1, configured);
        if (forceSerial) {
            result.setSerialReason(BatchResult.SerialReason.ARCHIVE_EXTRACT);
            LogService.info("FolderCrypt", "解压后/嵌套解密强制单线程");
            return 1;
        }
        long thresholdBytes = (long) Math.max(1, thresholdGiB) * 1024L * 1024L * 1024L;
        if (totalBytes >= thresholdBytes) {
            result.setSerialReason(BatchResult.SerialReason.THRESHOLD);
            LogService.info("FolderCrypt", "总大小 " + LogService.humanSize(totalBytes)
                    + " ≥ " + thresholdGiB + " GiB，切换为单线程");
            return 1;
        }
        return threads;
    }

    /**
     * 对文件列表求和大小，读失败的条目记为 0。
     *
     * @param files 文件路径
     * @return 总字节
     */
    static long sumFileSizes(List<Path> files) {
        long sum = 0L;
        if (files == null) {
            return 0L;
        }
        for (Path p : files) {
            sum += sizeOf(p);
        }
        return sum;
    }

    /**
     * 对目录内常规文件求和大小。
     *
     * @param dirs 目录列表
     * @return 总字节
     */
    static long sumDirSizes(List<Path> dirs) {
        long sum = 0L;
        if (dirs == null) {
            return 0L;
        }
        for (Path dir : dirs) {
            try (Stream<Path> walk = Files.walk(dir)) {
                for (Path p : walk.filter(Files::isRegularFile).toList()) {
                    sum += sizeOf(p);
                }
            } catch (IOException ignored) {
            }
        }
        return sum;
    }

    /**
     * 对解密单元估算输入大小。
     *
     * @param units 解密单元
     * @return 总字节
     */
    static long sumUnitSizes(List<Unit> units) {
        long sum = 0L;
        if (units == null) {
            return 0L;
        }
        for (Unit u : units) {
            if (u.isChunkDir && u.chunkBase != null) {
                Path parent = u.chunkBase.getParent();
                if (parent != null && Files.isDirectory(parent)) {
                    try (Stream<Path> children = Files.list(parent)) {
                        for (Path p : children.filter(Files::isRegularFile).toList()) {
                            sum += sizeOf(p);
                        }
                    } catch (IOException ignored) {
                    }
                }
            } else if (u.encFile != null) {
                sum += sizeOf(u.encFile);
            }
        }
        return sum;
    }

    /**
     * 读取文件大小，失败返回 0。
     *
     * @param path 路径
     * @return 字节数
     */
    private static long sizeOf(Path path) {
        try {
            return Files.size(path);
        } catch (IOException e) {
            return 0L;
        }
    }

    /**
     * 是否为内存耗尽类错误（含 cause 链）。
     *
     * @param t 失败原因
     * @return true 表示应停止并行
     */
    static boolean isMemoryError(Throwable t) {
        Throwable cur = t;
        int depth = 0;
        while (cur != null && depth < 8) {
            if (cur instanceof VirtualMachineError) {
                return true;
            }
            cur = cur.getCause();
            depth++;
        }
        return false;
    }

    /**
     * 是否为用户取消。
     *
     * @param t 失败原因
     * @return true 表示应中止整批
     */
    private static boolean isCancel(Throwable t) {
        if (t instanceof InterruptedException) {
            return true;
        }
        return t != null && "cancelled".equalsIgnoreCase(t.getMessage());
    }

    /**
     * 从异常提取短消息。
     *
     * @param t 失败原因
     * @return 非空消息
     */
    private static String failureMessage(Throwable t) {
        if (t == null) {
            return "failed";
        }
        String msg = t.getMessage();
        if (msg != null && !msg.isBlank()) {
            return msg;
        }
        return t.getClass().getSimpleName();
    }

    /**
     * 加密深度内的单个普通文件。
     *
     * @param src          源文件
     * @param inputDir     加密根
     * @param workDir      工作目录
     * @param opts         选项
     * @param taskReporter 该任务的进度回调
     * @throws Exception 加密失败
     */
    private static void encryptPlainFile(Path src, Path inputDir, Path workDir,
                                         EncryptOptions opts, ProgressReporter taskReporter)
            throws Exception {
        Path rel = inputDir.relativize(src);
        Path destEnc = workDir.resolve(rel.toString() + ENC_EXT);
        if (opts.split) {
            Path chunkDir = destEnc.getParent().resolve(
                    stripExt(destEnc.getFileName().toString()));
            Path chunkBase = chunkDir.resolve(destEnc.getFileName().toString());
            EncryptRequest req = buildRequest(src, chunkBase, opts, taskReporter);
            req.setSplit(true);
            req.setArchiveFormat(null);
            Encryptor.encrypt(req);
        } else {
            EncryptRequest req = buildRequest(src, destEnc, opts, taskReporter);
            req.setSplit(false);
            req.setArchiveFormat(null);
            Encryptor.encrypt(req);
        }
    }

    /**
     * 将深目录打成 ZIP 再加密。
     *
     * @param deepDir      深目录
     * @param inputDir     加密根
     * @param workDir      工作目录
     * @param opts         选项
     * @param taskReporter 该任务的进度回调
     * @throws Exception 打包或加密失败
     */
    private static void encryptDeepDirectory(Path deepDir, Path inputDir, Path workDir,
                                             EncryptOptions opts, ProgressReporter taskReporter)
            throws Exception {
        Path rel = inputDir.relativize(deepDir);
        String dirName = deepDir.getFileName().toString();
        Path parentInWork = rel.getParent() != null
                ? workDir.resolve(rel.getParent().toString())
                : workDir;
        Path destEnc = parentInWork.resolve(dirName + ".zip.ergou");
        Path tempArchive = archiveDirectory(deepDir);
        try {
            if (tempArchive == null) {
                throw new IOException("deep directory is empty: " + deepDir);
            }
            if (opts.split) {
                Path chunkDir = destEnc.getParent().resolve(
                        stripExt(destEnc.getFileName().toString()));
                Path chunkBase = chunkDir.resolve(destEnc.getFileName().toString());
                EncryptRequest req = buildRequest(tempArchive, chunkBase, opts, taskReporter);
                req.setSplit(true);
                req.setArchiveFormat(null);
                Encryptor.encrypt(req);
            } else {
                EncryptRequest req = buildRequest(tempArchive, destEnc, opts, taskReporter);
                req.setSplit(false);
                req.setArchiveFormat(null);
                Encryptor.encrypt(req);
            }
        } finally {
            if (tempArchive != null) {
                try {
                    Files.deleteIfExists(tempArchive);
                } catch (IOException ignored) {
                }
            }
        }
    }

    /**
     * 处理单个解密单元（文件 / 分卷 / 嵌套归档）。
     *
     * @param u            单元
     * @param dir          当前目录
     * @param mirrorRoot   输出镜像根
     * @param taskOpts     本任务选项
     * @param stats        统计
     * @param depth        当前深度
     * @param allowNested  是否深入嵌套归档
     * @throws Exception 处理失败
     */
    private static void decryptOneUnit(Unit u, Path dir, Path mirrorRoot,
                                       DecryptOptions taskOpts, DecryptStats stats,
                                       int depth, boolean allowNested) throws Exception {
        Path relParent = dir.relativize(u.relativeTo);
        Path destParent = mirrorRoot.resolve(relParent.toString());
        if (u.isArchive) {
            if (allowNested) {
                DecryptOptions nestedOpts = cloneDecryptOptions(taskOpts);
                nestedOpts.threadCount = 1;
                decryptArchive(u.encFile, destParent, nestedOpts, stats, depth + 1);
            } else {
                Path copyOut = destParent.resolve(u.outputName);
                Files.copy(u.encFile, copyOut, StandardCopyOption.REPLACE_EXISTING);
                stats.archivesPassthrough.incrementAndGet();
            }
        } else if (u.isChunkDir) {
            Path out = destParent.resolve(stripEncExt(u.outputName));
            decryptRecombine(u.chunkBase, out, taskOpts);
            stats.decrypted.incrementAndGet();
        } else {
            Path out = destParent.resolve(stripEncExt(u.outputName));
            decryptSingle(u.encFile, out, taskOpts);
            stats.decrypted.incrementAndGet();
        }
    }

    /**
     * 执行批任务队列：失败跳过；OOM 时停并行、GC 后改串行，串行再 OOM 则放弃余下。
     *
     * @param jobs       任务
     * @param threads    文件级线程数
     * @param encrypt    true 表示加密进度文案
     * @param reporter   总进度
     * @param progress   并行聚合器，可为 null
     * @param completed  已完成计数
     * @param total      任务总数
     * @param result     汇总
     * @throws InterruptedException 用户取消
     */
    private static void processJobs(List<BatchJob> jobs, int threads, boolean encrypt,
                                    ProgressReporter reporter,
                                    ParallelProgressAggregator progress,
                                    AtomicInteger completed, int total,
                                    BatchResult result) throws InterruptedException {
        ConcurrentLinkedQueue<BatchJob> queue = new ConcurrentLinkedQueue<>(jobs);
        AtomicBoolean oomDowngrade = new AtomicBoolean(false);
        AtomicReference<InterruptedException> cancelled = new AtomicReference<>();

        if (threads <= 1) {
            drainJobs(queue, encrypt, reporter, progress, completed, total,
                    result, oomDowngrade, cancelled, true);
        } else {
            ExecutorService executor = encrypt
                    ? CryptoThreadPool.forEncrypt(threads)
                    : CryptoThreadPool.forDecrypt(threads);
            try {
                List<java.util.concurrent.Future<?>> futures = new ArrayList<>();
                for (int i = 0; i < threads; i++) {
                    futures.add(executor.submit(() -> drainJobs(queue, encrypt, reporter, progress,
                            completed, total, result, oomDowngrade, cancelled, false)));
                }
                for (java.util.concurrent.Future<?> f : futures) {
                    try {
                        f.get();
                    } catch (java.util.concurrent.ExecutionException e) {
                        Throwable c = e.getCause() != null ? e.getCause() : e;
                        if (isCancel(c)) {
                            cancelled.compareAndSet(null, new InterruptedException("cancelled"));
                        } else {
                            result.addFailure("(worker)", failureMessage(c));
                        }
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        cancelled.compareAndSet(null, e);
                    }
                }
            } finally {
                executor.shutdownNow();
                try {
                    executor.awaitTermination(5, TimeUnit.SECONDS);
                } catch (InterruptedException ignored) {
                    Thread.currentThread().interrupt();
                }
            }
            if (oomDowngrade.get() && !queue.isEmpty() && cancelled.get() == null
                    && (reporter == null || !reporter.isCancelled())) {
                result.setSerialReason(BatchResult.SerialReason.OOM_DOWNGRADE);
                LogService.warn("FolderCrypt", "内存不足，余下 " + queue.size() + " 个任务改为单线程");
                drainJobs(queue, encrypt, reporter, progress, completed, total,
                        result, oomDowngrade, cancelled, true);
            }
        }

        InterruptedException c = cancelled.get();
        if (c != null) {
            throw c;
        }
        if (reporter != null && reporter.isCancelled()) {
            throw new InterruptedException("cancelled");
        }
        if (progress != null && progress.isCancelled()) {
            throw new InterruptedException("cancelled");
        }
    }

    /**
     * 从队列取出任务并执行。
     *
     * @param queue        剩余任务
     * @param encrypt      是否加密进度文案
     * @param reporter     总进度
     * @param progress     并行聚合器，可为 null
     * @param completed    已完成计数
     * @param total        任务总数
     * @param result       汇总
     * @param oomDowngrade 内存不足降级标志
     * @param cancelled    取消槽
     * @param serialMode   true 时 OOM 会放弃队列余下任务
     */
    private static void drainJobs(ConcurrentLinkedQueue<BatchJob> queue, boolean encrypt,
                                  ProgressReporter reporter,
                                  ParallelProgressAggregator progress,
                                  AtomicInteger completed, int total,
                                  BatchResult result, AtomicBoolean oomDowngrade,
                                  AtomicReference<InterruptedException> cancelled,
                                  boolean serialMode) {
        while (true) {
            if (cancelled.get() != null) {
                return;
            }
            if ((reporter != null && reporter.isCancelled())
                    || (progress != null && progress.isCancelled())) {
                cancelled.compareAndSet(null, new InterruptedException("cancelled"));
                return;
            }
            if (!serialMode && oomDowngrade.get()) {
                return;
            }
            BatchJob job = queue.poll();
            if (job == null) {
                return;
            }
            ParallelProgressAggregator.TaskHandle handle =
                    progress != null ? progress.openTask() : null;
            try {
                ProgressReporter taskReporter = handle != null ? handle : reporter;
                job.body.run(taskReporter);
                result.addSuccess(job.label);
                int done = completed.incrementAndGet();
                if (progress != null) {
                    progress.setStatus(encrypt
                            ? Messages.format("status.encrypting.progress", done, total, job.label)
                            : Messages.format("status.decrypting.progress", done, total));
                } else if (reporter != null) {
                    reporter.setStatus(encrypt
                            ? Messages.format("status.encrypting.progress", done, total, job.label)
                            : Messages.format("status.decrypting.progress", done, total));
                    reporter.setProgress((float) done / total, "");
                }
            } catch (InterruptedException e) {
                cancelled.compareAndSet(null, e);
                return;
            } catch (Throwable t) {
                if (isCancel(t)) {
                    cancelled.compareAndSet(null, new InterruptedException("cancelled"));
                    return;
                }
                String msg = failureMessage(t);
                LogService.error("FolderCrypt", "文件失败 " + job.label + " | " + msg, t);
                result.addFailure(job.label, msg);
                if (isMemoryError(t)) {
                    oomDowngrade.set(true);
                    result.setSerialReason(BatchResult.SerialReason.OOM_DOWNGRADE);
                    System.gc();
                    if (serialMode) {
                        BatchJob rest;
                        while ((rest = queue.poll()) != null) {
                            result.addFailure(rest.label, "skipped after OutOfMemoryError");
                            LogService.error("FolderCrypt", "内存不足，跳过余下文件 " + rest.label);
                        }
                    }
                    return;
                }
            } finally {
                if (handle != null) {
                    handle.close();
                }
            }
        }
    }

    /**
     * 批处理中的单个任务。
     */
    private static final class BatchJob {
        /** 用于日志与汇总的标签（相对路径或文件名） */
        final String label;
        /** 任务体 */
        final JobBody body;

        /**
         * @param label 标签
         * @param body  任务体
         */
        BatchJob(String label, JobBody body) {
            this.label = label;
            this.body = body;
        }
    }

    /**
     * 单个批任务体。
     */
    @FunctionalInterface
    private interface JobBody {
        /**
         * 执行任务。
         *
         * @param taskReporter 该任务进度回调
         * @throws Exception 失败
         */
        void run(ProgressReporter taskReporter) throws Exception;
    }

    // ================================================================
    // 内部数据结构
    // ================================================================

    private static final class Unit {
        final boolean isChunkDir;
        final boolean isArchive;
        final Path encFile;     // 普通文件 / 嵌套压缩包
        final Path chunkBase;   // 碎片 base 路径
        final String outputName;
        final Path relativeTo;  // 所在父目录（用于计算镜像相对路径）

        private Unit(boolean isChunkDir, boolean isArchive, Path encFile, Path chunkBase,
                     String outputName, Path relativeTo) {
            this.isChunkDir = isChunkDir;
            this.isArchive = isArchive;
            this.encFile = encFile;
            this.chunkBase = chunkBase;
            this.outputName = outputName;
            this.relativeTo = relativeTo;
        }

        static Unit file(Path encFile, String outputName, Path relativeTo) {
            return new Unit(false, false, encFile, null, outputName, relativeTo);
        }

        static Unit chunkDir(Path chunkBase, String outputName, Path relativeTo) {
            return new Unit(true, false, null, chunkBase, outputName, relativeTo);
        }

        static Unit archive(Path archiveFile, Path relativeTo) {
            return new Unit(false, true, archiveFile, null,
                    archiveFile.getFileName().toString(), relativeTo);
        }
    }

    /**
     * 解密统计：用于"全部不可解密才报错、否则跳过"的判定。字段使用 {@link AtomicInteger} 保证多线程安全。
     */
    private static final class DecryptStats {
        final AtomicInteger decrypted = new AtomicInteger(0);
        final AtomicInteger archivesPassthrough = new AtomicInteger(0);
        int skipped;                     // 仅在 collectUnits 单线程阶段写入，无需同步
    }

    /**
     * 没有任何可解密文件时抛出（单个文件后缀不可解密，或整批全部不可解密）。
     */
    public static final class NoDecryptableFilesException extends IOException {
        public NoDecryptableFilesException(String message) {
            super(message);
        }
    }

    // ================================================================
    // 选项 DTO
    // ================================================================

    /**
     * 文件夹加密公共选项。
     */
    public static final class EncryptOptions {
        public String password;
        public String comments = "";
        public boolean paranoid;
        public boolean reedSolomon;
        public boolean deniability;
        /**
         * 加密前压缩（Zstandard），对文件夹中每个文件单独生效。
         */
        public boolean compress;
        /**
         * Zstandard 压缩档位（1–22，仅 compress=true 时生效）。
         */
        public int compressionLevel = 3;
        public boolean split;
        public int chunkSize;            // 每卷大小，单位 MiB
        public String archiveFormat;     // null/"" 表示不压缩
        public String archivePassword;
        public List<String> keyfiles;
        public boolean keyfileOrdered;
        public RsCodecs rsCodecs;
        public ProgressReporter reporter;
        /**
         * 同时加密的线程数，默认 1（串行）。
         * 仅当输入为文件夹时生效，单文件加密忽略此值。
         */
        public int threadCount = 1;
        /**
         * 迭代加密深度，默认 2。
         *
         * <p>深度 1 表示仅加密根目录下的直接文件，子目录整体打包后加密；
         * 深度 2 表示加密根目录及一级子目录内的文件，二级子目录整体打包后加密，以此类推。
         * 超出深度的目录会先被打成 ZIP 压缩包，再对该压缩包进行加密（内部文件不再逐一加密）。
         */
        public int encryptDepth = 2;
        /**
         * 批处理汇总（输出）。由 {@link FolderCrypt} 写入，调用方可在返回后读取。
         */
        public BatchResult batchResult;
        /**
         * Argon2 内存覆写（KiB）。null 表示使用默认 1 GiB。
         * 移动端与单测可通过此字段降低内存占用。
         */
        public Integer argon2MemoryKib;
        /**
         * Argon2 迭代次数覆写。null 表示使用默认值。
         */
        public Integer argon2Passes;
        /**
         * Argon2 并行度覆写。null 表示使用默认值。
         */
        public Integer argon2Threads;
    }

    /**
     * 解密公共选项。
     */
    public static final class DecryptOptions {
        public String password;
        public String archivePassword;
        public boolean forceDecrypt;
        /**
         * 是否加深嵌套压缩包处理层数。
         *
         * <p>未勾选时解压后解密与解密后解压最多处理
         * {@link ArchivePostExtract#DEFAULT_MAX_DEPTH} 层；
         * 勾选后最多 {@link ArchivePostExtract#RECURSIVE_MAX_DEPTH} 层。
         */
        public boolean recursiveExtract;
        /**
         * 是否解压后解密。输入为明文压缩包时先解压再解密其中的加密文件 / 分卷。
         * 默认 true，以保持「选中压缩包即解压后解密」的既有体验。
         */
        public boolean extractThenDecrypt = true;
        /**
         * 是否解密后解压。解密产物若为明文归档，则解压到同名文件夹并保留压缩包。
         * 默认 false。
         */
        public boolean decryptThenExtract;
        /**
         * 已弃用：作为 {@link #decryptThenExtract} 的兼容别名。
         * 旧测试与调用写入此字段时仍会触发解密后解压。
         *
         * @deprecated 请使用 {@link #decryptThenExtract}
         */
        @Deprecated
        public boolean autoUnzip;
        public List<String> keyfiles;
        public RsCodecs rsCodecs;
        public ProgressReporter reporter;
        /**
         * 同时解密的线程数，默认 1（串行）。
         * 仅当输入为文件夹/压缩包时生效，单文件解密忽略此值。
         */
        public int threadCount = 1;
        /**
         * 批处理汇总（输出）。由 {@link FolderCrypt} 写入，调用方可在返回后读取。
         */
        public BatchResult batchResult;
    }
}
