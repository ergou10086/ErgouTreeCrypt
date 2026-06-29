package hbnu.project.ergoutreecrypt.volume;

import hbnu.project.ergoutreecrypt.encoding.RsCodecs;
import hbnu.project.ergoutreecrypt.fileops.ArchiveExtractor;
import hbnu.project.ergoutreecrypt.fileops.ArchivePacker;
import hbnu.project.ergoutreecrypt.fileops.Splitter;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;
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
 *   <li>压缩包：解压后逐个解密其中的加密文件。</li>
 *   <li>分卷碎片文件夹（含 {@code name.0, name.1, ...}）：合并后解密为单个文件。</li>
 *   <li>普通文件夹：递归解密其中所有加密文件（含其下的分卷碎片子文件夹）。</li>
 *   <li>单个 {@code .ergou}/{@code .pcv} 文件：直接解密。</li>
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
     * 加密整个文件夹。
     *
     * @param inputDir  输入文件夹
     * @param outputDir 输出位置（最终结果文件夹/压缩包将放在此目录下）
     * @param opts      公共加密选项（密码、RS、分卷、压缩等）
     */
    public static void encryptFolder(Path inputDir, Path outputDir, EncryptOptions opts) throws Exception {
        String folderName = inputDir.getFileName().toString();

        List<Path> files;
        try (Stream<Path> walk = Files.walk(inputDir)) {
            files = walk.filter(Files::isRegularFile).sorted().toList();
        }
        if (files.isEmpty()) {
            throw new IOException("input folder is empty: " + inputDir);
        }

        // 加密结果先落到一个工作目录（与输入同名），再视情况打包。
        Path workDir = outputDir.resolve(folderName);
        Files.createDirectories(workDir);

        ProgressReporter reporter = opts.reporter;
        int total = files.size();

        // 预创建所有目标目录（单线程，避免竞态）
        for (Path src : files) {
            Path rel = inputDir.relativize(src);
            Path destEnc = workDir.resolve(rel.toString() + ENC_EXT);
            Files.createDirectories(destEnc.getParent());
            if (opts.split) {
                Path chunkDir = destEnc.getParent().resolve(stripExt(destEnc.getFileName().toString()));
                Files.createDirectories(chunkDir);
            }
        }

        // 线程数钳制
        int threads = Math.max(1, Math.min(opts.threadCount, total));
        ExecutorService executor = CryptoThreadPool.forEncrypt(threads);
        AtomicInteger completed = new AtomicInteger(0);
        AtomicReference<Exception> firstError = new AtomicReference<>(null);

        try {
            List<java.util.concurrent.Future<?>> futures = new ArrayList<>();
            for (int i = 0; i < files.size(); i++) {
                final int idx = i;
                final Path src = files.get(i);
                futures.add(executor.submit(() -> {
                    // 检查是否已被取消或已有错误
                    if (reporter != null && reporter.isCancelled()) {
                        return;
                    }
                    if (firstError.get() != null) {
                        return;
                    }
                    try {
                        Path rel = inputDir.relativize(src);
                        Path destEnc = workDir.resolve(rel.toString() + ENC_EXT);

                        if (opts.split) {
                            Path chunkDir = destEnc.getParent().resolve(
                                    stripExt(destEnc.getFileName().toString()));
                            Path chunkBase = chunkDir.resolve(destEnc.getFileName().toString());
                            EncryptRequest req = buildRequest(src, chunkBase, opts);
                            req.setSplit(true);
                            req.setArchiveFormat(null);
                            Encryptor.encrypt(req);
                        } else {
                            EncryptRequest req = buildRequest(src, destEnc, opts);
                            req.setSplit(false);
                            req.setArchiveFormat(null);
                            Encryptor.encrypt(req);
                        }

                        int done = completed.incrementAndGet();
                        if (reporter != null) {
                            reporter.setStatus(
                                    String.format("Encrypting %d/%d: %s", done, total, rel));
                            reporter.setProgress((float) done / total, "");
                        }
                    } catch (Exception e) {
                        firstError.compareAndSet(null, e);
                    }
                }));
            }

            // 等待全部完成
            for (java.util.concurrent.Future<?> f : futures) {
                try {
                    f.get();
                } catch (java.util.concurrent.ExecutionException e) {
                    firstError.compareAndSet(null, (Exception) e.getCause());
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

        // 抛出首个错误（若有）
        Exception err = firstError.get();
        if (err != null) {
            if (err instanceof InterruptedException) {
                throw (InterruptedException) err;
            }
            throw err;
        }

        // 检查是否被取消
        if (reporter != null && reporter.isCancelled()) {
            throw new InterruptedException("cancelled");
        }

        // 若启用压缩：将整个工作目录打成一个压缩包，压缩为最后一步。
        if (opts.archiveFormat != null && !opts.archiveFormat.isEmpty()) {
            if (reporter != null) {
                reporter.setStatus("Archiving...");
            }
            ArchivePacker.Format fmt = ArchivePacker.parseFormat(opts.archiveFormat);
            Path archivePath = outputDir.resolve(folderName + ArchivePacker.extOf(fmt));
            List<Path> entries;
            try (Stream<Path> walk = Files.walk(workDir)) {
                entries = walk.filter(Files::isRegularFile).sorted().toList();
            }
            ArchivePacker.packEntries(archivePath, workDir, entries, fmt, opts.archivePassword);
            deleteRecursively(workDir);
        }

        if (reporter != null) {
            reporter.setProgress(1f, "");
        }
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
        DecryptStats stats = new DecryptStats();
        if (Files.isDirectory(input)) {
            // 输入文件夹：可能是单文件分卷碎片夹，或普通文件夹
            String chunkBase = detectChunkBase(input);
            if (chunkBase != null) {
                Files.createDirectories(outputDir);
                Path out = outputDir.resolve(stripEncExt(chunkBase));
                decryptRecombine(input.resolve(chunkBase), out, opts);
                stats.decrypted.incrementAndGet();
            } else {
                decryptDirectory(input, outputDir, input.getFileName().toString(), opts, stats, 0);
            }
        } else if (ArchiveExtractor.isArchive(input)) {
            decryptArchive(input, outputDir, opts, stats, 0);
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
            } else if (!isEncryptedName(fn)) {
                throw new NoDecryptableFilesException(
                        "无法解密：文件后缀不是受支持的加密格式（.ergou/.pcv）：" + input.getFileName());
            } else {
                Files.createDirectories(outputDir);
                Path out = outputDir.resolve(stripEncExt(fn));
                decryptSingle(input, out, opts);
                stats.decrypted.incrementAndGet();
            }
        }

        // 全部输入都没有产生任何输出时报错；否则（哪怕只解密了 1 个，或仅原样输出了嵌套压缩包）视为成功。
        if (stats.decrypted.get() == 0 && stats.archivesPassthrough.get() == 0) {
            throw new NoDecryptableFilesException(
                    "未找到任何可解密的文件（.ergou/.pcv）；已跳过 " + stats.skipped + " 个不可解密文件。");
        }
    }

    /**
     * 解密压缩包：解压（可带密码）后逐个解密内部加密文件。
     *
     * <p>嵌套压缩包仅在 {@link DecryptOptions#recursiveExtract} 为 true 时才继续深入；
     * 默认只解压最外层一层。
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
                reporter.setStatus("Extracting archive...");
            }
            ArchiveExtractor.extractPreserving(archive, extractDir, opts.archivePassword, reporter);
            // 解压结果可能是普通加密文件、分卷碎片子目录、嵌套压缩包或多层目录结构，统一交给目录解密逻辑。
            decryptDirectory(extractDir, outputDir, base, opts, stats, depth);
        } finally {
            deleteRecursively(extractDir);
        }
    }

    /**
     * 解密一个目录，镜像保留结构输出到 {@code outputDir/<mirrorName>}：
     * 分卷碎片子目录合并解密为单文件；普通加密文件逐个解密；嵌套压缩包递归处理。
     * 不可解密后缀的文件将被跳过（计入 {@code stats.skipped}）。
     */
    private static void decryptDirectory(Path dir, Path outputDir, String mirrorName,
                                         DecryptOptions opts, DecryptStats stats, int depth) throws Exception {
        // 若 dir 本身就是单个文件的分卷碎片集合（如解压后顶层即碎片），合并解密为单文件。
        String selfBase = detectChunkBase(dir);
        if (selfBase != null) {
            Files.createDirectories(outputDir);
            Path out = outputDir.resolve(stripEncExt(selfBase));
            decryptRecombine(dir.resolve(selfBase), out, opts);
            stats.decrypted.incrementAndGet();
            return;
        }

        Path mirrorRoot = outputDir.resolve(mirrorName);
        Files.createDirectories(mirrorRoot);

        // 是否允许深入处理内部的嵌套压缩包：仅在开启递归解压时才深入；否则原样输出，不再深入。
        boolean allowNested = opts.recursiveExtract;

        // 收集需处理的"单元"：分卷碎片子目录 + 普通加密文件 + 嵌套压缩包
        List<Unit> units = collectUnits(dir, stats, allowNested);
        ProgressReporter reporter = opts.reporter;
        int total = units.size();
        if (total == 0) {
            if (reporter != null) {
                reporter.setProgress(1f, "");
            }
            return;
        }

        // 预创建所有目标目录（单线程，避免竞态）
        for (Unit u : units) {
            Path relParent = dir.relativize(u.relativeTo);
            Path destParent = mirrorRoot.resolve(relParent.toString());
            Files.createDirectories(destParent);
        }

        // 嵌套调用（递归解压内部归档）始终使用串行模式，避免线程爆炸
        // 外层调用使用配置的线程数
        boolean isTopLevel = (depth == 0);
        int threads = isTopLevel ? Math.max(1, Math.min(opts.threadCount, total)) : 1;
        ExecutorService executor = threads > 1 ? CryptoThreadPool.forDecrypt(threads) : null;
        AtomicInteger completed = new AtomicInteger(0);
        AtomicReference<Exception> firstError = new AtomicReference<>(null);

        try {
            List<java.util.concurrent.Future<?>> futures = new ArrayList<>();
            for (int i = 0; i < units.size(); i++) {
                final Unit u = units.get(i);
                Runnable task = () -> {
                    // 检查是否已被取消或已有错误
                    if (reporter != null && reporter.isCancelled()) {
                        return;
                    }
                    if (firstError.get() != null) {
                        return;
                    }
                    try {
                        Path relParent = dir.relativize(u.relativeTo);
                        Path destParent = mirrorRoot.resolve(relParent.toString());

                        if (u.isArchive) {
                            if (allowNested) {
                                // 嵌套归档：递归内部始终串行
                                DecryptOptions nestedOpts = cloneDecryptOptions(opts);
                                nestedOpts.threadCount = 1;
                                decryptArchive(u.encFile, destParent, nestedOpts, stats, depth + 1);
                            } else {
                                Path copyOut = destParent.resolve(u.outputName);
                                Files.copy(u.encFile, copyOut, StandardCopyOption.REPLACE_EXISTING);
                                stats.archivesPassthrough.incrementAndGet();
                            }
                        } else if (u.isChunkDir) {
                            Path out = destParent.resolve(stripEncExt(u.outputName));
                            decryptRecombine(u.chunkBase, out, opts);
                            stats.decrypted.incrementAndGet();
                        } else {
                            Path out = destParent.resolve(stripEncExt(u.outputName));
                            decryptSingle(u.encFile, out, opts);
                            stats.decrypted.incrementAndGet();
                        }

                        int done = completed.incrementAndGet();
                        if (reporter != null) {
                            reporter.setStatus(
                                    String.format("Decrypting %d/%d", done, total));
                            reporter.setProgress((float) done / total, "");
                        }
                    } catch (Exception e) {
                        firstError.compareAndSet(null, e);
                    }
                };

                if (executor != null) {
                    futures.add(executor.submit(task));
                } else {
                    // 串行模式：直接执行
                    task.run();
                    Exception err = firstError.get();
                    if (err != null) {
                        if (err instanceof InterruptedException) {
                            throw (InterruptedException) err;
                        }
                        throw err;
                    }
                    if (reporter != null && reporter.isCancelled()) {
                        throw new InterruptedException("cancelled");
                    }
                }
            }

            // 等待全部完成（并行模式）
            if (executor != null) {
                for (java.util.concurrent.Future<?> f : futures) {
                    try {
                        f.get();
                    } catch (java.util.concurrent.ExecutionException e) {
                        firstError.compareAndSet(null, (Exception) e.getCause());
                    }
                }
            }
        } finally {
            if (executor != null) {
                executor.shutdownNow();
                try {
                    executor.awaitTermination(5, TimeUnit.SECONDS);
                } catch (InterruptedException ignored) {
                    Thread.currentThread().interrupt();
                }
            }
        }

        // 抛出首个错误（若有）
        Exception err = firstError.get();
        if (err != null) {
            if (err instanceof InterruptedException) {
                throw (InterruptedException) err;
            }
            throw err;
        }

        // 检查是否被取消
        if (reporter != null && reporter.isCancelled()) {
            throw new InterruptedException("cancelled");
        }

        if (reporter != null) {
            reporter.setProgress(1f, "");
        }
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
    // 请求构建
    // ================================================================

    private static EncryptRequest buildRequest(Path input, Path output, EncryptOptions opts) {
        EncryptRequest req = new EncryptRequest();
        req.setInputFile(input.toString());
        req.setOutputFile(output.toString());
        req.setPassword(opts.password == null ? "" : opts.password);
        req.setComments(opts.comments == null ? "" : opts.comments);
        req.setParanoid(opts.paranoid);
        req.setReedSolomon(opts.reedSolomon);
        req.setDeniability(opts.deniability);
        req.setChunkSize(opts.chunkSize);
        req.setRsCodecs(opts.rsCodecs != null ? opts.rsCodecs : new RsCodecs());
        if (opts.keyfiles != null && !opts.keyfiles.isEmpty()) {
            req.setKeyfiles(opts.keyfiles);
            req.setKeyfileOrdered(opts.keyfileOrdered);
        }
        req.setReporter(opts.reporter);
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
     */
    private static DecryptOptions cloneDecryptOptions(DecryptOptions opts) {
        DecryptOptions cloned = new DecryptOptions();
        cloned.password = opts.password;
        cloned.archivePassword = opts.archivePassword;
        cloned.forceDecrypt = opts.forceDecrypt;
        cloned.recursiveExtract = opts.recursiveExtract;
        cloned.autoUnzip = opts.autoUnzip;
        cloned.keyfiles = opts.keyfiles;
        cloned.rsCodecs = opts.rsCodecs;
        cloned.reporter = opts.reporter;
        cloned.threadCount = opts.threadCount;
        return cloned;
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
    }

    /**
     * 解密公共选项。
     */
    public static final class DecryptOptions {
        public String password;
        public String archivePassword;
        public boolean forceDecrypt;
        /**
         * 是否递归解压解密嵌套压缩包。默认 false：只解压最外层一层压缩包并解密其内容；
         * 内部若还有压缩包则原样输出，不再深入（更安全，避免压缩炸弹/意外深层展开）。
         */
        public boolean recursiveExtract;
        /**
         * 是否解压后解密。当输入为压缩包时，若为 true 则先解压再解密其中内容；
         * 若为 false 且压缩包本身是加密文件（.ergou 后缀），则作为单加密文件直接解密。
         */
        public boolean autoUnzip;
        public List<String> keyfiles;
        public RsCodecs rsCodecs;
        public ProgressReporter reporter;
        /**
         * 同时解密的线程数，默认 1（串行）。
         * 仅当输入为文件夹/压缩包时生效，单文件解密忽略此值。
         */
        public int threadCount = 1;
    }
}
