package hbnu.project.ergoutreecrypt.ui.support;

import hbnu.project.ergoutreecrypt.history.HistoryService;
import hbnu.project.ergoutreecrypt.settings.SettingsManager;

import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

/**
 * 桌面端缓存占用的扫描与清理。
 *
 * <p>汇总本工具运行过程中产生的全部可回收数据，供「存储空间」对话框展示明细并一键清理。
 * 扫描范围：
 * <ul>
 *   <li>应用数据目录 {@code ~/.ergoutreecrypt} 下的日志、操作历史、防护记录与其它残留文件；</li>
 *   <li>系统临时目录中由本工具生成的 {@code ergou*} 临时文件与目录；</li>
 *   <li>上次输出目录下遗留的 {@code .ergou-stage-*} 暂存工作目录。</li>
 * </ul>
 *
 * <p>扫描与清理只针对本工具自有的中间产物，不会触碰用户已生成的加密/解密结果与原始文件。
 * 所有目录遍历都按「尽量返回已统计部分」处理，权限不足或路径失效时不抛异常。
 *
 * @author ErgouTree
 * @since 2026/9/20
 */
public final class StorageUsage {

    /**
     * 应用数据目录名，位于用户主目录下。
     */
    private static final String DATA_DIR_NAME = ".ergoutreecrypt";

    /**
     * 数据目录下的日志子目录名。
     */
    private static final String LOGS_DIR_NAME = "logs";

    /**
     * 操作历史文件名。
     */
    private static final String HISTORY_FILE_NAME = "history.jsonl";

    /**
     * 防暴力破解记录文件名。
     */
    private static final String GUARD_FILE_NAME = "ergou_bruteforce_guard.json";

    /**
     * 临时产物通用前缀。
     */
    private static final String TEMP_PREFIX = "ergou";

    /**
     * 输出目录下暂存工作目录的前缀。
     */
    private static final String STAGE_PREFIX = ".ergou-stage-";

    /**
     * 启动清扫视为「陈旧」的时长（24 小时）。
     *
     * <p>陈旧的临时产物必然不属于本次运行，也不会被另一个正在运行的实例占用，
     * 因此可以安全删除；而近期修改过的条目一律保留，避免打断进行中的操作。
     */
    private static final long STALE_AGE_MILLIS = 24L * 60L * 60L * 1000L;

    private StorageUsage() {
    }

    /**
     * 一条缓存占用明细。
     *
     * @param labelKey 类别文案的 i18n key
     * @param path     该类缓存所在的目录或文件路径，用于向用户交代落盘位置
     * @param bytes    占用字节数
     * @param files    文件个数
     */
    public record Entry(String labelKey, String path, long bytes, long files) {
    }

    /**
     * 返回应用数据目录。
     *
     * @return 形如 {@code C:\Users\<用户>\.ergoutreecrypt} 的目录路径
     */
    public static Path dataDir() {
        return Path.of(System.getProperty("user.home"), DATA_DIR_NAME);
    }

    /**
     * 返回应用日志目录。
     *
     * @return 数据目录下的 {@code logs} 子目录
     */
    public static Path logsDir() {
        return dataDir().resolve(LOGS_DIR_NAME);
    }

    /**
     * 扫描全部缓存占用明细。
     *
     * @return 按固定顺序排列的明细列表；某项不存在时其占用为 0
     */
    public static List<Entry> scan() {
        Path data = dataDir();
        Path logs = logsDir();
        Path history = data.resolve(HISTORY_FILE_NAME);
        Path guard = data.resolve(GUARD_FILE_NAME);

        List<Entry> entries = new ArrayList<>();
        entries.add(new Entry("storage.cat.logs", logs.toString(), sizeOf(logs), countOf(logs)));
        entries.add(new Entry("storage.cat.history", history.toString(),
                sizeOf(history), countOf(history)));
        entries.add(new Entry("storage.cat.guard", guard.toString(),
                sizeOf(guard), countOf(guard)));

        List<Path> leftovers = dataLeftovers(data, logs, history, guard);
        entries.add(new Entry("storage.cat.data", data.toString(),
                totalSize(leftovers), totalCount(leftovers)));

        List<Path> temps = systemTempEntries();
        entries.add(new Entry("storage.cat.temp", systemTempDirText(),
                totalSize(temps), totalCount(temps)));

        List<Path> stages = stageEntries();
        entries.add(new Entry("storage.cat.stage", lastOutputDirText(),
                totalSize(stages), totalCount(stages)));

        return entries;
    }

    /**
     * 清理全部缓存并返回实际释放的字节数。
     *
     * <p>清理前会临时停用 JVM 底层日志，否则 Logback 持有 {@code jvm.log} 的打开句柄会导致
     * 删除失败；清理结束后按当前设置恢复。
     *
     * @return 实际释放的字节数
     */
    public static long clearAll() {
        long before = totalBytes(scan());

        boolean jvmLogging = SettingsManager.isJvmDiagnostics();
        JvmLogSupport.apply(false);
        try {
            deleteChildren(dataDir());
            for (Path entry : systemTempEntries()) {
                deleteRecursively(entry);
            }
            for (Path entry : stageEntries()) {
                deleteRecursively(entry);
            }
            // 历史文件已随之删除，同步清空服务层，避免后续读取到过期缓存
            HistoryService.clear();
        } finally {
            JvmLogSupport.apply(jvmLogging);
        }

        return Math.max(0L, before - totalBytes(scan()));
    }

    /**
     * 清扫陈旧的临时产物，用于在应用启动时阻止缓存跨会话累积。
     *
     * <p>只删除系统临时目录中的自有临时项与输出目录下遗留的暂存工作目录，且仅当条目的
     * 最后修改时间已超过 {@value #STALE_AGE_MILLIS} 毫秒（24 小时）。近期条目一律保留，
     * 因此不会干扰另一个正在运行的实例。
     *
     * @return 实际释放的字节数
     */
    public static long sweepStaleTempEntries() {
        long before = 0L;
        long after = 0L;

        List<Path> candidates = new ArrayList<>(systemTempEntries());
        candidates.addAll(stageEntries());

        long deadline = System.currentTimeMillis() - STALE_AGE_MILLIS;
        for (Path candidate : candidates) {
            if (!isStale(candidate, deadline)) {
                continue;
            }
            before += sizeOf(candidate);
            deleteRecursively(candidate);
            after += sizeOf(candidate);
        }

        return Math.max(0L, before - after);
    }

    /**
     * 判断条目是否可以按陈旧处理。
     *
     * <p>读取最后修改时间失败时按「不可判定」处理，返回 {@code false} 以保留该条目。
     *
     * @param path     待判定条目
     * @param deadline 早于该时间戳即视为陈旧
     * @return 可以安全删除时返回 {@code true}
     */
    private static boolean isStale(Path path, long deadline) {
        try {
            return Files.getLastModifiedTime(path).toMillis() < deadline;
        } catch (IOException | RuntimeException ignored) {
            return false;
        }
    }

    /**
     * 汇总一组明细的占用字节数。
     *
     * @param entries 明细列表
     * @return 合计字节数
     */
    public static long totalBytes(List<Entry> entries) {
        long total = 0L;
        for (Entry entry : entries) {
            total += entry.bytes();
        }
        return total;
    }

    /**
     * 列出数据目录下不属于「日志/历史/防护记录」的其它残留项。
     *
     * @param data    数据目录
     * @param logs    日志目录
     * @param history 操作历史文件
     * @param guard   防护记录文件
     * @return 其它残留项；目录不可读时返回空列表
     */
    private static List<Path> dataLeftovers(Path data, Path logs, Path history, Path guard) {
        List<Path> result = new ArrayList<>();
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(data)) {
            for (Path child : stream) {
                if (child.equals(logs) || child.equals(history) || child.equals(guard)) {
                    continue;
                }
                result.add(child);
            }
        } catch (IOException | RuntimeException ignored) {
            // 目录不存在或不可读时视为无残留
        }
        return result;
    }

    /**
     * 列出系统临时目录中由本工具生成的临时项。
     *
     * @return 临时文件与目录；临时目录不可读时返回空列表
     */
    private static List<Path> systemTempEntries() {
        List<Path> result = new ArrayList<>();
        Path tempDir = systemTempDir();
        if (tempDir == null) {
            return result;
        }
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(tempDir)) {
            for (Path child : stream) {
                if (isOwnTempName(child.getFileName().toString())) {
                    result.add(child);
                }
            }
        } catch (IOException | RuntimeException ignored) {
            // 临时目录不存在或不可读时视为无残留
        }
        return result;
    }

    /**
     * 判断临时目录下的条目名是否由本工具生成。
     *
     * <p>只接受 {@code ergou} 后面紧跟非字母字符（分隔符或随机数字）的命名，以及
     * {@code .ergou-stage-} 前缀，避免误删恰好共享前缀的无关文件。
     *
     * @param name 条目文件名
     * @return 属于本工具产物时返回 {@code true}
     */
    private static boolean isOwnTempName(String name) {
        if (name.startsWith(STAGE_PREFIX)) {
            return true;
        }
        if (!name.startsWith(TEMP_PREFIX)) {
            return false;
        }
        if (name.length() == TEMP_PREFIX.length()) {
            return true;
        }
        return !Character.isLetter(name.charAt(TEMP_PREFIX.length()));
    }

    /**
     * 列出上次输出目录下遗留的暂存工作目录。
     *
     * @return 暂存目录列表；未记录输出目录或目录不可读时返回空列表
     */
    private static List<Path> stageEntries() {
        List<Path> result = new ArrayList<>();
        Path outputDir = lastOutputDir();
        if (outputDir == null) {
            return result;
        }
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(outputDir)) {
            for (Path child : stream) {
                if (child.getFileName().toString().startsWith(STAGE_PREFIX)) {
                    result.add(child);
                }
            }
        } catch (IOException | RuntimeException ignored) {
            // 输出目录已被删除或不可读时视为无残留
        }
        return result;
    }

    /**
     * 返回系统临时目录。
     *
     * @return 系统临时目录；属性缺失或非法时返回 null
     */
    private static Path systemTempDir() {
        try {
            return Path.of(System.getProperty("java.io.tmpdir"));
        } catch (InvalidPathException | NullPointerException ignored) {
            return null;
        }
    }

    /**
     * 返回系统临时目录的展示文本。
     *
     * @return 系统临时目录路径；不可用时返回空串
     */
    private static String systemTempDirText() {
        Path dir = systemTempDir();
        return dir == null ? "" : dir.toString();
    }

    /**
     * 返回上次输出目录。
     *
     * @return 上次输出目录；未记录或路径非法时返回 null
     */
    private static Path lastOutputDir() {
        String raw = SettingsManager.getLastOutputDir();
        if (raw == null || raw.isBlank()) {
            return null;
        }
        try {
            return Path.of(raw);
        } catch (InvalidPathException ignored) {
            return null;
        }
    }

    /**
     * 返回上次输出目录的展示文本。
     *
     * @return 上次输出目录路径；未记录时返回空串
     */
    private static String lastOutputDirText() {
        Path dir = lastOutputDir();
        return dir == null ? "" : dir.toString();
    }

    /**
     * 递归统计单个文件或目录的占用字节数。
     *
     * @param path 目标路径
     * @return 占用字节数；路径不存在或不可读时返回 0
     */
    private static long sizeOf(Path path) {
        if (path == null || !Files.exists(path)) {
            return 0L;
        }
        if (Files.isRegularFile(path)) {
            return fileSize(path);
        }
        if (!Files.isDirectory(path)) {
            return 0L;
        }
        try (Stream<Path> walk = Files.walk(path)) {
            return walk.filter(Files::isRegularFile).mapToLong(StorageUsage::fileSize).sum();
        } catch (IOException | RuntimeException ignored) {
            return 0L;
        }
    }

    /**
     * 递归统计单个文件或目录包含的文件个数。
     *
     * @param path 目标路径
     * @return 文件个数；路径不存在或不可读时返回 0
     */
    private static long countOf(Path path) {
        if (path == null || !Files.exists(path)) {
            return 0L;
        }
        if (Files.isRegularFile(path)) {
            return 1L;
        }
        if (!Files.isDirectory(path)) {
            return 0L;
        }
        try (Stream<Path> walk = Files.walk(path)) {
            return walk.filter(Files::isRegularFile).count();
        } catch (IOException | RuntimeException ignored) {
            return 0L;
        }
    }

    /**
     * 汇总一组路径的占用字节数。
     *
     * @param paths 路径列表
     * @return 合计字节数
     */
    private static long totalSize(List<Path> paths) {
        long total = 0L;
        for (Path path : paths) {
            total += sizeOf(path);
        }
        return total;
    }

    /**
     * 汇总一组路径包含的文件个数。
     *
     * @param paths 路径列表
     * @return 合计文件个数
     */
    private static long totalCount(List<Path> paths) {
        long total = 0L;
        for (Path path : paths) {
            total += countOf(path);
        }
        return total;
    }

    /**
     * 读取单个文件的大小。
     *
     * @param path 文件路径
     * @return 文件字节数；读取失败时返回 0
     */
    private static long fileSize(Path path) {
        try {
            return Files.size(path);
        } catch (IOException | RuntimeException ignored) {
            return 0L;
        }
    }

    /**
     * 删除目录下的全部子项，保留目录本身。
     *
     * <p>目录本身按需重建，保留它可以避免后续写入时重复判断；删除失败的子项静默跳过。
     *
     * @param dir 目标目录
     */
    private static void deleteChildren(Path dir) {
        if (dir == null || !Files.isDirectory(dir)) {
            return;
        }
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(dir)) {
            for (Path child : stream) {
                deleteRecursively(child);
            }
        } catch (IOException | RuntimeException ignored) {
            // 目录不可读时无可清理内容
        }
    }

    /**
     * 递归删除文件或目录。
     *
     * @param path 目标路径
     */
    private static void deleteRecursively(Path path) {
        if (path == null || !Files.exists(path)) {
            return;
        }
        if (Files.isDirectory(path)) {
            try (DirectoryStream<Path> stream = Files.newDirectoryStream(path)) {
                for (Path child : stream) {
                    deleteRecursively(child);
                }
            } catch (IOException | RuntimeException ignored) {
                // 子项不可枚举时继续尝试删除目录本身
            }
        }
        try {
            Files.deleteIfExists(path);
        } catch (IOException | RuntimeException ignored) {
            // 被占用或无权限时保留该项，由下次清理重试
        }
    }
}
