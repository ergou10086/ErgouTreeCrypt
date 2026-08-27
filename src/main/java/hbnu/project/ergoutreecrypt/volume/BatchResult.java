package hbnu.project.ergoutreecrypt.volume;

import hbnu.project.ergoutreecrypt.i18n.Messages;
import hbnu.project.ergoutreecrypt.log.LogService;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 文件夹 / 归档批处理的汇总结果。
 *
 * <p>由 {@link FolderCrypt} 在整批过程中写入，供 UI 弹窗与日志使用。
 * 字段均线程安全，可在并行任务中入账。
 *
 * @author ErgouTree
 */
public final class BatchResult {

    /**
     * 文件级并行被强制改为单线程的原因。
     */
    public enum SerialReason {
        /** 未强制单线程 */
        NONE,
        /** 总输入达到设置中的大小阈值 */
        THRESHOLD,
        /** 压缩包解压后解密，始终单线程 */
        ARCHIVE_EXTRACT,
        /** 并行中出现内存不足，余下改为串行 */
        OOM_DOWNGRADE
    }

    /**
     * 单个失败条目。
     *
     * @param name    相对路径或文件名
     * @param message 失败原因
     */
    public record Failure(String name, String message) {
    }

    private final List<String> succeeded = Collections.synchronizedList(new ArrayList<>());
    private final List<Failure> failures = Collections.synchronizedList(new ArrayList<>());
    private final AtomicInteger skipped = new AtomicInteger();
    private volatile SerialReason serialReason = SerialReason.NONE;
    private volatile int threadCountUsed = 1;
    private volatile long totalBytes;

    /**
     * 记录一个成功处理的文件。
     *
     * @param name 相对路径或文件名
     */
    public void addSuccess(String name) {
        succeeded.add(name == null ? "" : name);
    }

    /**
     * 记录一个失败文件。
     *
     * @param name    相对路径或文件名
     * @param message 失败原因，可为 null
     */
    public void addFailure(String name, String message) {
        failures.add(new Failure(name == null ? "" : name,
                message == null || message.isBlank() ? "failed" : message));
    }

    /**
     * 增加跳过计数（不可解密后缀等）。
     *
     * @param n 增加量
     */
    public void addSkipped(int n) {
        if (n > 0) {
            skipped.addAndGet(n);
        }
    }

    /**
     * 设置强制单线程原因。{@link SerialReason#NONE} 不会覆盖已有非空原因。
     *
     * @param reason 原因
     */
    public void setSerialReason(SerialReason reason) {
        if (reason == null || reason == SerialReason.NONE) {
            return;
        }
        if (serialReason == SerialReason.NONE || reason == SerialReason.OOM_DOWNGRADE) {
            serialReason = reason;
        }
    }

    /**
     * 记录实际使用的文件级线程数。
     *
     * @param threads 线程数
     */
    public void setThreadCountUsed(int threads) {
        threadCountUsed = Math.max(1, threads);
    }

    /**
     * 记录本批输入总字节数。
     *
     * @param bytes 总大小
     */
    public void setTotalBytes(long bytes) {
        totalBytes = Math.max(0L, bytes);
    }

    /**
     * @return 成功文件名列表的快照
     */
    public List<String> succeeded() {
        synchronized (succeeded) {
            return List.copyOf(succeeded);
        }
    }

    /**
     * @return 失败条目快照
     */
    public List<Failure> failures() {
        synchronized (failures) {
            return List.copyOf(failures);
        }
    }

    /**
     * @return 成功数量
     */
    public int succeededCount() {
        return succeeded.size();
    }

    /**
     * @return 失败数量
     */
    public int failedCount() {
        return failures.size();
    }

    /**
     * @return 跳过数量
     */
    public int skippedCount() {
        return skipped.get();
    }

    /**
     * @return 是否有失败
     */
    public boolean hasFailures() {
        return !failures.isEmpty();
    }

    /**
     * @return 是否至少成功处理了一个文件
     */
    public boolean hasSuccesses() {
        return !succeeded.isEmpty();
    }

    /**
     * @return 强制单线程原因
     */
    public SerialReason serialReason() {
        return serialReason;
    }

    /**
     * @return 实际文件级线程数
     */
    public int threadCountUsed() {
        return threadCountUsed;
    }

    /**
     * @return 输入总字节数
     */
    public long totalBytes() {
        return totalBytes;
    }

    /**
     * 单行汇总，供状态栏与弹窗标题区使用。
     *
     * @return 如 {@code 成功 18，失败 2，跳过 1}
     */
    public String formatSummary() {
        return Messages.format("batch.summary.body",
                succeededCount(), failedCount(), skippedCount());
    }

    /**
     * 失败列表与策略说明，供弹窗详情。
     *
     * @return 多行文本，无失败且无策略说明时为空串
     */
    public String formatDetail() {
        StringBuilder sb = new StringBuilder();
        switch (serialReason) {
            case THRESHOLD -> sb.append(Messages.get("batch.summary.serial.threshold")).append('\n');
            case ARCHIVE_EXTRACT -> sb.append(Messages.get("batch.summary.serial.archive")).append('\n');
            case OOM_DOWNGRADE -> sb.append(Messages.get("batch.summary.serial.oom")).append('\n');
            case NONE -> {
            }
        }
        if (threadCountUsed > 1) {
            sb.append(Messages.format("batch.summary.threads", threadCountUsed)).append('\n');
        }
        List<Failure> fails = failures();
        if (!fails.isEmpty()) {
            sb.append(Messages.get("batch.summary.failures")).append('\n');
            int limit = Math.min(fails.size(), 20);
            for (int i = 0; i < limit; i++) {
                Failure f = fails.get(i);
                sb.append("  • ").append(f.name()).append(" — ").append(f.message()).append('\n');
            }
            if (fails.size() > limit) {
                sb.append("  … ").append(fails.size() - limit).append('\n');
            }
        }
        return sb.toString().strip();
    }

    /**
     * 将本批策略与汇总写入应用日志。
     *
     * @param category 日志分类
     */
    public void logSummary(String category) {
        String cat = category == null ? "FolderCrypt" : category;
        if (serialReason != SerialReason.NONE) {
            LogService.info(cat, "批处理策略 " + serialReason
                    + " threads=" + threadCountUsed
                    + " total=" + LogService.humanSize(totalBytes));
        }
        LogService.info(cat, "批处理完成 " + formatSummary());
        for (Failure f : failures()) {
            LogService.error(cat, "跳过失败文件 " + f.name() + " | " + f.message());
        }
    }
}
