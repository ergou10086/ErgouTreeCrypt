package hbnu.project.ergoutreecrypt.volume;

import hbnu.project.ergoutreecrypt.i18n.Messages;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 多文件并行加解密的进度聚合器。
 *
 * <p>各工作线程通过 {@link #openTask()} 获得独立的 {@link ProgressReporter} 槽位，
 * 向 UI 只发布聚合后的单调进度：以当前进行中任务的<strong>最慢</strong>进度为基准，
 * 避免多线程各自 0→1 互相覆盖导致进度条来回晃动。
 *
 * <p>速度信息对各活动槽位求和，显示整体吞吐，而非单线程平摊值。
 *
 * @author ErgouTree
 */
public final class ParallelProgressAggregator {

    private static final Pattern SPEED_PATTERN = Pattern.compile("([0-9]+(?:\\.[0-9]+)?)\\s*MiB/s");

    private final ProgressReporter delegate;
    private final int totalTasks;
    private final AtomicInteger completed = new AtomicInteger(0);
    private final AtomicInteger nextId = new AtomicInteger(0);
    private final ConcurrentHashMap<Integer, SlotState> active = new ConcurrentHashMap<>();
    private final AtomicReference<String> lastStatus = new AtomicReference<>("");
    private final AtomicLong publishedMicros = new AtomicLong(0);
    private volatile float lastOverall = 0f;
    private volatile double lastSpeedSum = -1d;

    /**
     * @param delegate   最终 UI 进度回调，可为 null（空操作）
     * @param totalTasks 总任务数，必须 &gt; 0
     */
    public ParallelProgressAggregator(ProgressReporter delegate, int totalTasks) {
        this.delegate = delegate;
        this.totalTasks = Math.max(1, totalTasks);
    }

    /**
     * 为单个并行任务打开进度槽位。
     *
     * <p>任务结束时必须调用返回句柄的 {@link TaskHandle#close()}（或 try-with-resources）。
     *
     * @return 该任务专用的进度句柄
     */
    public TaskHandle openTask() {
        int id = nextId.getAndIncrement();
        SlotState state = new SlotState();
        active.put(id, state);
        return new TaskHandle(id, state);
    }

    /**
     * 是否已请求取消（委托底层 reporter）。
     *
     * @return true 表示应中止
     */
    public boolean isCancelled() {
        return delegate != null && delegate.isCancelled();
    }

    /**
     * 向底层 reporter 转发状态文案，并刷新聚合进度。
     *
     * @param text 状态文案
     */
    public void setStatus(String text) {
        lastStatus.set(text == null ? "" : text);
        if (delegate != null) {
            delegate.setStatus(text);
        }
        publish();
    }

    /**
     * 强制将总体进度推到 100%。
     */
    public void completeAll() {
        completed.set(totalTasks);
        active.clear();
        lastOverall = 1f;
        if (delegate != null) {
            delegate.setProgress(1f, "");
        }
    }

    private void publish() {
        if (delegate == null) {
            return;
        }
        float minActive = 1f;
        double speedSum = 0d;
        int activeCount = 0;
        int progressedCount = 0;
        for (SlotState s : active.values()) {
            activeCount++;
            if (s.speedMibPerSec > 0) {
                speedSum += s.speedMibPerSec;
            }
            // 尚未进入载荷进度的槽位（如仍在派生密钥）不参与「最慢」计算
            if (!s.progressed) {
                continue;
            }
            progressedCount++;
            if (s.fraction < minActive) {
                minActive = s.fraction;
            }
        }
        if (progressedCount == 0) {
            minActive = 0f;
        }

        int done = completed.get();
        float overall = (done + minActive) / (float) totalTasks;
        if (overall < lastOverall) {
            overall = lastOverall;
        }
        if (overall > 1f) {
            overall = 1f;
        }
        lastOverall = overall;

        String info = speedSum > 0 ? Messages.format("status.speed", speedSum) : "";

        long now = System.nanoTime() / 1000L;
        long prev = publishedMicros.get();
        boolean boundary = overall <= 0.001f || overall >= 0.999f || activeCount == 0;
        boolean speedJump = Math.abs(speedSum - lastSpeedSum) >= 0.5;
        if (!boundary && !speedJump && now - prev < 40_000L) {
            return;
        }
        publishedMicros.set(now);
        lastSpeedSum = speedSum;
        delegate.setProgress(overall, info);
    }

    private static double parseSpeed(String info) {
        if (info == null || info.isEmpty()) {
            return 0d;
        }
        Matcher m = SPEED_PATTERN.matcher(info);
        if (m.find()) {
            try {
                return Double.parseDouble(m.group(1));
            } catch (NumberFormatException ignored) {
                return 0d;
            }
        }
        return 0d;
    }

    /**
     * 单个并行任务的进度槽位，实现 {@link ProgressReporter} 并支持 try-with-resources。
     */
    public final class TaskHandle implements ProgressReporter, AutoCloseable {

        private final int id;
        private final SlotState state;
        private final AtomicInteger closed = new AtomicInteger(0);

        private TaskHandle(int id, SlotState state) {
            this.id = id;
            this.state = state;
        }

        @Override
        public void setStatus(String text) {
            lastStatus.set(text == null ? "" : text);
            if (delegate != null) {
                delegate.setStatus(text);
            }
        }

        @Override
        public void setStatus(String text, ProgressPhase phase) {
            lastStatus.set(text == null ? "" : text);
            if (delegate != null) {
                delegate.setStatus(text, phase);
            }
        }

        @Override
        public void setProgress(float fraction, String info) {
            setProgress(fraction, info, ProgressPhase.CRYPTO);
        }

        @Override
        public void setProgress(float fraction, String info, ProgressPhase phase) {
            if (closed.get() != 0) {
                return;
            }
            float f = fraction;
            if (f < 0f) {
                f = 0f;
            } else if (f > 1f) {
                f = 1f;
            }
            state.fraction = f;
            state.progressed = true;
            double spd = parseSpeed(info);
            if (spd > 0) {
                state.speedMibPerSec = spd;
            }
            publish();
        }

        @Override
        public void setCanCancel(boolean can) {
            if (delegate != null) {
                delegate.setCanCancel(can);
            }
        }

        @Override
        public boolean isCancelled() {
            return ParallelProgressAggregator.this.isCancelled();
        }

        /**
         * 标记本任务完成：从活动集合移除并增加已完成计数，刷新聚合进度。
         */
        @Override
        public void close() {
            if (!closed.compareAndSet(0, 1)) {
                return;
            }
            active.remove(id);
            completed.incrementAndGet();
            publish();
        }
    }

    /**
     * 活动槽位可变状态。
     */
    private static final class SlotState {
        volatile float fraction;
        volatile double speedMibPerSec;
        volatile boolean progressed;
    }

    /**
     * 供测试读取当前活动槽位数。
     *
     * @return 活动任务数
     */
    int activeCount() {
        return active.size();
    }

    /**
     * 供测试读取已完成任务数。
     *
     * @return 已完成数
     */
    int completedCount() {
        return completed.get();
    }

    /**
     * 供测试读取最近一次发布的总体进度。
     *
     * @return 总体进度 0~1
     */
    float lastOverall() {
        return lastOverall;
    }

    /**
     * 供测试窥视活动槽位速度之和（不经节流）。
     *
     * @return 活动槽位速度总和（MiB/s）
     */
    double activeSpeedSum() {
        double sum = 0d;
        for (SlotState s : active.values()) {
            if (s.speedMibPerSec > 0) {
                sum += s.speedMibPerSec;
            }
        }
        return sum;
    }

    /**
     * 供测试窥视活动槽位中的最小进度。
     *
     * @return 最慢活动进度，无活动时为 0
     */
    float minActiveFraction() {
        float min = 1f;
        boolean any = false;
        for (SlotState s : active.values()) {
            if (!s.progressed) {
                continue;
            }
            any = true;
            if (s.fraction < min) {
                min = s.fraction;
            }
        }
        return any ? min : 0f;
    }

    /**
     * 供测试窥视内部 map（只读用途）。
     *
     * @return 活动槽位快照
     */
    Map<Integer, Float> activeFractionsSnapshot() {
        ConcurrentHashMap<Integer, Float> snap = new ConcurrentHashMap<>();
        active.forEach((k, v) -> snap.put(k, v.fraction));
        return snap;
    }
}
