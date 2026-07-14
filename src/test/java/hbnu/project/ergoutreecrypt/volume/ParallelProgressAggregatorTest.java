package hbnu.project.ergoutreecrypt.volume;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

/**
 * {@link ParallelProgressAggregator} 单元测试：最慢任务基准、单调进度、速度汇总。
 *
 * @author ErgouTree
 */
public final class ParallelProgressAggregatorTest {

    /**
     * 多槽位并行时，总体进度以最慢活动任务为基准，且不会因更慢任务出现而回跳。
     */
    @Test
    void usesSlowestActiveTaskAndNeverGoesBackward() {
        List<Float> published = new ArrayList<>();
        ProgressReporter sink = recordingSink(published, new AtomicReference<>());

        ParallelProgressAggregator agg = new ParallelProgressAggregator(sink, 4);
        try (ParallelProgressAggregator.TaskHandle a = agg.openTask();
             ParallelProgressAggregator.TaskHandle b = agg.openTask()) {
            a.setProgress(0.8f, "40.0 MiB/s");
            // (0 + 0.8) / 4 = 0.2
            assertEquals(0.2f, agg.lastOverall(), 0.001f);
            assertEquals(40.0, agg.activeSpeedSum(), 0.01);

            b.setProgress(0.2f, "10.0 MiB/s");
            // 计算值 (0+0.2)/4=0.05，但单调保护保持 0.2，避免进度条回跳
            assertEquals(0.2f, agg.lastOverall(), 0.001f);
            assertEquals(50.0, agg.activeSpeedSum(), 0.01);
            assertEquals(0.2f, agg.minActiveFraction(), 0.001f);

            // 新任务尚未上报进度时，不把最慢基准拉回 0
            try (ParallelProgressAggregator.TaskHandle c = agg.openTask()) {
                assertEquals(0.2f, agg.lastOverall(), 0.001f);
                c.setProgress(0.5f, "5.0 MiB/s");
                assertEquals(55.0, agg.activeSpeedSum(), 0.01);
            }
            // c 完成后 completed=1，活动 a=0.8 b=0.2 → (1+0.2)/4=0.3
            assertEquals(0.3f, agg.lastOverall(), 0.001f);
        }
        assertEquals(3, agg.completedCount());
        assertTrue(agg.lastOverall() >= 0.3f - 0.001f);
        for (int i = 1; i < published.size(); i++) {
            assertTrue(published.get(i) + 1e-6f >= published.get(i - 1),
                    "progress went backward: " + published);
        }
    }

    /**
     * 速度字符串可解析并按活动槽位求和后发布到 UI。
     */
    @Test
    void aggregatesPerTaskThroughput() {
        AtomicReference<String> lastInfo = new AtomicReference<>("");
        ProgressReporter sink = recordingSink(new ArrayList<>(), lastInfo);
        ParallelProgressAggregator agg = new ParallelProgressAggregator(sink, 2);
        try (ParallelProgressAggregator.TaskHandle a = agg.openTask();
             ParallelProgressAggregator.TaskHandle b = agg.openTask()) {
            a.setProgress(0.5f, "16.0 MiB/s");
            b.setProgress(0.5f, "16.0 MiB/s");
            assertEquals(32.0, agg.activeSpeedSum(), 0.01);
            assertTrue(lastInfo.get().contains("32"),
                    "expected aggregated speed in UI info, got: " + lastInfo.get());
        }
    }

    private static ProgressReporter recordingSink(List<Float> fractions,
                                                  AtomicReference<String> infoOut) {
        return new ProgressReporter() {
            @Override
            public void setStatus(String text) {
            }

            @Override
            public void setProgress(float fraction, String info) {
                fractions.add(fraction);
                if (info != null) {
                    infoOut.set(info);
                }
            }

            @Override
            public void setCanCancel(boolean can) {
            }

            @Override
            public boolean isCancelled() {
                return false;
            }
        };
    }
}
