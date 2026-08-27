package hbnu.project.ergoutreecrypt.log;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * {@link JvmDiagnostics}、{@link LogEvent#stackDump} 与 {@link CompositeLogSink} 测试。
 *
 * @author ErgouTree
 * @since 2026/8/27
 */
public final class JvmDiagnosticsTest {

    /**
     * 每个用例复位静态诊断状态。
     */
    @AfterEach
    void tearDown() {
        LogService.reset();
    }

    /**
     * 快照应包含堆占用与处理器数。
     */
    @Test
    void snapshotContainsHeapAndProcessors() {
        String snap = JvmDiagnostics.snapshot();
        assertTrue(snap.contains("heap used="), snap);
        assertTrue(snap.contains("max="), snap);
        assertTrue(snap.contains("processors="), snap);
    }

    /**
     * 环境摘要应包含 Java 与操作系统标识。
     */
    @Test
    void environmentLineContainsJavaVersion() {
        String env = JvmDiagnostics.environmentLine();
        assertTrue(env.contains("java="), env);
        assertTrue(env.contains("os="), env);
    }

    /**
     * 堆栈转储应包含线程名与帧。
     */
    @Test
    void stackDumpIncludesThreadAndFrames() {
        RuntimeException boom = new RuntimeException("diag");
        String dump = LogEvent.stackDump(boom);
        assertNotNull(dump);
        assertTrue(dump.contains("thread="), dump);
        assertTrue(dump.contains("RuntimeException"), dump);
        assertTrue(dump.contains("diag"), dump);
        assertTrue(dump.contains(" at "), dump);
    }

    /**
     * 堆栈转储应展开 cause 链。
     */
    @Test
    void stackDumpIncludesCauseChain() {
        Exception inner = new IllegalStateException("inner");
        Exception outer = new RuntimeException("outer", inner);
        String dump = LogEvent.stackDump(outer);
        assertTrue(dump.contains("Caused by:"), dump);
        assertTrue(dump.contains("IllegalStateException"), dump);
        assertTrue(dump.contains("inner"), dump);
    }

    /**
     * 重复 start 不改变状态；stop 后关闭。
     */
    @Test
    void startIsIdempotentAndStopRestores() {
        LogService.register(new MemoryLogBuffer(), null);
        assertFalse(JvmDiagnostics.isEnabled());
        JvmDiagnostics.start();
        assertTrue(JvmDiagnostics.isEnabled());
        JvmDiagnostics.start();
        assertTrue(JvmDiagnostics.isEnabled());
        JvmDiagnostics.stop();
        assertFalse(JvmDiagnostics.isEnabled());
    }

    /**
     * 开启诊断后 ERROR 事件应带完整堆栈。
     */
    @Test
    void errorIncludesFullStackWhenDiagnosticsOn() {
        MemoryLogBuffer buffer = new MemoryLogBuffer(32);
        LogService.register(buffer, null);
        LogService.setLevel(LogLevel.INFO);
        JvmDiagnostics.start();
        LogService.error("Cat", "boom", new IllegalStateException("bad"));
        LogEvent event = LogService.snapshot().stream()
                .filter(e -> "Cat".equals(e.category()))
                .findFirst()
                .orElseThrow();
        assertNotNull(event.exceptionSummary());
        assertTrue(event.exceptionSummary().contains("thread="), event.exceptionSummary());
        assertTrue(event.exceptionSummary().contains(" at "), event.exceptionSummary());
        assertTrue(event.formatLine().contains("IllegalStateException"), event.formatLine());
    }

    /**
     * 会话起止在诊断开启时应写入 JVM 快照。
     */
    @Test
    void sessionBoundaryWritesSnapshotWhenEnabled() {
        MemoryLogBuffer buffer = new MemoryLogBuffer(32);
        LogService.register(buffer, null);
        JvmDiagnostics.start();
        LogService.beginSession("GENERIC_DECRYPT", "demo.ergou");
        boolean sawBegin = LogService.snapshot().stream()
                .anyMatch(e -> "JVM".equals(e.category()) && e.message().contains("session-begin"));
        assertTrue(sawBegin);
        LogService.endSession(false, 10);
        boolean sawFail = LogService.snapshot().stream()
                .anyMatch(e -> "JVM".equals(e.category()) && e.message().contains("session-end fail"));
        assertTrue(sawFail);
    }

    /**
     * 组合接收器应转发给全部下游。
     */
    @Test
    void compositeForwardsToAllSinks() {
        AtomicInteger a = new AtomicInteger();
        AtomicInteger b = new AtomicInteger();
        List<String> seen = new ArrayList<>();
        CompositeLogSink composite = new CompositeLogSink(
                event -> a.incrementAndGet(),
                event -> {
                    b.incrementAndGet();
                    seen.add(event.message());
                });
        composite.accept(new LogEvent(1L, LogLevel.INFO, "T", "hello", null, null));
        assertEquals(1, a.get());
        assertEquals(1, b.get());
        assertEquals(List.of("hello"), seen);
    }

    /**
     * 单个下游失败不应阻断其余接收器。
     */
    @Test
    void compositeIgnoresFailingSink() {
        AtomicInteger ok = new AtomicInteger();
        CompositeLogSink composite = new CompositeLogSink(
                event -> {
                    throw new RuntimeException("sink down");
                },
                event -> ok.incrementAndGet());
        composite.accept(new LogEvent(1L, LogLevel.INFO, "T", "x", null, null));
        assertEquals(1, ok.get());
    }
}
