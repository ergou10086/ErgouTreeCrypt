package hbnu.project.ergoutreecrypt.log;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * {@link LogService} 与 {@link MemoryLogBuffer} 的核心行为测试。
 *
 * @author ErgouTree
 * @since 2026/8/26
 */
public final class LogServiceTest {

    private MemoryLogBuffer buffer;

    /**
     * 每个用例注册独立内存缓冲，避免静态门面串扰。
     */
    @BeforeEach
    void setUp() {
        LogService.reset();
        buffer = new MemoryLogBuffer(8);
        LogService.register(buffer, null);
        LogService.setLevel(LogLevel.INFO);
        LogService.setClearOnNewOperation(true);
    }

    /**
     * 恢复静态门面，避免影响其他测试类。
     */
    @AfterEach
    void tearDown() {
        LogService.reset();
    }

    @Test
    void unregisteredDropsEvents() {
        LogService.reset();
        LogService.info("T", "should drop");
        assertTrue(LogService.snapshot().isEmpty());
    }

    @Test
    void infoLevelDropsTrace() {
        LogService.info("Cat", "visible");
        LogService.trace("Cat", "hidden");
        List<LogEvent> events = LogService.snapshot();
        assertEquals(1, events.size());
        assertEquals(LogLevel.INFO, events.get(0).level());
        assertEquals("visible", events.get(0).message());
    }

    @Test
    void traceLevelKeepsAll() {
        LogService.setLevel(LogLevel.TRACE);
        LogService.error("Cat", "e");
        LogService.warn("Cat", "w");
        LogService.info("Cat", "i");
        LogService.trace("Cat", "t");
        List<LogEvent> events = LogService.snapshot();
        assertEquals(4, events.size());
        assertEquals(LogLevel.ERROR, events.get(0).level());
        assertEquals(LogLevel.TRACE, events.get(3).level());
        assertTrue(LogService.isTraceEnabled());
    }

    @Test
    void ringBufferDropsOldest() {
        MemoryLogBuffer small = new MemoryLogBuffer(3);
        small.accept(event("a"));
        small.accept(event("b"));
        small.accept(event("c"));
        small.accept(event("d"));
        List<LogEvent> snap = small.snapshot();
        assertEquals(3, snap.size());
        assertEquals("b", snap.get(0).message());
        assertEquals("c", snap.get(1).message());
        assertEquals("d", snap.get(2).message());
    }

    @Test
    void clearEmptiesBufferAndNotifies() {
        AtomicInteger cleared = new AtomicInteger();
        buffer.addListener(new LogListener() {
            @Override
            public void onEvent(LogEvent event) {
            }

            @Override
            public void onCleared() {
                cleared.incrementAndGet();
            }
        });
        LogService.info("Cat", "keep");
        assertEquals(1, LogService.snapshot().size());
        LogService.clear();
        assertTrue(LogService.snapshot().isEmpty());
        assertEquals(1, cleared.get());
    }

    @Test
    void beginSessionClearsWhenRefreshEnabled() {
        LogService.info("Old", "stale");
        LogService.beginSession("GENERIC_ENCRYPT", "demo.zip");
        List<LogEvent> events = LogService.snapshot();
        assertEquals(1, events.size());
        assertEquals("Session", events.get(0).category());
        assertTrue(events.get(0).message().contains("GENERIC_ENCRYPT"));
        assertTrue(events.get(0).message().contains("demo.zip"));
    }

    @Test
    void beginSessionKeepsHistoryWhenRefreshDisabled() {
        LogService.setClearOnNewOperation(false);
        LogService.info("Old", "stale");
        LogService.beginSession("GENERIC_DECRYPT", "a.ergou");
        List<LogEvent> events = LogService.snapshot();
        assertEquals(2, events.size());
        assertEquals("stale", events.get(0).message());
    }

    @Test
    void endSessionRecordsResultAndDuration() {
        LogService.beginSession("VERIFY", "a.ergou");
        LogService.endSession(true, 42);
        List<LogEvent> events = LogService.snapshot();
        LogEvent last = events.get(events.size() - 1);
        assertTrue(last.message().contains("完成"));
        assertEquals(42L, last.elapsedMillis());
    }

    @Test
    void exportTextContainsFormattedLines() {
        LogService.info("Encryptor", "开始加密 demo.zip");
        String text = LogService.exportText();
        assertTrue(text.contains("INFO"));
        assertTrue(text.contains("[Encryptor]"));
        assertTrue(text.contains("demo.zip"));
    }

    @Test
    void listenerReceivesEvents() {
        List<String> seen = new ArrayList<>();
        LogService.addListener(event -> seen.add(event.message()));
        LogService.info("Cat", "one");
        LogService.warn("Cat", "two");
        assertEquals(List.of("one", "two"), seen);
    }

    @Test
    void humanSizeFormatsBinaryUnits() {
        assertEquals("512 B", LogService.humanSize(512));
        assertTrue(LogService.humanSize(1536).endsWith("KiB"));
        assertTrue(LogService.humanSize(2L * 1024 * 1024).contains("MiB"));
    }

    @Test
    void errorSummarizesThrowable() {
        LogService.error("Cat", "boom", new IllegalStateException("bad"));
        LogEvent event = LogService.snapshot().get(0);
        assertEquals(LogLevel.ERROR, event.level());
        assertNotNull(event.exceptionSummary());
        assertTrue(event.exceptionSummary().contains("IllegalStateException"));
        assertTrue(event.exceptionSummary().contains("bad"));
        assertFalse(event.exceptionSummary().contains(" at "));
    }

    /**
     * 构造仅用于环形缓冲测试的最小事件。
     *
     * @param message 消息
     * @return 事件
     */
    private static LogEvent event(String message) {
        return new LogEvent(1L, LogLevel.INFO, "T", message, null, null);
    }
}
