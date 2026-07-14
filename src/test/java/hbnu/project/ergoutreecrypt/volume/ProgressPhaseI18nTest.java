package hbnu.project.ergoutreecrypt.volume;

import hbnu.project.ergoutreecrypt.i18n.Messages;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 进度阶段与状态文案国际化测试。
 *
 * <p>验证压缩/解压阶段使用 {@link ProgressPhase#ARCHIVE} 与加解密阶段分离，
 * 且状态文案严格跟随当前语言环境，避免中英混杂。
 *
 * @author ErgouTree
 */
public final class ProgressPhaseI18nTest {

    private Locale previous;

    @AfterEach
    void restoreLocale() {
        if (previous != null) {
            Messages.setLocale(previous);
        }
    }

    /**
     * 中文环境下进度状态 key 全部为中文文案，且不含典型英文片段。
     */
    @Test
    void chineseStatusMessagesAreLocalized() {
        previous = Messages.getLocale();
        Messages.setLocale(Locale.SIMPLIFIED_CHINESE);

        assertEquals("正在打包归档…", Messages.get("status.archiving"));
        assertEquals("正在解压归档…", Messages.get("status.extracting"));
        assertEquals("正在压缩…", Messages.get("status.compressing"));
        assertEquals("正在派生密钥…", Messages.get("status.deriving"));
        assertTrue(Messages.format("status.extracting.progress", 1, 3).contains("解压"));
        assertTrue(Messages.format("status.archiving.progress", 2, 5).contains("打包"));
        assertFalse(Messages.get("status.archiving").matches(".*[A-Za-z]{4,}.*"));
        assertFalse(Messages.get("status.extracting").matches(".*[A-Za-z]{4,}.*"));
    }

    /**
     * 英文环境下进度状态 key 为英文文案。
     */
    @Test
    void englishStatusMessagesAreLocalized() {
        previous = Messages.getLocale();
        Messages.setLocale(Locale.ENGLISH);

        assertEquals("Archiving...", Messages.get("status.archiving"));
        assertEquals("Extracting archive...", Messages.get("status.extracting"));
        assertEquals("Compressing...", Messages.get("status.compressing"));
        assertEquals("Deriving key...", Messages.get("status.deriving"));
        assertEquals("Extracting (1/3)...", Messages.format("status.extracting.progress", 1, 3));
        assertEquals("Archiving (2/5)...", Messages.format("status.archiving.progress", 2, 5));
    }

    /**
     * 切换语言后同一 key 文案立即变化。
     */
    @Test
    void localeToggleSwitchesStatusText() {
        previous = Messages.getLocale();
        Messages.setLocale(Locale.SIMPLIFIED_CHINESE);
        String zh = Messages.get("status.archiving");
        Messages.setLocale(Locale.ENGLISH);
        String en = Messages.get("status.archiving");
        assertNotEquals(zh, en);
        assertTrue(zh.contains("打包") || zh.contains("归档"));
        assertTrue(en.toLowerCase(Locale.ROOT).contains("archiv"));
    }

    /**
     * RecordingProgressReporter 能区分 CRYPTO 与 ARCHIVE 阶段事件。
     */
    @Test
    void recordingReporterSeparatesPhases() {
        RecordingProgressReporter reporter = new RecordingProgressReporter();
        reporter.setStatus(Messages.get("status.deriving"), ProgressPhase.CRYPTO);
        reporter.setProgress(0.5f, "1.0 MiB/s", ProgressPhase.CRYPTO);
        reporter.setStatus(Messages.get("status.archiving"), ProgressPhase.ARCHIVE);
        reporter.setProgress(0.8f, "", ProgressPhase.ARCHIVE);

        assertEquals(2, reporter.cryptoEvents.size());
        assertEquals(2, reporter.archiveEvents.size());
        assertEquals(ProgressPhase.CRYPTO, reporter.cryptoEvents.get(0).phase);
        assertEquals(ProgressPhase.ARCHIVE, reporter.archiveEvents.get(0).phase);
        assertEquals(0.5f, reporter.cryptoEvents.get(1).fraction, 0.001f);
        assertEquals(0.8f, reporter.archiveEvents.get(1).fraction, 0.001f);
    }

    /**
     * 进度条说明文案的 i18n key 存在且中英不同。
     */
    @Test
    void progressCaptionsLocalized() {
        previous = Messages.getLocale();
        Messages.setLocale(Locale.SIMPLIFIED_CHINESE);
        String zhCrypto = Messages.get("progress.crypto");
        String zhArchive = Messages.get("progress.archive");
        Messages.setLocale(Locale.ENGLISH);
        String enCrypto = Messages.get("progress.crypto");
        String enArchive = Messages.get("progress.archive");

        assertNotEquals(zhCrypto, enCrypto);
        assertNotEquals(zhArchive, enArchive);
        assertFalse(zhCrypto.isBlank());
        assertFalse(zhArchive.isBlank());
    }

    /**
     * 测试用进度记录器：按阶段分别收集事件。
     */
    static final class RecordingProgressReporter implements ProgressReporter {

        final List<Event> cryptoEvents = new CopyOnWriteArrayList<>();
        final List<Event> archiveEvents = new CopyOnWriteArrayList<>();
        private volatile boolean cancelled;

        @Override
        public void setStatus(String text) {
            setStatus(text, ProgressPhase.CRYPTO);
        }

        @Override
        public void setStatus(String text, ProgressPhase phase) {
            Event e = new Event(phase, text, -1f, null);
            bucket(phase).add(e);
        }

        @Override
        public void setProgress(float fraction, String info) {
            setProgress(fraction, info, ProgressPhase.CRYPTO);
        }

        @Override
        public void setProgress(float fraction, String info, ProgressPhase phase) {
            Event e = new Event(phase, null, fraction, info);
            bucket(phase).add(e);
        }

        @Override
        public void setCanCancel(boolean can) {
        }

        @Override
        public boolean isCancelled() {
            return cancelled;
        }

        /**
         * 请求取消。
         */
        void cancel() {
            cancelled = true;
        }

        /**
         * 返回全部事件（CRYPTO 在前，再接 ARCHIVE）。
         *
         * @return 事件列表副本
         */
        List<Event> allEvents() {
            List<Event> all = new ArrayList<>(cryptoEvents.size() + archiveEvents.size());
            all.addAll(cryptoEvents);
            all.addAll(archiveEvents);
            return all;
        }

        private List<Event> bucket(ProgressPhase phase) {
            return phase == ProgressPhase.ARCHIVE ? archiveEvents : cryptoEvents;
        }

        /**
         * 单次进度/状态事件。
         *
         * @param phase    阶段
         * @param status   状态文案，进度事件可为 null
         * @param fraction 进度值，状态事件为 -1
         * @param info     附加信息
         */
        record Event(ProgressPhase phase, String status, float fraction, String info) {
        }
    }
}
