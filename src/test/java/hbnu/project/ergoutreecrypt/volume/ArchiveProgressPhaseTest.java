package hbnu.project.ergoutreecrypt.volume;

import hbnu.project.ergoutreecrypt.encoding.RsCodecs;
import hbnu.project.ergoutreecrypt.fileops.ArchivePacker;
import hbnu.project.ergoutreecrypt.i18n.Messages;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Locale;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 验证加密后压缩路径中，压缩进度以 {@link ProgressPhase#ARCHIVE} 独立上报，
 * 且状态文案跟随当前语言。
 *
 * @author ErgouTree
 */
public final class ArchiveProgressPhaseTest {

    private Locale previous;

    @AfterEach
    void restoreLocale() {
        if (previous != null) {
            Messages.setLocale(previous);
        }
    }

    /**
     * 加密后 ZIP 归档：必须出现 ARCHIVE 阶段进度，且文案为中文。
     *
     * @param dir 临时目录
     */
    @Test
    void encryptThenArchiveReportsSeparateArchivePhaseInChinese(@TempDir Path dir) throws Exception {
        previous = Messages.getLocale();
        Messages.setLocale(Locale.SIMPLIFIED_CHINESE);

        Path input = dir.resolve("plain.txt");
        Files.writeString(input, "hello archive progress " + "x".repeat(4096), StandardCharsets.UTF_8);
        Path output = dir.resolve("plain.txt.ergou");

        ProgressPhaseI18nTest.RecordingProgressReporter reporter =
                new ProgressPhaseI18nTest.RecordingProgressReporter();

        EncryptRequest req = new EncryptRequest();
        req.setInputFile(input.toString());
        req.setOutputFile(output.toString());
        req.setPassword("progress-test");
        req.setArchiveFormat("ZIP");
        req.setRsCodecs(new RsCodecs());
        req.setReporter(reporter);

        Encryptor.encrypt(req);

        assertFalse(reporter.archiveEvents.isEmpty(), "应上报独立的压缩/归档进度事件");
        assertTrue(reporter.archiveEvents.stream()
                        .anyMatch(e -> e.fraction() >= 0.99f),
                "归档进度应走到接近完成");
        assertTrue(reporter.archiveEvents.stream()
                        .anyMatch(e -> e.status() != null && e.status().contains("打包")),
                "中文环境下归档状态应含「打包」");
        assertTrue(reporter.cryptoEvents.stream()
                        .anyMatch(e -> e.status() != null && (
                                e.status().contains("派生")
                                        || e.status().contains("生成")
                                        || e.status().contains("完成"))),
                "加解密阶段状态应为中文");

        Path archive = Path.of(req.getOutputFile());
        assertTrue(Files.exists(archive));
        assertTrue(archive.getFileName().toString().endsWith(".zip")
                || archive.getFileName().toString().endsWith(".ZIP"));
    }

    /**
     * 纯打包路径：ArchivePacker 进度全部标记为 ARCHIVE，英文文案正确。
     *
     * @param dir 临时目录
     */
    @Test
    void packEntriesReportsArchivePhaseInEnglish(@TempDir Path dir) throws Exception {
        previous = Messages.getLocale();
        Messages.setLocale(Locale.ENGLISH);

        Path a = dir.resolve("a.bin");
        Path b = dir.resolve("b.bin");
        Files.write(a, new byte[1024]);
        Files.write(b, new byte[2048]);
        Path out = dir.resolve("bundle.zip");

        ProgressPhaseI18nTest.RecordingProgressReporter reporter =
                new ProgressPhaseI18nTest.RecordingProgressReporter();

        ArchivePacker.packEntries(out, dir, java.util.List.of(a, b),
                ArchivePacker.Format.ZIP, null, reporter);

        assertTrue(Files.exists(out));
        assertFalse(reporter.archiveEvents.isEmpty());
        assertTrue(reporter.cryptoEvents.isEmpty(), "纯打包不应产生 CRYPTO 进度");
        assertTrue(reporter.archiveEvents.stream()
                        .anyMatch(e -> e.status() != null
                                && e.status().toLowerCase(Locale.ROOT).contains("archiv")),
                "英文环境下状态应含 Archiving");
        assertTrue(reporter.archiveEvents.stream().anyMatch(e -> e.fraction() >= 0.99f));
    }
}
