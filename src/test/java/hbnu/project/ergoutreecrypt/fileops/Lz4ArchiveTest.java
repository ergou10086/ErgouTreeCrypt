package hbnu.project.ergoutreecrypt.fileops;

import hbnu.project.ergoutreecrypt.settings.SettingsManager;
import hbnu.project.ergoutreecrypt.filetypes.OutputNaming;
import hbnu.project.ergoutreecrypt.volume.ProgressReporter;
import org.apache.commons.compress.archivers.tar.*;
import org.apache.commons.compress.compressors.lz4.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.stream.Stream;
import static org.junit.jupiter.api.Assertions.*;

class Lz4ArchiveTest {
    @TempDir Path dir;
    private boolean custom, fallback;
    @BeforeEach void save() {
        custom = SettingsManager.isArchiveCustomEncryption();
        fallback = SettingsManager.isArchivePasswordFallback();
        SettingsManager.setArchiveCustomEncryption(true);
        SettingsManager.setArchivePasswordFallback(false);
    }
    @AfterEach void restore() {
        SettingsManager.setArchiveCustomEncryption(custom);
        SettingsManager.setArchivePasswordFallback(fallback);
    }
    @TestFactory Stream<DynamicTest> singleFileBoundariesAndPasswords() {
        return Stream.of(0, 1, 65536, 4 * 1024 * 1024 + 123).flatMap(size ->
            Stream.of("", "归档🔑password").map(pwd -> DynamicTest.dynamicTest(size + "/" + (pwd.isEmpty() ? "plain" : "wrapped"), () -> {
                byte[] data = new byte[size]; new Random(size).nextBytes(data);
                Path input = Files.write(dir.resolve("音频.bin"), data);
                Path archive = dir.resolve("音频.bin.lz4");
                ArchivePacker.pack(archive, input, ArchivePacker.Format.LZ4, pwd);
                assertEquals(!pwd.isEmpty(), ArchiveExtractor.isEncryptedFile(archive));
                if (!pwd.isEmpty()) {
                    assertThrows(ArchiveExtractor.PasswordNeededException.class, () -> ArchiveExtractor.extract(archive, dir.resolve("missing"), null));
                    IOException wrong = assertThrows(IOException.class, () -> ArchiveExtractor.extract(archive, dir.resolve("wrong"), "wrong"));
                    assertTrue(ArchiveExtractor.isPasswordRelatedError(wrong));
                    try (var walk = Files.list(dir.resolve("wrong"))) { assertEquals(0, walk.count()); }
                } else {
                    byte[] bytes = Files.readAllBytes(archive);
                    assertTrue(FramedLZ4CompressorInputStream.matches(bytes, bytes.length));
                    assertEquals(0x64, bytes[4] & 255); // independent blocks, content checksum
                    assertEquals(0x70, bytes[5] & 255); // 4 MiB blocks
                }
                Path out = ArchiveExtractor.extractPreserving(archive, dir.resolve("ok"), pwd).getFirst();
                assertEquals("音频.bin", out.getFileName().toString());
                assertEquals(-1, Files.mismatch(input, out));
            })));
    }
    @Test void directoryTreeEmptyDirectoriesAndPromotion() throws Exception {
        Path root = Files.createDirectories(dir.resolve("目录"));
        Files.createDirectories(root.resolve("empty"));
        Path a = Files.writeString(root.resolve("a.txt"), "A");
        Path b = Files.writeString(Files.createDirectories(root.resolve("子目录")).resolve("b.txt"), "B");
        Path archive = dir.resolve("tree.tar.lz4");
        ArchivePacker.pack(archive, root, ArchivePacker.Format.LZ4, null);
        Path dest = dir.resolve("tree-out");
        assertEquals(2, ArchiveExtractor.extract(archive, dest, null).size());
        assertTrue(Files.isDirectory(dest.resolve("目录/empty")));
        assertEquals(-1, Files.mismatch(a, dest.resolve("目录/a.txt")));
        assertEquals(-1, Files.mismatch(b, dest.resolve("目录/子目录/b.txt")));
        ArchivePacker.packEntries(archive, root, List.of(a,b), List.of("one/a.txt", "two/b.txt"), ArchivePacker.Format.LZ4, "pw", null);
        assertEquals(2, ArchiveExtractor.extract(archive, dir.resolve("explicit"), "pw").size());
        assertEquals("A", Files.readString(dir.resolve("explicit/one/a.txt")));
        assertEquals(ArchivePacker.Format.TAR_LZ4, ArchivePacker.effectiveFormat(ArchivePacker.Format.LZ4, 2));
        assertEquals(ArchivePacker.Format.LZ4, ArchivePacker.effectiveFormat(ArchivePacker.Format.LZ4, 1));
    }
    @Test void formatAndOutputNames() {
        assertEquals(ArchivePacker.Format.TAR_LZ4, ArchivePacker.parseFormat(" tar.lz4 "));
        assertEquals(".lz4", ArchivePacker.extOf(ArchivePacker.Format.LZ4));
        assertEquals(".tar.lz4", ArchivePacker.extOf(ArchivePacker.Format.TAR_LZ4));
        assertTrue(ArchiveExtractor.isArchive(Path.of("FILE.TAR.LZ4")));
        assertEquals("file.tar.lz4.ergou", OutputNaming.preArchiveEncryptOutputName("file.ergou", "TAR.LZ4"));
        assertEquals("file", ArchivePostExtract.folderNameFor(Path.of("file.tar.lz4")));
        assertThrows(IllegalArgumentException.class, () -> ArchivePacker.parseFormat("invalid"));
    }
    @Test void passwordResolutionAllFormats() {
        for (var fmt : ArchivePacker.Format.values()) {
            assertNull(ArchivePacker.resolveArchivePassword(null, "volume", fmt));
            assertNull(ArchivePacker.resolveArchivePassword("", "volume", fmt));
            assertEquals("explicit", ArchivePacker.resolveArchivePassword("explicit", "volume", fmt));
            SettingsManager.setArchivePasswordFallback(true);
            assertEquals("volume", ArchivePacker.resolveArchivePassword(null, "volume", fmt));
            SettingsManager.setArchiveCustomEncryption(false);
            assertEquals(fmt == ArchivePacker.Format.ZIP ? "explicit" : null,
                    ArchivePacker.resolveArchivePassword("explicit", "volume", fmt));
            SettingsManager.setArchiveCustomEncryption(true);
            SettingsManager.setArchivePasswordFallback(false);
        }
    }
    @TestFactory Stream<DynamicTest> referenceCliFixtures() {
        return Stream.of("independent", "linked-k64", "block-checksum", "empty", "concatenated", "reference.tar").map(name ->
            DynamicTest.dynamicTest(name, () -> {
                Path archive = dir.resolve(name + ".lz4");
                try (var in = getClass().getResourceAsStream("/lz4/golden/" + name + ".lz4")) { assertNotNull(in); Files.copy(in, archive, StandardCopyOption.REPLACE_EXISTING); }
                byte[] payload;
                try (var in = getClass().getResourceAsStream("/lz4/golden/payload.txt")) { payload = in.readAllBytes(); }
                Path out = dir.resolve("fixture-" + name);
                List<Path> files = ArchiveExtractor.extract(archive, out, null);
                if (name.equals("reference.tar")) {
                    assertEquals(2, files.size());
                    assertArrayEquals(payload, Files.readAllBytes(out.resolve("目录/payload.txt")));
                    assertEquals(0, Files.size(out.resolve("empty.bin")));
                } else if (name.equals("empty")) assertEquals(0, Files.size(files.getFirst()));
                else if (name.equals("concatenated")) {
                    ByteArrayOutputStream expected = new ByteArrayOutputStream(); expected.write(payload); expected.write(payload);
                    assertArrayEquals(expected.toByteArray(), Files.readAllBytes(files.getFirst()));
                } else if (name.equals("linked-k64")) {
                    ByteArrayOutputStream expected = new ByteArrayOutputStream();
                    for (int i=0;i<100;i++) expected.write(payload);
                    assertArrayEquals(expected.toByteArray(), Files.readAllBytes(files.getFirst()));
                } else assertArrayEquals(payload, Files.readAllBytes(files.getFirst()));
            }));
    }
    @TestFactory Stream<DynamicTest> checksumAndTruncationRejectedWithoutPublishing() {
        return Stream.of(ArchivePacker.Format.LZ4, ArchivePacker.Format.TAR_LZ4).flatMap(fmt ->
            Stream.of("checksum", "truncate").map(kind -> DynamicTest.dynamicTest(fmt + "/" + kind, () -> {
                Path source = Files.writeString(dir.resolve("valid.txt"), "data".repeat(2000));
                Path archive = dir.resolve("bad" + ArchivePacker.extOf(fmt));
                ArchivePacker.pack(archive, source, fmt, null);
                byte[] bytes = Files.readAllBytes(archive);
                if (kind.equals("truncate")) bytes = Arrays.copyOf(bytes, bytes.length - 3);
                else bytes[bytes.length - 1] ^= 1;
                Files.write(archive, bytes);
                Path dest = dir.resolve("reject-" + fmt + "-" + kind);
                assertThrows(IOException.class, () -> ArchiveExtractor.extract(archive, dest, null));
                try (var walk = Files.list(dest)) { assertEquals(0, walk.count()); }
            })));
    }
    @Test void traversalAndLinksRejected() throws Exception {
        for (String name : List.of("../escape.txt", "link")) {
            Path archive = dir.resolve("attack.tar.lz4");
            try (var fos = Files.newOutputStream(archive); var lz4 = new FramedLZ4CompressorOutputStream(fos); var tar = new TarArchiveOutputStream(lz4)) {
                TarArchiveEntry entry = name.equals("link") ? new TarArchiveEntry(name, TarConstants.LF_SYMLINK) : new TarArchiveEntry(name);
                if (name.equals("link")) entry.setLinkName("../escape.txt"); else entry.setSize(1);
                tar.putArchiveEntry(entry); if (!name.equals("link")) tar.write(1); tar.closeArchiveEntry();
            }
            assertThrows(IOException.class, () -> ArchiveExtractor.extract(archive, dir.resolve("attack-out"), null));
            assertFalse(Files.exists(dir.resolve("escape.txt")));
        }
    }
    @TestFactory Stream<DynamicTest> existingFormatsStillRoundtrip() {
        return Arrays.stream(ArchivePacker.Format.values()).flatMap(fmt -> Stream.of("", "pw").map(pwd -> DynamicTest.dynamicTest(fmt + "/" + pwd, () -> {
            Path input = Files.writeString(dir.resolve("regression.txt"), "compatible");
            Path archive = dir.resolve("regression-" + fmt + (pwd.isEmpty() ? "plain" : "wrapped") + ".txt" + ArchivePacker.extOf(fmt));
            ArchivePacker.pack(archive, input, fmt, pwd);
            assertEquals("compatible", Files.readString(ArchiveExtractor.extract(archive, dir.resolve("regression-out"), pwd).getFirst()));
        })));
    }
    @Test void explicitPasswordIsUsedBeforePromptAndWrongPasswordCanRetry() throws Exception {
        Path input = Files.writeString(dir.resolve("source.txt"), "retry-content");
        Path archive = dir.resolve("retry.txt.lz4");
        ArchivePacker.pack(archive, input, ArchivePacker.Format.LZ4, "correct");
        java.util.concurrent.atomic.AtomicInteger prompts = new java.util.concurrent.atomic.AtomicInteger();
        ArchivePasswordProvider delegate = (path, retry) -> {
            assertTrue(retry); prompts.incrementAndGet(); return "correct";
        };
        ArchivePostExtract.extractIfArchive(archive, 2, null,
                ArchivePasswordProvider.withPassword("correct", delegate));
        assertEquals(0, prompts.get());
        ArchivePostExtract.extractIfArchive(archive, 2, null,
                ArchivePasswordProvider.withPassword("wrong", delegate));
        assertEquals(1, prompts.get());
        assertEquals("retry-content", Files.readString(dir.resolve("retry.txt/retry.txt")));
    }

    @Test void progressUsesCompressedBytesAndFinishes() throws Exception {
        byte[] data = new byte[5 * 1024 * 1024]; new Random(1).nextBytes(data);
        Path input = Files.write(dir.resolve("progress.bin"), data);
        Path archive = dir.resolve("progress.bin.lz4");
        ArchivePacker.pack(archive, input, ArchivePacker.Format.LZ4, "pw");
        List<Float> values = new ArrayList<>();
        ProgressReporter reporter = new ProgressReporter() {
            public void setStatus(String text) {} public void setProgress(float f, String info) { values.add(f); }
            public void setCanCancel(boolean can) {} public boolean isCancelled() { return false; }
        };
        ArchiveExtractor.extractPreserving(archive, dir.resolve("progress-out"), "pw", reporter);
        assertTrue(values.size() > 3); assertEquals(1f, values.getLast());
        for (int i=1;i<values.size();i++) assertTrue(values.get(i) >= values.get(i-1));
    }
}
