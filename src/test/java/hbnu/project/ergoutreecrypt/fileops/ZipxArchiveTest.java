package hbnu.project.ergoutreecrypt.fileops;

import hbnu.project.ergoutreecrypt.settings.SettingsManager;
import hbnu.project.ergoutreecrypt.volume.*;
import org.apache.commons.compress.archivers.zip.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

/** ZIPX integrity, standard-format and failure-publication regressions. */
class ZipxArchiveTest {
    @TempDir Path root;

    /** Every writable codec restores Unicode, empty files and directories with or without AES. */
    @Test void codecsAndAesRoundtrip() throws Exception {
        Path text = root.resolve("ひなみ 桜花.txt"), empty = root.resolve("empty");
        Files.writeString(text, "跨平台 ZIPX\n".repeat(10000)); Files.write(empty, new byte[0]);
        Path directory = Files.createDirectory(root.resolve("empty-dir"));
        for (ZipxMethod method : ZipxMethod.values()) for (String password : Arrays.asList(null, "密码🔑")) {
            Path archive = root.resolve(method + "-" + (password != null) + ".zipx");
            ZipxArchive.pack(archive, List.of(text, empty, directory), List.of("目录/ひなみ 桜花.txt", "empty", "空目录/"), method, password, null);
            assertEquals(password != null, ArchiveExtractor.hasEncryptedEntries(archive));
            ZipxArchive.verify(archive, password);
            Path output = root.resolve("out-" + archive.getFileName());
            assertEquals(2, ArchiveExtractor.extract(archive, output, password).size());
            assertEquals(-1, Files.mismatch(text, output.resolve("目录/ひなみ 桜花.txt")));
            assertEquals(0, Files.size(output.resolve("empty")));
            assertTrue(Files.isDirectory(output.resolve("空目录")));
        }
    }

    /** A corrupted second entry cannot publish the already validated first entry. */
    @Test void damagedLaterEntryDoesNotPublishEarlierEntry() throws Exception {
        Path source = root.resolve("source"); Files.writeString(source, "two-entry content");
        Path archive = root.resolve("multi.zipx");
        ZipxArchive.pack(archive, List.of(source, source), List.of("first", "second"), ZipxMethod.XZ, "correct", null);
        long tag;
        try (var zip = org.apache.commons.compress.archivers.zip.ZipFile.builder().setPath(archive).get()) {
            var second = zip.getEntry("second"); tag = second.getDataOffset() + second.getCompressedSize() - 1;
        }
        byte[] bytes = Files.readAllBytes(archive); bytes[(int) tag] ^= 1; Files.write(archive, bytes);
        Path output = root.resolve("out");
        assertThrows(IOException.class, () -> ArchiveExtractor.extract(archive, output, "correct"));
        assertEquals(0, count(output));
    }

    /** LZMA dictionaries from untrusted archives cannot exceed the configured memory budget. */
    @Test void oversizedLzmaDictionaryIsRejected() throws Exception {
        Path source = root.resolve("source"); Files.writeString(source, "dictionary test");
        Path archive = root.resolve("dictionary.zipx");
        ZipxArchive.pack(archive, List.of(source), List.of("payload"), ZipxMethod.LZMA, null, null);
        long offset;
        try (var zip = org.apache.commons.compress.archivers.zip.ZipFile.builder().setPath(archive).get()) {
            offset = zip.getEntry("payload").getDataOffset();
        }
        byte[] bytes = Files.readAllBytes(archive);
        java.nio.ByteBuffer.wrap(bytes).order(java.nio.ByteOrder.LITTLE_ENDIAN).putInt((int) offset + 5, Integer.MAX_VALUE);
        Files.write(archive, bytes);
        Path output = root.resolve("out");
        assertThrows(IOException.class, () -> ArchiveExtractor.extract(archive, output, null));
        assertEquals(0, count(output));
    }

    /** Selected folders are recursively expanded by the shared pre-archive entry API. */
    @Test void selectedFolderEntryIsExpanded() throws Exception {
        Path folder = Files.createDirectories(root.resolve("folder/nested"));
        Files.writeString(folder.resolve("text"), "nested content");
        Path archive = root.resolve("selected.zipx");
        ArchivePacker.packEntries(archive, root, List.of(folder.getParent()), List.of("renamed"), ArchivePacker.Format.ZIPX, null, null);
        ArchiveExtractor.extract(archive, root.resolve("out"), null);
        assertEquals("nested content", Files.readString(root.resolve("out/renamed/nested/text")));
    }

    /** Archive callbacks use the archive phase and reach completion after successful publication. */
    @Test void archiveProgressUsesArchivePhase() throws Exception {
        Path source = root.resolve("source"); Files.write(source, new byte[2 * 1024 * 1024]);
        List<Float> fractions = new ArrayList<>();
        ProgressReporter reporter = new ProgressReporter() {
            /** {@inheritDoc} */
            public void setStatus(String text) { }
            /** {@inheritDoc} */
            public void setProgress(float fraction, String info) { }
            /** {@inheritDoc} */
            public void setProgress(float fraction, String info, ProgressPhase phase) {
                assertEquals(ProgressPhase.ARCHIVE, phase); fractions.add(fraction);
            }
            /** {@inheritDoc} */
            public void setCanCancel(boolean can) { }
            /** {@inheritDoc} */
            public boolean isCancelled() { return false; }
        };
        ArchivePacker.pack(root.resolve("progress.zipx"), source, ArchivePacker.Format.ZIPX, null, reporter);
        assertTrue(fractions.size() >= 2); assertEquals(1f, fractions.getLast());
    }

    /** Independent Python and 7-Zip fixtures exercise data descriptors and AES interoperability. */
    @Test void independentGoldenArchives() throws Exception {
        Path golden = Path.of("src/test/resources/zipx/golden");
        if (!Files.isDirectory(golden)) golden = Path.of("../../src/test/resources/zipx/golden");
        assertTrue(Files.isDirectory(golden), "Independent ZIPX fixtures are required");
        try (var paths = Files.list(golden)) {
            for (Path archive : paths.filter(p -> p.toString().endsWith(".zipx") && !p.getFileName().toString().startsWith("unsupported-")).toList()) {
                String password = archive.getFileName().toString().contains("aes") ? "reference-password" : null;
                ZipxArchive.verify(archive, password);
                List<Path> files = ArchiveExtractor.extract(archive, root.resolve(archive.getFileName().toString()), password);
                assertTrue(files.stream().anyMatch(p -> {
                    try { return Files.readString(p).equals("Independent ZIPX reference\n".repeat(32)); }
                    catch (IOException e) { return false; }
                }), archive.toString());
            }
        }
    }

    /** Wrong or missing passwords never overwrite existing output. */
    @Test void passwordFailuresLeaveDestinationUntouched() throws Exception {
        Path archive = archive(true), output = Files.createDirectory(root.resolve("out"));
        Files.writeString(output.resolve("payload"), "existing user data");
        assertThrows(ArchiveExtractor.PasswordNeededException.class, () -> ArchiveExtractor.extract(archive, output, null));
        assertThrows(IOException.class, () -> ArchiveExtractor.extract(archive, output, "wrong"));
        assertThrows(IOException.class, () -> ZipxArchive.verify(archive, "wrong"));
        assertEquals("existing user data", Files.readString(output.resolve("payload")));
        assertEquals(1, count(output));
    }

    /** AE-1 must check CRC in addition to ciphertext authentication; AE-2 requires a zero CRC. */
    @Test void independentAesCrcFailuresDoNotPublishPlaintext() throws Exception {
        Path golden = Path.of("src/test/resources/zipx/golden");
        if (!Files.isDirectory(golden)) golden = Path.of("../../src/test/resources/zipx/golden");
        for (int version : List.of(1, 2)) {
            byte[] bytes = Files.readAllBytes(golden.resolve("python-xz-aes256-ae" + version + ".zipx"));
            java.nio.ByteBuffer records = java.nio.ByteBuffer.wrap(bytes).order(java.nio.ByteOrder.LITTLE_ENDIAN);
            for (int index = 0; index <= bytes.length - 4; index++) {
                int signature = records.getInt(index);
                if (signature == 0x04034b50) records.putInt(index + 14, 0x12345678);
                if (signature == 0x02014b50) records.putInt(index + 16, 0x12345678);
            }
            Path archive = root.resolve("bad-ae" + version + ".zipx");
            Files.write(archive, bytes);
            Path output = root.resolve("bad-ae" + version);
            assertThrows(IOException.class, () -> ZipxArchive.verify(archive, "reference-password"));
            assertThrows(IOException.class, () -> ArchiveExtractor.extract(archive, output, "reference-password"));
            assertEquals(0, count(output));
        }
    }

    /** Both CRC failure and an AES tag failure prevent publication of every archive entry. */
    @Test void corruptionAndTruncationAreRejected() throws Exception {
        for (boolean aes : List.of(false, true)) {
            Path archive = archive(aes);
            byte[] original = Files.readAllBytes(archive);
            long offset, size;
            try (var zip = org.apache.commons.compress.archivers.zip.ZipFile.builder().setPath(archive).get()) {
                var entry = zip.getEntry("payload"); offset = entry.getDataOffset(); size = entry.getCompressedSize();
            }
            for (String damage : List.of("payload", "tag", "truncated")) {
                byte[] bytes = original.clone();
                if (damage.equals("truncated")) bytes = Arrays.copyOf(bytes, (int) (offset + size - 3));
                else bytes[(int) (offset + (damage.equals("tag") ? size - 1 : aes ? 18 : 15))] ^= 1;
                Path bad = root.resolve("bad-" + aes + "-" + damage + ".zipx"); Files.write(bad, bytes);
                Path output = root.resolve("out-" + aes + "-" + damage);
                assertThrows(IOException.class, () -> ArchiveExtractor.extract(bad, output, aes ? "correct" : null));
                assertThrows(IOException.class, () -> ZipxArchive.verify(bad, aes ? "correct" : null));
                assertEquals(0, count(output));
            }
        }
    }

    /** Unsupported methods are named explicitly and cannot silently drop an entry. */
    @Test void unsupportedMethodsFailBeforeWriting() throws Exception {
        for (int method : List.of(94, 96, 97, 98, 1234)) {
            Path archive = rawArchive("method-" + method, "payload", method);
            Path output = root.resolve("out-" + method);
            IOException error = assertThrows(IOException.class, () -> ArchiveExtractor.extract(archive, output, null));
            assertTrue(error.getMessage().contains(Integer.toString(method)));
            assertEquals(0, count(output));
        }
    }

    /** Portable path validation covers files and directories before any output is exported. */
    @Test void unsafeNamesAndDuplicateEntriesAreRejected() throws Exception {
        for (String name : List.of("../escape", "/absolute", "C:/drive", "dir\\escape", "../dir/")) {
            Path archive = rawArchive("unsafe-" + Math.abs(name.hashCode()), name, 0);
            Path output = root.resolve("out-" + Math.abs(name.hashCode()));
            assertThrows(IOException.class, () -> ArchiveExtractor.extract(archive, output, null), name);
            assertEquals(0, count(output));
        }
        Path text = root.resolve("source"); Files.writeString(text, "test");
        assertThrows(IOException.class, () -> ZipxArchive.pack(root.resolve("duplicate.zipx"), List.of(text, text), List.of("same", "SAME"), ZipxMethod.XZ, null, null));
    }

    /** The extension does not determine compression capability. */
    @Test void advancedMethodsWithZipExtensionWork() throws Exception {
        Path archive = archive(true), renamed = root.resolve("renamed.zip"); Files.copy(archive, renamed);
        assertEquals(1, ArchiveExtractor.extract(renamed, root.resolve("renamed-out"), "correct").size());
    }

    /** A legacy Deflate ZIP remains readable when named ZIPX. */
    @Test void legacyZipWithZipxExtensionWorks() throws Exception {
        Path archive = root.resolve("deflate.zipx");
        try (var zip = new java.util.zip.ZipOutputStream(Files.newOutputStream(archive))) {
            zip.putNextEntry(new java.util.zip.ZipEntry("payload")); zip.write("legacy".getBytes()); zip.closeEntry();
        }
        assertEquals("legacy", Files.readString(ArchiveExtractor.extract(archive, root.resolve("legacy"), null).getFirst()));
    }

    /** ZIPX passwords use native AES regardless of the custom wrapper setting. */
    @Test void nativePasswordPolicyAndFormatNaming() {
        boolean saved = SettingsManager.isArchiveCustomEncryption();
        try {
            SettingsManager.setArchiveCustomEncryption(false);
            assertEquals("explicit", ArchivePacker.resolveArchivePassword("explicit", null, ArchivePacker.Format.ZIPX));
            assertFalse(ArchivePacker.isCustomEncryptionFormat(ArchivePacker.Format.ZIPX));
            assertEquals(ArchivePacker.Format.ZIPX, ArchivePacker.parseFormat("zipx"));
            assertEquals(".zipx", ArchivePacker.extOf(ArchivePacker.Format.ZIPX));
            assertTrue(ArchiveExtractor.isArchive(Path.of("sample.ZIPX")));
            assertEquals("sample", ArchivePostExtract.folderNameFor(Path.of("sample.zipx")));
        } finally { SettingsManager.setArchiveCustomEncryption(saved); }
    }

    /** Folder packing preserves nested files and empty directories. */
    @Test void folderPackingAndExplicitNames() throws Exception {
        Path folder = Files.createDirectory(root.resolve("folder"));
        Files.createDirectory(folder.resolve("empty")); Files.writeString(folder.resolve("text"), "folder payload");
        Path archive = root.resolve("folder.zipx"); ArchivePacker.pack(archive, folder, ArchivePacker.Format.ZIPX, "correct");
        ArchiveExtractor.extract(archive, root.resolve("folder-out"), "correct");
        assertEquals("folder payload", Files.readString(root.resolve("folder-out/folder/text")));
        assertTrue(Files.isDirectory(root.resolve("folder-out/folder/empty")));
    }

    /** Cancellation preserves an existing archive and removes task staging files. */
    @Test void cancellationPreservesExistingArchive() throws Exception {
        Path source = root.resolve("source"), output = root.resolve("existing.zipx");
        Files.writeString(source, "source"); Files.writeString(output, "existing archive");
        ProgressReporter cancelled = new ProgressReporter() {
            /** {@inheritDoc} */
            public void setStatus(String text) { }
            /** {@inheritDoc} */
            public void setProgress(float fraction, String info) { }
            /** {@inheritDoc} */
            public void setCanCancel(boolean can) { }
            /** {@inheritDoc} */
            public boolean isCancelled() { return true; }
        };
        assertThrows(IOException.class, () -> ArchivePacker.pack(output, source, ArchivePacker.Format.ZIPX, null, cancelled));
        assertEquals("existing archive", Files.readString(output));
        assertEquals(2, count(root));
    }

    /**
     * Creates a small archive for failure testing.
     * @param aes whether to encrypt
     * @return archive path
     * @throws Exception creation failed
     */
    private Path archive(boolean aes) throws Exception {
        Path source = root.resolve("source"); Files.writeString(source, "archive payload ".repeat(1000));
        Path output = root.resolve("payload-" + aes + ".zipx");
        ArchivePacker.packEntries(output, root, List.of(source), List.of("payload"), ArchivePacker.Format.ZIPX, aes ? "correct" : null, null);
        return output;
    }

    /**
     * Constructs malformed or unsupported raw entries without the production writer.
     * @param id unique archive name
     * @param name raw entry name
     * @param method raw method number
     * @return archive path
     * @throws Exception fixture construction failed
     */
    private Path rawArchive(String id, String name, int method) throws Exception {
        Path archive = root.resolve(id + ".zipx");
        byte[] filename = name.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        var bytes = java.nio.ByteBuffer.allocate(30 + filename.length + 46 + filename.length + 22)
                .order(java.nio.ByteOrder.LITTLE_ENDIAN);
        bytes.putInt(0x04034b50).putShort((short) 63).putShort((short) 0x800).putShort((short) method)
                .putInt(0).putInt(0).putInt(0).putInt(0).putShort((short) filename.length).putShort((short) 0).put(filename);
        int central = bytes.position();
        bytes.putInt(0x02014b50).putShort((short) 63).putShort((short) 63).putShort((short) 0x800).putShort((short) method)
                .putInt(0).putInt(0).putInt(0).putInt(0).putShort((short) filename.length).putShort((short) 0)
                .putShort((short) 0).putShort((short) 0).putShort((short) 0).putInt(0).putInt(0).put(filename);
        int length = bytes.position() - central;
        bytes.putInt(0x06054b50).putInt(0).putShort((short) 1).putShort((short) 1).putInt(length).putInt(central).putShort((short) 0);
        Files.write(archive, bytes.array());
        return archive;
    }

    /**
     * Counts immediate output children including leaked staging files.
     * @param directory output directory
     * @return child count
     * @throws IOException listing failed
     */
    private long count(Path directory) throws IOException {
        if (!Files.exists(directory)) return 0;
        try (var paths = Files.list(directory)) { return paths.count(); }
    }
}
