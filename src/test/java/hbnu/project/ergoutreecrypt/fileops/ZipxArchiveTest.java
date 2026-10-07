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

/** ZIPX 完整性、标准格式及失败时不发布产物的回归测试。 */
class ZipxArchiveTest {
    @TempDir Path root;

    /** 每种可写编解码器在启用或关闭 AES 时，均还原 Unicode 名称、空文件与目录。 */
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

    /** 第二条目损坏时，已验证的第一条目也不能发布。 */
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

    /** 不可信归档中的 LZMA 字典不能超过配置的内存预算。 */
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

    /** 共享归档前处理接口递归展开选中的文件夹。 */
    @Test void selectedFolderEntryIsExpanded() throws Exception {
        Path folder = Files.createDirectories(root.resolve("folder/nested"));
        Files.writeString(folder.resolve("text"), "nested content");
        Path archive = root.resolve("selected.zipx");
        ArchivePacker.packEntries(archive, root, List.of(folder.getParent()), List.of("renamed"), ArchivePacker.Format.ZIPX, null, null);
        ArchiveExtractor.extract(archive, root.resolve("out"), null);
        assertEquals("nested content", Files.readString(root.resolve("out/renamed/nested/text")));
    }

    /** 归档回调使用归档阶段，且仅在成功发布后报告完成。 */
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

    /** 独立 Python 和 7-Zip 样例覆盖数据描述符与 AES 互通。 */
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

    /** 缺少密码或密码错误时，绝不覆盖已有输出。 */
    @Test void passwordFailuresLeaveDestinationUntouched() throws Exception {
        Path archive = archive(true), output = Files.createDirectory(root.resolve("out"));
        Files.writeString(output.resolve("payload"), "existing user data");
        assertThrows(ArchiveExtractor.PasswordNeededException.class, () -> ArchiveExtractor.extract(archive, output, null));
        assertThrows(IOException.class, () -> ArchiveExtractor.extract(archive, output, "wrong"));
        assertThrows(IOException.class, () -> ZipxArchive.verify(archive, "wrong"));
        assertEquals("existing user data", Files.readString(output.resolve("payload")));
        assertEquals(1, count(output));
    }

    /** AE-1 除密文认证外还校验 CRC；AE-2 要求 CRC 为零。 */
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

    /** CRC 或 AES 标签校验失败时，所有归档条目都禁止发布。 */
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

    /** 明确报告不支持的方法，不得静默丢弃条目。 */
    @Test void unsupportedMethodsFailBeforeWriting() throws Exception {
        for (int method : List.of(94, 96, 97, 98, 1234)) {
            Path archive = rawArchive("method-" + method, "payload", method);
            Path output = root.resolve("out-" + method);
            IOException error = assertThrows(IOException.class, () -> ArchiveExtractor.extract(archive, output, null));
            assertTrue(error.getMessage().contains(Integer.toString(method)));
            assertEquals(0, count(output));
        }
    }

    /** 导出任何输出之前，可移植路径校验同时检查文件和目录。 */
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

    /** 不能通过扩展名判断压缩能力。 */
    @Test void advancedMethodsWithZipExtensionWork() throws Exception {
        Path archive = archive(true), renamed = root.resolve("renamed.zip"); Files.copy(archive, renamed);
        assertEquals(1, ArchiveExtractor.extract(renamed, root.resolve("renamed-out"), "correct").size());
    }

    /** 旧版 Deflate ZIP 即使改名为 ZIPX，仍可读取。 */
    @Test void legacyZipWithZipxExtensionWorks() throws Exception {
        Path archive = root.resolve("deflate.zipx");
        try (var zip = new java.util.zip.ZipOutputStream(Files.newOutputStream(archive))) {
            zip.putNextEntry(new java.util.zip.ZipEntry("payload")); zip.write("legacy".getBytes()); zip.closeEntry();
        }
        assertEquals("legacy", Files.readString(ArchiveExtractor.extract(archive, root.resolve("legacy"), null).getFirst()));
    }

    /** ZIPX 密码始终使用原生 AES，不受自定义包裹设置影响。 */
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

    /** 文件夹打包保留嵌套文件和空目录。 */
    @Test void folderPackingAndExplicitNames() throws Exception {
        Path folder = Files.createDirectory(root.resolve("folder"));
        Files.createDirectory(folder.resolve("empty")); Files.writeString(folder.resolve("text"), "folder payload");
        Path archive = root.resolve("folder.zipx"); ArchivePacker.pack(archive, folder, ArchivePacker.Format.ZIPX, "correct");
        ArchiveExtractor.extract(archive, root.resolve("folder-out"), "correct");
        assertEquals("folder payload", Files.readString(root.resolve("folder-out/folder/text")));
        assertTrue(Files.isDirectory(root.resolve("folder-out/folder/empty")));
    }

    /** 取消操作保留已有归档，并清理本任务暂存文件。 */
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
     * 创建用于失败测试的小型归档。
     * @param aes 是否加密
     * @return 归档路径
     * @throws Exception 创建失败
     */
    private Path archive(boolean aes) throws Exception {
        Path source = root.resolve("source"); Files.writeString(source, "archive payload ".repeat(1000));
        Path output = root.resolve("payload-" + aes + ".zipx");
        ArchivePacker.packEntries(output, root, List.of(source), List.of("payload"), ArchivePacker.Format.ZIPX, aes ? "correct" : null, null);
        return output;
    }

    /**
     * 绕过生产写入器，构造畸形或不支持的原始条目。
     * @param id 唯一归档名称
     * @param name 原始条目名
     * @param method 原始方法编号
     * @return 归档路径
     * @throws Exception 样例构造失败
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
     * 统计输出目录的直接子项，包括泄漏的暂存文件。
     * @param directory 输出目录
     * @return 子项数量
     * @throws IOException 列举失败
     */
    private long count(Path directory) throws IOException {
        if (!Files.exists(directory)) return 0;
        try (var paths = Files.list(directory)) { return paths.count(); }
    }
}
