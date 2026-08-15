package hbnu.project.ergoutreecrypt.history;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 文件历史存储测试。
 *
 * <p>覆盖 JSONL 编解码往返、特殊字符转义、记录数量上限、
 * 损坏行容错、清空与未注册服务降级等关键行为。
 *
 * @author ErgouTree
 * @since 2026/8/14
 */
public final class FileHistoryStoreTest {

    /** JUnit 注入的临时目录，各测试方法独立 */
    @TempDir
    Path tempDir;

    private FileHistoryStore newStore() {
        return new FileHistoryStore(tempDir);
    }

    private static OperationRecord record(String file, String path, String uri,
                                          OperationType type, long ts) {
        return new OperationRecord(file, path, uri, type, ts);
    }

    @Test
    void testRoundTripNewestFirst() {
        FileHistoryStore store = newStore();
        store.record(record("a.txt", "/out/a.txt", null, OperationType.GENERIC_ENCRYPT, 1000L));
        store.record(record("b.mp4", "/out/b.mp4", "content://tree/1", OperationType.STEGO_ENCODE, 2000L));
        store.record(record("c.wav", "/out/c.wav", null, OperationType.FPE_DECRYPT, 3000L));

        List<OperationRecord> list = store.list();
        assertEquals(3, list.size());
        // 最新在前
        assertEquals("c.wav", list.get(0).fileName());
        assertEquals(OperationType.FPE_DECRYPT, list.get(0).type());
        assertEquals(3000L, list.get(0).timestampEpochMillis());
        assertEquals("b.mp4", list.get(1).fileName());
        assertEquals("content://tree/1", list.get(1).outputUri());
        assertEquals("a.txt", list.get(2).fileName());
        assertEquals("/out/a.txt", list.get(2).outputPath());
    }

    @Test
    void testSpecialCharactersRoundTrip() {
        FileHistoryStore store = newStore();
        // 引号、反斜杠、换行、制表符、控制字符、中文与 emoji
        String tricky = "引号\"反斜杠\\换行\n制表\t回车\r控制中文路径🚀📁";
        store.record(record(tricky, "C:\\dir\\" + tricky, "content://\"tree\"/x", OperationType.GENERIC_ENCRYPT, 42L));

        List<OperationRecord> list = store.list();
        assertEquals(1, list.size());
        OperationRecord r = list.get(0);
        assertEquals(tricky, r.fileName());
        assertEquals("C:\\dir\\" + tricky, r.outputPath());
        assertEquals("content://\"tree\"/x", r.outputUri());
        assertEquals(OperationType.GENERIC_ENCRYPT, r.type());
        assertEquals(42L, r.timestampEpochMillis());
    }

    @Test
    void testValueContainingFieldNameNotMispParsed() {
        FileHistoryStore store = newStore();
        // 文件名内嵌类似键名与转义的序列，解析器不得误判
        String sneaky = "a\"path\":\"b\\\\n\",\"uri\":\"c";
        store.record(record(sneaky, null, null, OperationType.GENERIC_DECRYPT, 7L));

        List<OperationRecord> list = store.list();
        assertEquals(1, list.size());
        assertEquals(sneaky, list.get(0).fileName());
        assertNull(list.get(0).outputPath());
        assertNull(list.get(0).outputUri());
    }

    @Test
    void testNullPathAndUriRoundTrip() {
        FileHistoryStore store = newStore();
        store.record(record("only-name.txt", null, null, OperationType.STEGO_EXTRACT, 9L));

        OperationRecord r = store.list().get(0);
        assertEquals("only-name.txt", r.fileName());
        assertNull(r.outputPath());
        assertNull(r.outputUri());
    }

    @Test
    void testCapDropsOldest() {
        FileHistoryStore store = newStore();
        for (int i = 0; i < FileHistoryStore.MAX_RECORDS + 5; i++) {
            store.record(record("f" + i, "/out/f" + i, null, OperationType.GENERIC_ENCRYPT, i));
        }

        List<OperationRecord> list = store.list();
        assertEquals(FileHistoryStore.MAX_RECORDS, list.size());
        // 最旧 5 条（0-4）被丢弃，最新一条在最前
        assertEquals("f504", list.get(0).fileName());
        assertEquals("f5", list.get(list.size() - 1).fileName());
    }

    @Test
    void testCorruptedLinesSkipped() throws Exception {
        FileHistoryStore store = newStore();
        store.record(record("good.txt", "/out/good.txt", null, OperationType.GENERIC_ENCRYPT, 1L));
        // 手动追加损坏行：截断 JSON、非法数字、未知类型、非 JSON 文本
        java.nio.file.Files.writeString(tempDir.resolve("history.jsonl"),
                "{\"ts\":999,\"type\":\"GENERIC_ENCRYPT\",\"file\":\"broken\n"
                        + "{\"ts\":\"not-a-number\",\"type\":\"GENERIC_ENCRYPT\",\"file\":\"x\"}\n"
                        + "{\"ts\":1,\"type\":\"FUTURE_TYPE\",\"file\":\"x\"}\n"
                        + "random garbage\n",
                java.nio.charset.StandardCharsets.UTF_8,
                java.nio.file.StandardOpenOption.APPEND);

        List<OperationRecord> list = store.list();
        assertEquals(1, list.size());
        assertEquals("good.txt", list.get(0).fileName());
    }

    @Test
    void testUnknownTypeLineSkipped() throws Exception {
        FileHistoryStore store = newStore();
        store.record(record("known.txt", null, null, OperationType.FPE_ENCRYPT, 1L));
        java.nio.file.Files.writeString(tempDir.resolve("history.jsonl"),
                "{\"ts\":2,\"type\":\"BRAND_NEW_TYPE\",\"file\":\"future.txt\",\"path\":null,\"uri\":null}\n",
                java.nio.charset.StandardCharsets.UTF_8,
                java.nio.file.StandardOpenOption.APPEND);

        List<OperationRecord> list = store.list();
        assertEquals(1, list.size());
        assertEquals("known.txt", list.get(0).fileName());
    }

    @Test
    void testClearRemovesRecords() {
        FileHistoryStore store = newStore();
        store.record(record("a.txt", null, null, OperationType.GENERIC_ENCRYPT, 1L));
        assertEquals(1, store.list().size());

        store.clear();
        assertTrue(store.list().isEmpty());
        // 清空后仍可继续记录
        store.record(record("b.txt", null, null, OperationType.GENERIC_DECRYPT, 2L));
        assertEquals(1, store.list().size());
    }

    @Test
    void testUnregisteredServiceDegradesGracefully() {
        HistoryService.register(null);
        HistoryService.record(OperationType.GENERIC_ENCRYPT, "a.txt", "/out/a.txt", null);
        assertTrue(HistoryService.list().isEmpty());
        HistoryService.clear();
    }

    @Test
    void testServiceIgnoresBlankFileName() {
        FileHistoryStore store = newStore();
        HistoryService.register(store);
        HistoryService.record(OperationType.GENERIC_ENCRYPT, null, "/out", null);
        HistoryService.record(OperationType.GENERIC_ENCRYPT, "  ", "/out", null);
        HistoryService.record(OperationType.GENERIC_ENCRYPT, "ok.txt", "/out", null);

        assertEquals(1, store.list().size());
        assertEquals("ok.txt", store.list().get(0).fileName());
    }

    @Test
    void testServiceRecordForwardsFields() {
        FileHistoryStore store = newStore();
        HistoryService.register(store);
        HistoryService.record(OperationType.FPE_ENCRYPT, "song.mp3", "/out/song.mp3", "content://tree/9");

        OperationRecord r = store.list().get(0);
        assertEquals("song.mp3", r.fileName());
        assertEquals("/out/song.mp3", r.outputPath());
        assertEquals("content://tree/9", r.outputUri());
        assertEquals(OperationType.FPE_ENCRYPT, r.type());
        assertTrue(r.timestampEpochMillis() > 0);
    }
}
