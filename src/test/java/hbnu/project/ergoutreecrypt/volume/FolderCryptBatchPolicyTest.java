package hbnu.project.ergoutreecrypt.volume;

import hbnu.project.ergoutreecrypt.encoding.RsCodecs;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 批处理策略：阈值单线程、解压后串行、单文件失败跳过。
 *
 * @author ErgouTree
 */
class FolderCryptBatchPolicyTest {

    /**
     * 总大小达到阈值时应强制 1 线程。
     */
    @Test
    void resolveThreadCount_thresholdForcesSerial() {
        BatchResult r = new BatchResult();
        int threads = FolderCrypt.resolveThreadCount(8, 11L << 30, false, r, 10);
        assertEquals(1, threads);
        assertEquals(BatchResult.SerialReason.THRESHOLD, r.serialReason());
    }

    /**
     * 低于阈值时保留配置线程数。
     */
    @Test
    void resolveThreadCount_belowThresholdKeepsConfigured() {
        BatchResult r = new BatchResult();
        int threads = FolderCrypt.resolveThreadCount(4, 1L << 30, false, r, 10);
        assertEquals(4, threads);
        assertEquals(BatchResult.SerialReason.NONE, r.serialReason());
    }

    /**
     * 解压后解密 / 嵌套强制单线程，优先于阈值。
     */
    @Test
    void resolveThreadCount_forceSerialWins() {
        BatchResult r = new BatchResult();
        int threads = FolderCrypt.resolveThreadCount(8, 100L, true, r, 10);
        assertEquals(1, threads);
        assertEquals(BatchResult.SerialReason.ARCHIVE_EXTRACT, r.serialReason());
    }

    /**
     * OutOfMemoryError 及其包装应识别为内存错误。
     */
    @Test
    void isMemoryError_detectsOomAndCause() {
        assertTrue(FolderCrypt.isMemoryError(new OutOfMemoryError("heap")));
        assertTrue(FolderCrypt.isMemoryError(new java.io.IOException("wrap", new OutOfMemoryError())));
        assertFalse(FolderCrypt.isMemoryError(new java.io.IOException("disk")));
    }

    /**
     * 文件夹中混入错误密码的加密文件时，其余文件应解密成功。
     */
    @Test
    void decryptFolder_skipsAuthFailureAndContinues() throws Exception {
        Path tmp = Files.createTempDirectory("fc-skip-");
        try {
            Path a = tmp.resolve("ok.txt");
            Path b = tmp.resolve("bad.txt");
            Files.write(a, "hello-ok".getBytes());
            Files.write(b, "hello-bad".getBytes());
            Path ea = tmp.resolve("ok.txt.ergou");
            Path eb = tmp.resolve("bad.txt.ergou");
            encryptOne(a, ea, "pw-ok");
            encryptOne(b, eb, "pw-bad");

            Path folder = tmp.resolve("mix");
            Files.createDirectories(folder);
            Files.move(ea, folder.resolve("ok.txt.ergou"));
            Files.move(eb, folder.resolve("bad.txt.ergou"));

            Path decOut = tmp.resolve("decout");
            Files.createDirectories(decOut);
            FolderCrypt.DecryptOptions dop = new FolderCrypt.DecryptOptions();
            dop.password = "pw-ok";
            dop.rsCodecs = new RsCodecs();
            FolderCrypt.decryptAuto(folder, decOut, dop);

            assertTrue(Files.exists(decOut.resolve("mix/ok.txt")));
            assertArrayEquals("hello-ok".getBytes(), Files.readAllBytes(decOut.resolve("mix/ok.txt")));
            assertFalse(Files.exists(decOut.resolve("mix/bad.txt")));
            assertNotNull(dop.batchResult);
            assertEquals(1, dop.batchResult.succeededCount());
            assertEquals(1, dop.batchResult.failedCount());
        } finally {
            rmrf(tmp);
        }
    }

    /**
     * 加密文件夹时单个失败不应阻止其余文件落盘。
     */
    @Test
    void encryptFolder_recordsBatchResultOnSuccess() throws Exception {
        Path tmp = Files.createTempDirectory("fc-enc-batch-");
        try {
            Path in = tmp.resolve("src");
            Files.createDirectories(in);
            Files.write(in.resolve("a.txt"), "aa".getBytes());
            Files.write(in.resolve("b.txt"), "bb".getBytes());
            Path out = tmp.resolve("out");
            Files.createDirectories(out);
            FolderCrypt.EncryptOptions eo = new FolderCrypt.EncryptOptions();
            eo.password = "pw";
            eo.rsCodecs = new RsCodecs();
            FolderCrypt.encryptFolder(in, out, eo);
            assertNotNull(eo.batchResult);
            assertEquals(2, eo.batchResult.succeededCount());
            assertEquals(0, eo.batchResult.failedCount());
            assertTrue(Files.exists(out.resolve("src/a.txt.ergou")));
            assertTrue(Files.exists(out.resolve("src/b.txt.ergou")));
        } finally {
            rmrf(tmp);
        }
    }

    /**
     * 单文件加密辅助。
     *
     * @param src 明文
     * @param out 密文路径
     * @param pw  密码
     */
    private static void encryptOne(Path src, Path out, String pw) throws Exception {
        EncryptRequest req = new EncryptRequest();
        req.setInputFile(src.toString());
        req.setOutputFile(out.toString());
        req.setPassword(pw);
        req.setRsCodecs(new RsCodecs());
        Encryptor.encrypt(req);
    }

    /**
     * 递归删除临时目录。
     *
     * @param dir 目录
     */
    private static void rmrf(Path dir) throws Exception {
        if (!Files.exists(dir)) {
            return;
        }
        try (Stream<Path> w = Files.walk(dir)) {
            w.sorted(Comparator.reverseOrder()).forEach(p -> {
                try {
                    Files.deleteIfExists(p);
                } catch (Exception ignored) {
                }
            });
        }
    }
}
