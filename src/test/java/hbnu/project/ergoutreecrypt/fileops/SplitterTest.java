package hbnu.project.ergoutreecrypt.fileops;

import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

/**
 * {@link Splitter} 切分 / 合并 / 命名规则，不涉及密码学。
 *
 * @author ErgouTree
 */
class SplitterTest {

    /**
     * 切分后再合并应得到与原文完全相同的字节。
     *
     * @throws Exception 读写失败
     */
    @Test
    void splitThenRecombine_restoresExactBytes() throws Exception {
        Path tmp = Files.createTempDirectory("split-id-");
        try {
            byte[] data = new byte[3 * 1024 * 1024 + 77];
            new java.util.Random(7).nextBytes(data);
            Path src = tmp.resolve("payload.bin");
            Files.write(src, data);

            Splitter.split(src, 1024 * 1024);
            assertTrue(Files.exists(Path.of(src + ".0")));
            assertTrue(Files.exists(Path.of(src + ".1")));
            assertTrue(Files.exists(Path.of(src + ".2")));
            assertTrue(Files.exists(Path.of(src + ".3")));
            assertFalse(Files.exists(Path.of(src + ".4")));

            Path merged = tmp.resolve("merged.bin");
            Splitter.recombine(merged, src.toString());
            assertArrayEquals(data, Files.readAllBytes(merged));
        } finally {
            rmrf(tmp);
        }
    }

    /**
     * 文件小于一片时只产生 {@code .0}。
     *
     * @throws Exception 读写失败
     */
    @Test
    void fileSmallerThanChunk_producesOnlyZero() throws Exception {
        Path tmp = Files.createTempDirectory("split-small-");
        try {
            Path src = tmp.resolve("tiny.bin");
            Files.write(src, "hello".getBytes());
            Splitter.split(src, 1024 * 1024);
            assertTrue(Files.exists(Path.of(src + ".0")));
            assertFalse(Files.exists(Path.of(src + ".1")));
            Path merged = tmp.resolve("out.bin");
            Splitter.recombine(merged, src.toString());
            assertEquals("hello", Files.readString(merged));
        } finally {
            rmrf(tmp);
        }
    }

    /**
     * {@code .ergou.N} 与 {@code .pcv.N} 均识别为分卷碎片。
     */
    @Test
    void chunkPathDetection_supportsErgouAndPcv() {
        assertTrue(Splitter.isSplitChunkPath("D:/out/movie.bin.ergou.0"));
        assertTrue(Splitter.isSplitChunkPath("movie.bin.ergou.12"));
        assertTrue(Splitter.isSplitChunkPath("legacy.pcv.3"));
        assertFalse(Splitter.isSplitChunkPath("movie.bin.ergou"));
        assertFalse(Splitter.isSplitChunkPath("movie.bin"));
        assertFalse(Splitter.isSplitChunkPath("movie.bin.ergou.incomplete"));

        String base = Splitter.splitChunkBase("C:/enc/a.bin.ergou.2");
        assertNotNull(base);
        assertTrue(base.replace('\\', '/').endsWith("enc/a.bin.ergou"));
        assertNull(Splitter.splitChunkBase("a.bin.ergou"));
    }

    /**
     * 缺少中间片时合并应失败（按最大编号 + 1 连续读取）。
     *
     * @throws Exception 读写失败
     */
    @Test
    void missingMiddleChunk_recombineFails() throws Exception {
        Path tmp = Files.createTempDirectory("split-gap-");
        try {
            Path src = tmp.resolve("file.ergou");
            Files.write(src, new byte[2 * 1024 * 1024 + 10]);
            Splitter.split(src, 1024 * 1024);
            Files.delete(Path.of(src + ".1"));
            Path merged = tmp.resolve("out.bin");
            assertThrows(Exception.class, () -> Splitter.recombine(merged, src.toString()));
        } finally {
            rmrf(tmp);
        }
    }

    /**
     * {@link Splitter#listChunks} 按序号返回全部碎片路径。
     *
     * @throws Exception 读写失败
     */
    @Test
    void listChunks_isOrdered() throws Exception {
        Path tmp = Files.createTempDirectory("split-list-");
        try {
            Path src = tmp.resolve("x.ergou");
            Files.write(src, new byte[2 * 1024 * 1024 + 1]);
            Splitter.split(src, 1024 * 1024);
            List<Path> chunks = Splitter.listChunks(src);
            assertEquals(3, chunks.size());
            assertEquals(src + ".0", chunks.get(0).toString());
            assertEquals(src + ".1", chunks.get(1).toString());
            assertEquals(src + ".2", chunks.get(2).toString());
        } finally {
            rmrf(tmp);
        }
    }

    /**
     * 递归删除临时目录。
     *
     * @param dir 目录
     * @throws Exception 列举失败
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
