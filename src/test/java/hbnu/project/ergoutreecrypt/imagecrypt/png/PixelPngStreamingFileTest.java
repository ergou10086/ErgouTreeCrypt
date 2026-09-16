package hbnu.project.ergoutreecrypt.imagecrypt.png;

import hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptProtocol;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 使用 Phase 0 真实尺寸图片夹具验证文件级流式 PNG 往返。
 *
 * @author ErgouTree
 * @since 2026/9/16
 */
final class PixelPngStreamingFileTest {

    /**
     * 每个测试独立的临时输出目录。
     */
    @TempDir
    Path tempDirectory;

    /**
     * 1.2 MiB PNG 原文件必须跨默认 1 MiB IDAT 边界逐字节恢复。
     *
     * @throws Exception 文件读写、资源定位或 PNG 校验失败
     */
    @Test
    void realImageFixtureRoundTripsThroughMultipleDefaultIdatChunks() throws Exception {
        Path source = fixturePath("sample.png");
        long length = Files.size(source);
        int width = 1024;
        long pixels = (length + ImageCryptProtocol.PNG_BYTES_PER_PIXEL - 1L)
                / ImageCryptProtocol.PNG_BYTES_PER_PIXEL;
        int height = Math.toIntExact((pixels + width - 1L) / width);
        Path encrypted = tempDirectory.resolve("sample.egimg-container.png");
        Path restored = tempDirectory.resolve("sample.restored.png");

        try (InputStream input = Files.newInputStream(source);
             OutputStream output = Files.newOutputStream(encrypted)) {
            new PixelPngWriter().write(output, width, height, input, length);
        }
        try (InputStream input = Files.newInputStream(encrypted);
             OutputStream output = Files.newOutputStream(restored)) {
            new PixelPngReader().read(input, output, length);
        }

        assertEquals(-1L, Files.mismatch(source, restored));
        assertTrue(countIdatChunks(encrypted) > 1,
                "默认 1 MiB 分块应让该夹具跨越多个 IDAT");
    }

    /**
     * 定位图片加密测试资源。
     *
     * @param name 资源文件名
     * @return 文件系统路径
     * @throws URISyntaxException 资源 URI 非法
     */
    private static Path fixturePath(final String name) throws URISyntaxException {
        return Path.of(PixelPngStreamingFileTest.class
                .getResource("/imagecrypt/fixtures/" + name).toURI());
    }

    /**
     * 流式统计 PNG 的 IDAT 块数。
     *
     * @param png PNG 文件
     * @return IDAT 数量
     * @throws Exception 文件读取或块校验失败
     */
    private static int countIdatChunks(final Path png) throws Exception {
        int count = 0;
        try (InputStream input = Files.newInputStream(png)) {
            PngChunkReader reader = new PngChunkReader(input);
            reader.readSignature();
            PngChunkReader.ChunkHeader header;
            while ((header = reader.nextChunk()) != null) {
                if (header.isType("IDAT")) {
                    count++;
                }
                reader.skipChunk();
            }
        }
        return count;
    }
}
