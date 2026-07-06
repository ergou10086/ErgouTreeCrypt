package hbnu.project.ergoutreecrypt.stego;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * PNG LSB 嵌入/提取引擎测试。
 *
 * @author ErgouTree
 */
class PngLsbStegoTest {

    /**
     * 创建简单的 RGB 测试图像（100×100）。
     */
    private static BufferedImage createTestImage(final int w, final int h) {
        BufferedImage img = new BufferedImage(w, h, BufferedImage.TYPE_INT_RGB);
        for (int y = 0; y < h; y++) {
            for (int x = 0; x < w; x++) {
                int r = (x * 7 + y * 3) & 0xFF;
                int g = (x * 11 + y * 5) & 0xFF;
                int b = (x * 13 + y * 7) & 0xFF;
                int rgb = (r << 16) | (g << 8) | b;
                img.setRGB(x, y, rgb);
            }
        }
        return img;
    }

    private static Path writeTestPng(final Path dir, final String name,
                                      final BufferedImage img) throws Exception {
        Path p = dir.resolve(name);
        ImageIO.write(img, "PNG", p.toFile());
        return p;
    }

    @Test
    void embedAndExtractLsb1(@TempDir Path dir) throws Exception {
        BufferedImage img = createTestImage(100, 100);
        Path src = writeTestPng(dir, "src.png", img);
        Path stego = dir.resolve("stego.png");

        byte[] payload = "Hello, Steganography! Secret data here.".getBytes();

        // 构建完整的元数据头，payloadSize 与实际 payload 大小一致
        StegoMetadata meta = StegoMetadata.builder()
                .lsbDepth(1).hasMac(false).paranoid(false)
                .channels(3).payloadSize(payload.length).fileName("test.dat")
                .build();
        byte[] header = meta.toBytes();

        PngLsbStego.embed(src, stego, header, payload, 1);
        assertTrue(Files.exists(stego), "隐写图片应存在");

        // 提取
        PngLsbStego.ExtractResult result = PngLsbStego.extract(stego, header.length, 1);
        assertNotNull(result);
        assertArrayEquals(payload, result.encryptedPayload(), "嵌入的 payload 应完整还原");
    }

    @Test
    void embedAndExtractLsb2(@TempDir Path dir) throws Exception {
        BufferedImage img = createTestImage(200, 200);
        Path src = writeTestPng(dir, "src.png", img);
        Path stego = dir.resolve("stego.png");

        byte[] payload = new byte[5000];
        for (int i = 0; i < payload.length; i++) payload[i] = (byte) (i & 0xFF);

        StegoMetadata meta = StegoMetadata.builder()
                .lsbDepth(2).hasMac(false).paranoid(false)
                .channels(3).payloadSize(payload.length).fileName("data.bin")
                .build();
        byte[] header = meta.toBytes();

        PngLsbStego.embed(src, stego, header, payload, 2);
        PngLsbStego.ExtractResult result = PngLsbStego.extract(stego, header.length, 2);
        assertNotNull(result);
        assertArrayEquals(payload, result.encryptedPayload());
    }

    @Test
    void capacityInsufficient(@TempDir Path dir) throws Exception {
        BufferedImage img = createTestImage(10, 10); // 太小
        Path src = writeTestPng(dir, "tiny.png", img);
        Path stego = dir.resolve("stego.png");

        byte[] hugePayload = new byte[50000];

        assertThrows(ImageStegoException.class, () ->
                PngLsbStego.embed(src, stego, new byte[10], hugePayload, 1));
    }

    @Test
    void grayscaleImageSupported(@TempDir Path dir) throws Exception {
        BufferedImage gray = new BufferedImage(100, 100, BufferedImage.TYPE_BYTE_GRAY);
        for (int y = 0; y < 100; y++) {
            for (int x = 0; x < 100; x++) {
                gray.setRGB(x, y, (x + y) & 0xFF);
            }
        }
        Path src = writeTestPng(dir, "gray.png", gray);
        Path stego = dir.resolve("stego.png");

        byte[] payload = "gray test".getBytes();
        StegoMetadata meta = StegoMetadata.builder()
                .lsbDepth(1).hasMac(false).paranoid(false)
                .channels(1).payloadSize(payload.length).fileName("g.dat")
                .build();
        byte[] header = meta.toBytes();

        PngLsbStego.embed(src, stego, header, payload, 1);
        PngLsbStego.ExtractResult result = PngLsbStego.extract(stego, header.length, 1);
        assertNotNull(result);
        assertArrayEquals(payload, result.encryptedPayload());
    }

    @Test
    void paletteImageRejected(@TempDir Path dir) throws Exception {
        BufferedImage palette = new BufferedImage(100, 100, BufferedImage.TYPE_BYTE_INDEXED);
        Path src = writeTestPng(dir, "palette.png", palette);

        assertThrows(ImageStegoException.class, () ->
                PngLsbStego.embed(src, dir.resolve("out.png"),
                        new byte[10], new byte[10], 1));
    }
}
