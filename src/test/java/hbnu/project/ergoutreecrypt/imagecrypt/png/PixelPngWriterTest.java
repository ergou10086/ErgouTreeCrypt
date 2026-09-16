package hbnu.project.ergoutreecrypt.imagecrypt.png;

import hbnu.project.ergoutreecrypt.exception.ErrorKind;
import hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptException;
import hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptRandomSource;
import org.junit.jupiter.api.Test;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.InflaterInputStream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link PixelPngWriter} 的流式映射与查看器兼容测试。
 *
 * @author ErgouTree
 * @since 2026/9/16
 */
final class PixelPngWriterTest {

    /**
     * writer 产物必须能被标准 ImageIO 解码为正确尺寸的 RGB 图片。
     *
     * @throws Exception 写出或解码失败
     */
    @Test
    void generatedPngIsReadableByImageIo() throws Exception {
        byte[] payload = sequence(700);
        byte[] png = write(17, 14, payload, 64);

        BufferedImage image = ImageIO.read(new ByteArrayInputStream(png));
        assertNotNull(image);
        assertEquals(17, image.getWidth());
        assertEquals(14, image.getHeight());
    }

    /**
     * 0 字节、恰好一行和跨多个 IDAT 的逻辑边界都必须逐字节恢复。
     *
     * @throws Exception 读写失败
     */
    @Test
    void logicalBoundariesRoundTripExactly() throws Exception {
        assertRoundTrip(7, 3, new byte[0], 19);
        assertRoundTrip(7, 3, sequence(21), 19);
        assertRoundTrip(31, 20, sequence(1_700), 37);
    }

    /**
     * writer 必须按 IHDR、sRGB、连续 IDAT、IEND 排列块，扫描线统一使用 filter 0。
     *
     * @throws Exception 解析或解压失败
     */
    @Test
    void writerUsesNormativeChunkOrderAndFilterZero() throws Exception {
        int width = 9;
        int height = 5;
        byte[] png = write(width, height, sequence(80), 17);
        PngChunkReader reader = new PngChunkReader(new ByteArrayInputStream(png));
        reader.readSignature();

        List<String> types = new ArrayList<>();
        ByteArrayOutputStream compressed = new ByteArrayOutputStream();
        PngChunkReader.ChunkHeader header;
        byte[] buffer = new byte[13];
        while ((header = reader.nextChunk()) != null) {
            types.add(header.type());
            if (header.isType("IDAT")) {
                int count;
                while ((count = reader.readChunkData(buffer, 0, buffer.length)) >= 0) {
                    if (count > 0) {
                        compressed.write(buffer, 0, count);
                    }
                }
            } else {
                reader.skipChunk();
            }
        }

        assertEquals("IHDR", types.get(0));
        assertEquals("sRGB", types.get(1));
        assertEquals("IEND", types.get(types.size() - 1));
        long idatCount = types.stream().filter("IDAT"::equals).count();
        assertTrue(idatCount > 1, "小分块配置应生成多个 IDAT");

        byte[] scanlines;
        try (InflaterInputStream inflater = new InflaterInputStream(
                new ByteArrayInputStream(compressed.toByteArray()))) {
            scanlines = inflater.readAllBytes();
        }
        int rowStride = width * 3 + 1;
        assertEquals(rowStride * height, scanlines.length);
        for (int y = 0; y < height; y++) {
            assertEquals(0, scanlines[y * rowStride] & 0xff);
        }
    }

    /**
     * 输入短于或长于声明长度时必须失败，避免协议长度与像素内容分歧。
     */
    @Test
    void logicalInputMustMatchDeclaredLength() {
        PixelPngWriter writer = writer(64);
        ImageCryptException shortInput = assertThrows(ImageCryptException.class,
                () -> writer.write(new ByteArrayOutputStream(), 4, 4,
                        new ByteArrayInputStream(new byte[2]), 3));
        assertEquals(ErrorKind.INVALID_HEADER, shortInput.kind());

        ImageCryptException extraInput = assertThrows(ImageCryptException.class,
                () -> writer.write(new ByteArrayOutputStream(), 4, 4,
                        new ByteArrayInputStream(new byte[2]), 1));
        assertEquals(ErrorKind.INVALID_HEADER, extraInput.kind());
    }

    /**
     * 超出画布容量的载荷必须在开始写 PNG 前拒绝。
     */
    @Test
    void capacityOverflowIsRejectedBeforeWriting() {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        ImageCryptException thrown = assertThrows(ImageCryptException.class,
                () -> writer(64).write(output, 1, 1,
                        new ByteArrayInputStream(new byte[4]), 4));
        assertEquals(ErrorKind.CAPACITY_INSUFFICIENT, thrown.kind());
        assertEquals(0, output.size());
    }

    /**
     * 写出并用共享 reader 验证一个逻辑载荷。
     *
     * @param width     画布宽度
     * @param height    画布高度
     * @param payload   逻辑载荷
     * @param chunkSize IDAT 分块大小
     * @throws Exception 读写失败
     */
    private static void assertRoundTrip(final int width, final int height,
                                        final byte[] payload, final int chunkSize) throws Exception {
        byte[] png = write(width, height, payload, chunkSize);
        ByteArrayOutputStream recovered = new ByteArrayOutputStream();
        new PixelPngReader().read(new ByteArrayInputStream(png), recovered, payload.length);
        assertArrayEquals(payload, recovered.toByteArray());
    }

    /**
     * 使用确定性 padding 写出测试 PNG。
     *
     * @param width     画布宽度
     * @param height    画布高度
     * @param payload   逻辑载荷
     * @param chunkSize IDAT 分块大小
     * @return PNG 字节
     * @throws Exception 写出失败
     */
    private static byte[] write(final int width, final int height,
                                final byte[] payload, final int chunkSize) throws Exception {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        writer(chunkSize).write(output, width, height,
                new ByteArrayInputStream(payload), payload.length);
        return output.toByteArray();
    }

    /**
     * 创建确定性 padding 的测试 writer。
     *
     * @param chunkSize IDAT 分块大小
     * @return writer
     */
    private static PixelPngWriter writer(final int chunkSize) {
        ImageCryptRandomSource random = length -> {
            byte[] value = new byte[length];
            for (int i = 0; i < value.length; i++) {
                value[i] = (byte) (0xa5 ^ i);
            }
            return value;
        };
        return new PixelPngWriter(random, chunkSize);
    }

    /**
     * 生成递增的确定性测试字节。
     *
     * @param length 长度
     * @return 测试字节
     */
    private static byte[] sequence(final int length) {
        byte[] result = new byte[length];
        for (int i = 0; i < result.length; i++) {
            result[i] = (byte) (i * 31 + 7);
        }
        return result;
    }
}
