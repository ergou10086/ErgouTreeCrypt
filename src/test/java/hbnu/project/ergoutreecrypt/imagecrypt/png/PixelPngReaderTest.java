package hbnu.project.ergoutreecrypt.imagecrypt.png;

import hbnu.project.ergoutreecrypt.exception.ErrorKind;
import hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptException;
import hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptFrame;
import hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptProtocol;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * {@link PixelPngReader} 的过滤、长度、块次序与帧边界测试。
 *
 * @author ErgouTree
 * @since 2026/9/16
 */
final class PixelPngReaderTest {

    /**
     * reader 必须在跨多个小 IDAT 的情况下正确反转 filter 0–4。
     *
     * @throws Exception 构造或读取 PNG 失败
     */
    @Test
    void allStandardFiltersAreReversedAcrossIdatBoundaries() throws Exception {
        int width = 2;
        int height = 5;
        int rowBytes = width * ImageCryptProtocol.PNG_BYTES_PER_PIXEL;
        byte[][] rawRows = new byte[height][rowBytes];
        ByteArrayOutputStream expected = new ByteArrayOutputStream();
        ByteArrayOutputStream inflated = new ByteArrayOutputStream();

        for (int y = 0; y < height; y++) {
            for (int x = 0; x < rowBytes; x++) {
                rawRows[y][x] = (byte) (17 + y * 29 + x * 11);
            }
            byte[] previous = y == 0 ? null : rawRows[y - 1];
            byte[] filtered = PngContainerTestSupport.filter(y, rawRows[y], previous,
                    ImageCryptProtocol.PNG_BYTES_PER_PIXEL);
            inflated.write(y);
            inflated.write(filtered);
            expected.write(rawRows[y]);
        }

        byte[] png = PngContainerTestSupport.standardPng(
                PngContainerTestSupport.rgbIhdr(width, height),
                PngContainerTestSupport.zlib(inflated.toByteArray()), 3);
        ByteArrayOutputStream actual = new ByteArrayOutputStream();
        new PixelPngReader().read(new ByteArrayInputStream(png), actual, expected.size());
        assertArrayEquals(expected.toByteArray(), actual.toByteArray());
    }

    /**
     * 帧入口必须从 184 字节头推导精确长度，不向下游输出随机 padding。
     *
     * @throws Exception 帧或 PNG 构造失败
     */
    @Test
    void frameReaderStopsAtAuthTagAndDiscardsPadding() throws Exception {
        int width = 10;
        int height = 9;
        byte[] ciphertext = sequence(10, 3);
        byte[] tag = sequence(ImageCryptProtocol.AUTH_TAG_LENGTH, 71);
        ImageCryptFrame originalFrame = publicFrame(width, height, ciphertext.length);
        byte[] frameBytes = concatenate(originalFrame.toBytes(), ciphertext, tag);

        ByteArrayOutputStream png = new ByteArrayOutputStream();
        new PixelPngWriter().write(png, width, height,
                new ByteArrayInputStream(frameBytes), frameBytes.length);

        ByteArrayOutputStream recovered = new ByteArrayOutputStream();
        ImageCryptFrame parsed = new PixelPngReader().readFrame(
                new ByteArrayInputStream(png.toByteArray()), recovered);
        assertEquals(ciphertext.length, parsed.ciphertextLength());
        assertEquals(width, parsed.canvasWidth());
        assertEquals(height, parsed.canvasHeight());
        assertArrayEquals(frameBytes, recovered.toByteArray());
    }

    /**
     * PNG IHDR 与 OuterHeader 的画布尺寸不一致时必须在输出头之前失败。
     *
     * @throws Exception 帧或 PNG 构造失败
     */
    @Test
    void frameCanvasMustMatchIhdr() throws Exception {
        byte[] frameBytes = concatenate(publicFrame(10, 9, 10).toBytes(),
                new byte[10], new byte[ImageCryptProtocol.AUTH_TAG_LENGTH]);
        ByteArrayOutputStream png = new ByteArrayOutputStream();
        new PixelPngWriter().write(png, 9, 10,
                new ByteArrayInputStream(frameBytes), frameBytes.length);

        ByteArrayOutputStream recovered = new ByteArrayOutputStream();
        ImageCryptException thrown = assertThrows(ImageCryptException.class,
                () -> new PixelPngReader().readFrame(
                        new ByteArrayInputStream(png.toByteArray()), recovered));
        assertEquals(ErrorKind.INVALID_HEADER, thrown.kind());
        assertEquals(0, recovered.size());
    }

    /**
     * IHDR、sRGB、任一 IDAT 或 IEND 的 CRC 位变化都必须被拒绝。
     *
     * @throws Exception PNG 构造失败
     */
    @Test
    void everyChunkCrcIsVerified() throws Exception {
        byte[] payload = sequence(90, 9);
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        new PixelPngWriter().write(output, 10, 4,
                new ByteArrayInputStream(payload), payload.length);
        byte[] original = output.toByteArray();

        for (int crcOffset : PngContainerTestSupport.chunkCrcLastOffsets(original)) {
            byte[] corrupted = original.clone();
            corrupted[crcOffset] ^= 1;
            ImageCryptException thrown = assertThrows(ImageCryptException.class,
                    () -> new PixelPngReader().read(new ByteArrayInputStream(corrupted),
                            new ByteArrayOutputStream(), payload.length));
            assertEquals(ErrorKind.INVALID_HEADER, thrown.kind());
        }
    }

    /**
     * zlib 提前结束、额外压缩字节和额外解压输出都必须明确失败。
     *
     * @throws Exception PNG 构造失败
     */
    @Test
    void zlibMustEndExactlyAtDeclaredScanlineCapacity() throws Exception {
        byte[] correct = PngContainerTestSupport.zlib(new byte[]{0, 1, 2, 3});
        assertInvalid(PngContainerTestSupport.standardPng(
                PngContainerTestSupport.rgbIhdr(1, 1),
                Arrays.copyOf(correct, correct.length - 1), 64), 3);

        byte[] trailingCompressed = Arrays.copyOf(correct, correct.length + 1);
        trailingCompressed[trailingCompressed.length - 1] = 7;
        assertInvalid(PngContainerTestSupport.standardPng(
                PngContainerTestSupport.rgbIhdr(1, 1), trailingCompressed, 64), 3);

        byte[] extraOutput = PngContainerTestSupport.zlib(new byte[]{0, 1, 2, 3, 4});
        assertInvalid(PngContainerTestSupport.standardPng(
                PngContainerTestSupport.rgbIhdr(1, 1), extraOutput, 64), 3);

        byte[] shortOutput = PngContainerTestSupport.zlib(new byte[]{0, 1, 2});
        assertInvalid(PngContainerTestSupport.standardPng(
                PngContainerTestSupport.rgbIhdr(1, 1), shortOutput, 64), 3);
    }

    /**
     * IDAT 之间出现其它块后再次出现 IDAT 必须作为非连续序列拒绝。
     *
     * @throws Exception PNG 构造失败
     */
    @Test
    void idatChunksMustBeContiguous() throws Exception {
        byte[] compressed = PngContainerTestSupport.zlib(new byte[]{0, 1, 2, 3});
        byte[] png = PngContainerTestSupport.png(
                new PngContainerTestSupport.ChunkSpec("IHDR", PngContainerTestSupport.rgbIhdr(1, 1)),
                new PngContainerTestSupport.ChunkSpec("IDAT", compressed),
                new PngContainerTestSupport.ChunkSpec("tEXt", new byte[]{'x'}),
                new PngContainerTestSupport.ChunkSpec("IDAT", new byte[0]),
                new PngContainerTestSupport.ChunkSpec("IEND", new byte[0]));
        assertInvalid(png, 3);
    }

    /**
     * 合法 ancillary chunk 可位于 IDAT 前后，未知关键块必须拒绝。
     *
     * @throws Exception PNG 构造失败
     */
    @Test
    void ancillaryChunksAreIgnoredButUnknownCriticalChunksAreRejected() throws Exception {
        byte[] compressed = PngContainerTestSupport.zlib(new byte[]{0, 1, 2, 3});
        byte[] accepted = PngContainerTestSupport.png(
                new PngContainerTestSupport.ChunkSpec("IHDR", PngContainerTestSupport.rgbIhdr(1, 1)),
                new PngContainerTestSupport.ChunkSpec("tEXt", new byte[]{'a'}),
                new PngContainerTestSupport.ChunkSpec("IDAT", compressed),
                new PngContainerTestSupport.ChunkSpec("tIME", new byte[7]),
                new PngContainerTestSupport.ChunkSpec("IEND", new byte[0]));
        ByteArrayOutputStream recovered = new ByteArrayOutputStream();
        new PixelPngReader().read(new ByteArrayInputStream(accepted), recovered, 3);
        assertArrayEquals(new byte[]{1, 2, 3}, recovered.toByteArray());

        byte[] rejected = PngContainerTestSupport.png(
                new PngContainerTestSupport.ChunkSpec("IHDR", PngContainerTestSupport.rgbIhdr(1, 1)),
                new PngContainerTestSupport.ChunkSpec("PLTE", new byte[]{0, 0, 0}),
                new PngContainerTestSupport.ChunkSpec("IDAT", compressed),
                new PngContainerTestSupport.ChunkSpec("IEND", new byte[0]));
        assertInvalid(rejected, 3);
    }

    /**
     * 超大维度和非 RGB8/非交错 IHDR 必须在行缓冲分配前拒绝。
     *
     * @throws Exception PNG 构造失败
     */
    @Test
    void unsafeOrUnsupportedIhdrIsRejectedBeforeInflation() throws Exception {
        assertInvalid(PngContainerTestSupport.png(
                new PngContainerTestSupport.ChunkSpec("IHDR",
                        PngContainerTestSupport.rgbIhdr(8193, 1))), 0);
        assertInvalid(PngContainerTestSupport.png(
                new PngContainerTestSupport.ChunkSpec("IHDR",
                        PngContainerTestSupport.ihdr(1, 1, 16, 2, 0))), 0);
        assertInvalid(PngContainerTestSupport.png(
                new PngContainerTestSupport.ChunkSpec("IHDR",
                        PngContainerTestSupport.ihdr(1, 1, 8, 2, 1))), 0);
    }

    /**
     * 缺少 IEND 或 IEND 后仍有字节都必须失败。
     *
     * @throws Exception PNG 构造失败
     */
    @Test
    void iendMustExistAndBePhysicalEndOfFile() throws Exception {
        byte[] compressed = PngContainerTestSupport.zlib(new byte[]{0, 1, 2, 3});
        byte[] missing = PngContainerTestSupport.png(
                new PngContainerTestSupport.ChunkSpec("IHDR", PngContainerTestSupport.rgbIhdr(1, 1)),
                new PngContainerTestSupport.ChunkSpec("IDAT", compressed));
        assertInvalid(missing, 3);

        byte[] valid = PngContainerTestSupport.standardPng(
                PngContainerTestSupport.rgbIhdr(1, 1), compressed, 64);
        byte[] trailing = Arrays.copyOf(valid, valid.length + 1);
        trailing[trailing.length - 1] = 1;
        assertInvalid(trailing, 3);
    }

    /**
     * 构造合法公开恢复模式帧。
     *
     * @param width       画布宽度
     * @param height      画布高度
     * @param innerLength 密文长度
     * @return 带 keyConfirm 的帧
     * @throws ImageCryptException 参数非法
     */
    private static ImageCryptFrame publicFrame(final int width, final int height,
                                               final long innerLength)
            throws ImageCryptException {
        return ImageCryptFrame.newPublicFrame(width, height, innerLength, 0, 0,
                        sequence(ImageCryptProtocol.HKDF_SALT_LENGTH, 1),
                        sequence(ImageCryptProtocol.NONCE_LENGTH, 33),
                        sequence(ImageCryptProtocol.MASTER_KEY_LENGTH, 65))
                .withKeyConfirm(sequence(ImageCryptProtocol.KEY_CONFIRM_LENGTH, 97));
    }

    /**
     * 断言 PNG 以 INVALID_HEADER 失败。
     *
     * @param png           PNG 字节
     * @param logicalLength 期望抽取长度
     */
    private static void assertInvalid(final byte[] png, final long logicalLength) {
        ImageCryptException thrown = assertThrows(ImageCryptException.class,
                () -> new PixelPngReader().read(new ByteArrayInputStream(png),
                        new ByteArrayOutputStream(), logicalLength));
        assertEquals(ErrorKind.INVALID_HEADER, thrown.kind());
    }

    /**
     * 拼接多个字节数组。
     *
     * @param parts 字节数组
     * @return 拼接结果
     */
    private static byte[] concatenate(final byte[]... parts) {
        int length = 0;
        for (byte[] part : parts) {
            length += part.length;
        }
        byte[] result = new byte[length];
        int offset = 0;
        for (byte[] part : parts) {
            System.arraycopy(part, 0, result, offset, part.length);
            offset += part.length;
        }
        return result;
    }

    /**
     * 生成非全零的确定性字节。
     *
     * @param length 长度
     * @param seed   起始值
     * @return 测试字节
     */
    private static byte[] sequence(final int length, final int seed) {
        byte[] result = new byte[length];
        for (int i = 0; i < result.length; i++) {
            result[i] = (byte) (seed + i * 13);
        }
        return result;
    }
}
