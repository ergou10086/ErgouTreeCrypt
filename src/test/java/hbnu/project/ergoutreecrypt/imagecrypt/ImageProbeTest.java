package hbnu.project.ergoutreecrypt.imagecrypt;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptTestSupport.fixture;
import static hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptTestSupport.minimalBmp;
import static hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptTestSupport.minimalGif;
import static hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptTestSupport.minimalJpeg;
import static hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptTestSupport.minimalPng;
import static hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptTestSupport.webpVp8;
import static hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptTestSupport.webpVp8l;
import static hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptTestSupport.webpVp8x;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link ImageProbe} 的格式识别与尺寸提示测试。
 *
 * <p>覆盖五种首期格式的魔数识别、尺寸解析、扩展名冲突提示与有界读取行为，并额外用两份
 * 真实素材（1280×720 RGBA PNG、1920×1080 VP8X WebP）验证真实容器结构下的解析结果。
 *
 * @author ErgouTree
 * @since 2026/9/15
 */
final class ImageProbeTest {

    // ================================================================
    // 合成样本：魔数与尺寸
    // ================================================================

    @Test
    void recognizesPngAndReadsIhdrDimensions() {
        ImageProbe.Result result = ImageProbe.probeBytes(minimalPng(640, 480), "a.png");
        assertEquals(ImageFormat.PNG, result.format());
        assertEquals(640, result.width());
        assertEquals(480, result.height());
        assertTrue(result.hasSizeHint());
        assertFalse(result.extensionConflict());
    }

    @Test
    void recognizesJpegAndReadsSofDimensions() {
        ImageProbe.Result result = ImageProbe.probeBytes(minimalJpeg(800, 600), "a.jpg");
        assertEquals(ImageFormat.JPEG, result.format());
        assertEquals(800, result.width());
        assertEquals(600, result.height());

        assertEquals(ImageFormat.JPEG, ImageProbe.probeBytes(minimalJpeg(800, 600), "a.jpeg").format());
    }

    @Test
    void recognizesGifAndReadsLogicalScreenDescriptor() {
        ImageProbe.Result result = ImageProbe.probeBytes(minimalGif(320, 240), "a.gif");
        assertEquals(ImageFormat.GIF, result.format());
        assertEquals(320, result.width());
        assertEquals(240, result.height());
    }

    @Test
    void recognizesBmpAndHandlesTopDownHeight() {
        ImageProbe.Result result = ImageProbe.probeBytes(minimalBmp(1920, 1080, 40), "a.bmp");
        assertEquals(ImageFormat.BMP, result.format());
        assertEquals(1920, result.width());
        assertEquals(1080, result.height());

        ImageProbe.Result topDown = ImageProbe.probeBytes(minimalBmp(1920, -1080, 40), "a.bmp");
        assertEquals(1080, topDown.height());
    }

    @Test
    void recognizesWebpAcrossAllThreeChunkLayouts() {
        ImageProbe.Result extended = ImageProbe.probeBytes(webpVp8x(1920, 1080), "a.webp");
        assertEquals(ImageFormat.WEBP, extended.format());
        assertEquals(1920, extended.width());
        assertEquals(1080, extended.height());

        ImageProbe.Result lossless = ImageProbe.probeBytes(webpVp8l(513, 257), "a.webp");
        assertEquals(ImageFormat.WEBP, lossless.format());
        assertEquals(513, lossless.width());
        assertEquals(257, lossless.height());

        ImageProbe.Result lossy = ImageProbe.probeBytes(webpVp8(640, 360), "a.webp");
        assertEquals(ImageFormat.WEBP, lossy.format());
        assertEquals(640, lossy.width());
        assertEquals(360, lossy.height());
    }

    // ================================================================
    // 拒绝与提示
    // ================================================================

    @Test
    void unrecognizedInputYieldsNoFormat() {
        assertNull(ImageProbe.probeBytes("hello world, not an image".getBytes(StandardCharsets.UTF_8),
                "note.txt").format());
        assertNull(ImageProbe.probeBytes(new byte[0], "empty.bin").format());
        assertNull(ImageProbe.probeBytes(null, "empty.bin").format());
        assertNull(ImageProbe.probeBytes(new byte[4], "tiny.bin").format());
    }

    @Test
    void bmpMagicAloneIsNotEnough() {
        byte[] fake = new byte[32];
        fake[0] = 'B';
        fake[1] = 'M';
        assertNull(ImageProbe.probeBytes(fake, "fake.bmp").format());
    }

    @Test
    void truncatedContainersStillIdentifyTheFormatWithZeroSize() {
        byte[] truncatedPng = new byte[12];
        System.arraycopy(minimalPng(10, 10), 0, truncatedPng, 0, 12);
        ImageProbe.Result result = ImageProbe.probeBytes(truncatedPng, "cut.png");
        assertEquals(ImageFormat.PNG, result.format());
        assertEquals(0, result.width());
        assertFalse(result.hasSizeHint());
    }

    @Test
    void extensionConflictIsReportedWithoutBlocking() {
        byte[] jpeg = minimalJpeg(100, 100);
        ImageProbe.Result conflicted = ImageProbe.probeBytes(jpeg, "photo.png");
        assertEquals(ImageFormat.JPEG, conflicted.format());
        assertTrue(conflicted.extensionConflict());

        ImageProbe.Result matching = ImageProbe.probeBytes(jpeg, "photo.JPG");
        assertFalse(matching.extensionConflict());

        ImageProbe.Result unknownExtension = ImageProbe.probeBytes(jpeg, "photo.bin");
        assertFalse(unknownExtension.extensionConflict(), "非图片扩展名不应报冲突");

        ImageProbe.Result noExtension = ImageProbe.probeBytes(jpeg, "photo");
        assertFalse(noExtension.extensionConflict());
        assertEquals("", noExtension.extension());
    }

    @Test
    void absurdDimensionsAreTreatedAsUnknown() {
        ImageProbe.Result result = ImageProbe.probeBytes(
                minimalPng(ImageProbe.LIMIT_HINT_SIDE + 1, 100), "a.png");
        assertEquals(ImageFormat.PNG, result.format());
        assertEquals(0, result.width());
        assertFalse(result.hasSizeHint());
    }

    // ================================================================
    // 真实素材与有界读取
    // ================================================================

    @Test
    void realFixturesProbeAsExpected() throws IOException {
        ImageProbe.Result png = ImageProbe.probeBytes(fixture("sample.png"), "sample.png");
        assertEquals(ImageFormat.PNG, png.format());
        assertEquals(1280, png.width());
        assertEquals(720, png.height());

        ImageProbe.Result jpg = ImageProbe.probeBytes(fixture("sample.jpg"), "sample.jpg");
        assertEquals(ImageFormat.JPEG, jpg.format());
        assertTrue(jpg.hasSizeHint());

        ImageProbe.Result webp = ImageProbe.probeBytes(fixture("sample.webp"), "sample.webp");
        assertEquals(ImageFormat.WEBP, webp.format());
        assertEquals(1920, webp.width());
        assertEquals(1080, webp.height());
    }

    @Test
    void fileProbeOnlyReadsABoundedPrefix(@TempDir final Path dir) throws IOException {
        Path input = dir.resolve("sample.png");
        Files.write(input, fixture("sample.png"));
        long originalSize = Files.size(input);

        ImageProbe.Result result = ImageProbe.probe(input);
        assertEquals(ImageFormat.PNG, result.format());
        assertEquals(originalSize, Files.size(input), "探测不得改写输入文件");
        assertTrue(originalSize > ImageProbe.PROBE_PREFIX_BYTES,
                "夹具应大于探测前缀，才能证明读取确实被截断");
    }

    @Test
    void probeFailsFastOnMissingFile(@TempDir final Path dir) {
        Path missing = dir.resolve("nope.png");
        assertThrows(IOException.class, () -> ImageProbe.probe(missing));
    }
}
