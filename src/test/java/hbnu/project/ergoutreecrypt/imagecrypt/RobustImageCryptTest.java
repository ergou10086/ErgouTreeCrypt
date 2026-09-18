package hbnu.project.ergoutreecrypt.imagecrypt;

import hbnu.project.ergoutreecrypt.exception.ErrorKind;
import hbnu.project.ergoutreecrypt.imagecrypt.robust.RobustCarrier;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.imageio.IIOImage;
import javax.imageio.ImageIO;
import javax.imageio.ImageWriteParam;
import javax.imageio.ImageWriter;
import javax.imageio.stream.ImageOutputStream;
import java.awt.image.BufferedImage;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Iterator;

import static hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptTestSupport.assertKind;
import static hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptTestSupport.fixture;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 抗图片重编码纠错载体的端到端测试。
 *
 * @author ErgouTree
 * @since 2026/9/17
 */
final class RobustImageCryptTest {

    /** 测试临时目录。 */
    @TempDir
    Path workDirectory;

    /**
     * 纠错 PNG 未经重编码时必须逐字节恢复原文件。
     *
     * @throws Exception 测试读写失败
     */
    @Test
    void robustPngRoundTripsExactly() throws Exception {
        Path source = workDirectory.resolve("source.jpg");
        Files.write(source, fixture("sample.jpg"));
        Path encrypted = workDirectory.resolve("robust.png");

        ImageCryptCodec codec = new ImageCryptCodec();
        codec.encrypt(source, encrypted, null,
                ImageCryptOptions.errorCorrecting(ImageCryptMode.PUBLIC_RECOVERY, false));
        Path restored = codec.decrypt(encrypted, Files.createDirectory(workDirectory.resolve("out")),
                null);

        assertArrayEquals(Files.readAllBytes(source), Files.readAllBytes(restored));
    }

    /**
     * 纠错载体经与 QQ 样本一致的 JPEG quality 90 重编码后仍须逐字节恢复。
     *
     * @throws Exception 测试读写失败
     */
    @Test
    void survivesQuality90JpegReencoding() throws Exception {
        Path source = workDirectory.resolve("qq-source.jpg");
        Files.write(source, fixture("sample.jpg"));
        Path encrypted = workDirectory.resolve("qq-robust.png");
        Path recompressed = workDirectory.resolve("qq-saved.jpg");

        ImageCryptCodec codec = new ImageCryptCodec();
        codec.encrypt(source, encrypted, null,
                ImageCryptOptions.errorCorrecting(ImageCryptMode.PUBLIC_RECOVERY, false));
        writeJpeg(ImageIO.read(encrypted.toFile()), recompressed, 0.90f);
        assertTrue(codec.isEncrypted(recompressed));

        Path restored = codec.decrypt(recompressed,
                Files.createDirectory(workDirectory.resolve("qq-out")), null);
        assertArrayEquals(Files.readAllBytes(source), Files.readAllBytes(restored));
    }

    /**
     * 超容量 PNG 应先生成有损 JPEG 恢复副本，该副本在载体重编码前后保持逐字节一致。
     *
     * @throws Exception 测试读写失败
     */
    @Test
    void oversizedPngUsesStableLossyRecoveryCopy() throws Exception {
        Path source = workDirectory.resolve("large-source.png");
        Files.write(source, fixture("sample.png"));
        Path encrypted = workDirectory.resolve("large-robust.png");
        Path recompressed = workDirectory.resolve("large-saved.jpg");

        ImageCryptCodec codec = new ImageCryptCodec();
        codec.encrypt(source, encrypted, null,
                ImageCryptOptions.errorCorrecting(ImageCryptMode.PUBLIC_RECOVERY, false));
        Path baseline = codec.decrypt(encrypted,
                Files.createDirectory(workDirectory.resolve("large-baseline")), null);
        assertTrue(baseline.getFileName().toString().endsWith(".jpg"));
        assertTrue(ImageIO.read(baseline.toFile()) != null);

        writeJpeg(ImageIO.read(encrypted.toFile()), recompressed, 0.90f);
        Path recovered = codec.decrypt(recompressed,
                Files.createDirectory(workDirectory.resolve("large-recovered")), null);
        assertArrayEquals(Files.readAllBytes(baseline), Files.readAllBytes(recovered));
    }

    /**
     * 超过 RS 能力的载荷错误应被严格模式拒绝，并可由显式尽力恢复选项导出损坏副本。
     *
     * @throws Exception 测试读写失败
     */
    @Test
    void bestEffortCanCommitUncorrectablePayload() throws Exception {
        Path source = workDirectory.resolve("damaged-source.jpg");
        Files.write(source, fixture("sample.jpg"));
        Path encrypted = workDirectory.resolve("damaged-robust.png");
        Path damaged = workDirectory.resolve("damaged.png");

        ImageCryptCodec codec = new ImageCryptCodec();
        codec.encrypt(source, encrypted, null,
                ImageCryptOptions.errorCorrecting(ImageCryptMode.PUBLIC_RECOVERY, false));
        BufferedImage image = ImageIO.read(encrypted.toFile());
        damageOneCodewordInSecondGroup(image);
        ImageIO.write(image, "png", damaged.toFile());

        Path strictDirectory = Files.createDirectory(workDirectory.resolve("strict"));
        assertKind(ErrorKind.TAMPERED_DATA,
                () -> codec.decrypt(damaged, strictDirectory, null));

        Path effortDirectory = Files.createDirectory(workDirectory.resolve("effort"));
        Path restored = codec.decrypt(damaged, effortDirectory, null, false, true,
                ImageCryptProgress.NONE);
        assertTrue(Files.exists(restored));
        assertNotEquals(-1L, Files.mismatch(source, restored));
    }

    /**
     * 破坏第二交织组中同一码字的 40 个符号，超过 32 字节纠错上限。
     *
     * @param image 待修改载体
     */
    private static void damageOneCodewordInSecondGroup(final BufferedImage image) {
        long groupStart = RobustCarrier.GROUP_PIXELS;
        for (int column = 0; column < 40; column++) {
            long codewordByte = (long) column * RobustCarrier.INTERLEAVE;
            long firstSymbol = groupStart + codewordByte * 8 / 3;
            for (int symbol = 0; symbol < 4; symbol++) {
                invertPixel(image, firstSymbol + symbol);
            }
        }
    }

    /**
     * 反转指定线性位置的灰度值。
     *
     * @param image 图片
     * @param index 线性像素位置
     */
    private static void invertPixel(final BufferedImage image, final long index) {
        int x = (int) (index % image.getWidth());
        int y = (int) (index / image.getWidth());
        int value = image.getRGB(x, y) & 0xff;
        int inverted = 255 - value;
        image.setRGB(x, y, 0xff000000 | inverted << 16 | inverted << 8 | inverted);
    }

    /**
     * 以显式质量写出 JPEG，模拟 QQ 样本的量化配置。
     *
     * @param image 图片
     * @param output 输出路径
     * @param quality JPEG 质量
     * @throws Exception 写入失败
     */
    private static void writeJpeg(final BufferedImage image, final Path output,
                                  final float quality) throws Exception {
        Iterator<ImageWriter> writers = ImageIO.getImageWritersByFormatName("jpeg");
        ImageWriter writer = writers.next();
        ImageWriteParam params = writer.getDefaultWriteParam();
        params.setCompressionMode(ImageWriteParam.MODE_EXPLICIT);
        params.setCompressionQuality(quality);
        try (ImageOutputStream stream = ImageIO.createImageOutputStream(output.toFile())) {
            writer.setOutput(stream);
            writer.write(null, new IIOImage(image, null, null), params);
        } finally {
            writer.dispose();
        }
    }
}
