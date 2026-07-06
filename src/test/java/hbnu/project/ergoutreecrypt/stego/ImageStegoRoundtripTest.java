package hbnu.project.ergoutreecrypt.stego;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Security;

/**
 * 图像隐写端到端往返测试（含 Argon2id + XChaCha20 加密）。
 *
 * @author ErgouTree
 */
class ImageStegoRoundtripTest {

    private static final byte[] PASSWORD = "ErgouTree-Stego-2026".getBytes(StandardCharsets.UTF_8);
    private final ImageStegoCodec codec = new ImageStegoCodec();

    @BeforeAll
    static void setup() {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }
    }

    /**
     * 创建 RGB 测试图像。
     */
    private static BufferedImage createRgbImage(final int w, final int h) {
        BufferedImage img = new BufferedImage(w, h, BufferedImage.TYPE_INT_RGB);
        for (int y = 0; y < h; y++) {
            for (int x = 0; x < w; x++) {
                int r = (x * 7 + y * 3) & 0xFF;
                int g = (x * 11 + y * 5) & 0xFF;
                int b = (x * 13 + y * 7) & 0xFF;
                img.setRGB(x, y, (r << 16) | (g << 8) | b);
            }
        }
        return img;
    }

    private static Path writePng(final Path dir, final String name,
                                  final BufferedImage img) throws Exception {
        Path p = dir.resolve(name);
        ImageIO.write(img, "PNG", p.toFile());
        return p;
    }

    private static byte[] randomBytes(final int len) {
        byte[] b = new byte[len];
        for (int i = 0; i < len; i++) b[i] = (byte) ((i * 37 + 11) & 0xFF);
        return b;
    }

    @Test
    void textFileRoundtrip(@TempDir Path dir) throws Exception {
        BufferedImage img = createRgbImage(200, 200);
        Path imagePath = writePng(dir, "image.png", img);

        byte[] secretContent = "Hello, Image Steganography! 中文内容测试。".getBytes(StandardCharsets.UTF_8);
        Path secretPath = dir.resolve("secret.txt");
        Files.write(secretPath, secretContent);

        Path stegoPath = dir.resolve("stego.png");
        Path outDir = Files.createDirectory(dir.resolve("extracted"));

        StegoOptions opts = StegoOptions.builder().lsbDepth(1).storeMac(true).build();
        codec.hide(imagePath, secretPath, stegoPath, PASSWORD, opts);

        // 验证隐写图片存在且视觉上仍是合法 PNG
        assertTrue(Files.exists(stegoPath));
        BufferedImage stegoImg = ImageIO.read(stegoPath.toFile());
        assertTrue(stegoImg.getWidth() == 200 && stegoImg.getHeight() == 200);

        // 提取
        Path extracted = codec.extract(stegoPath, outDir, PASSWORD);
        byte[] extractedContent = Files.readAllBytes(extracted);
        assertArrayEquals(secretContent, extractedContent, "文本文件应逐字节还原");
    }

    @Test
    void binaryFileRoundtrip(@TempDir Path dir) throws Exception {
        BufferedImage img = createRgbImage(300, 300);
        Path imagePath = writePng(dir, "image.png", img);

        byte[] binaryData = randomBytes(4096);
        Path secretPath = dir.resolve("data.bin");
        Files.write(secretPath, binaryData);

        Path stegoPath = dir.resolve("stego.png");
        Path outDir = Files.createDirectory(dir.resolve("extracted"));

        StegoOptions opts = StegoOptions.builder().lsbDepth(1).storeMac(true).build();
        codec.hide(imagePath, secretPath, stegoPath, PASSWORD, opts);
        Path extracted = codec.extract(stegoPath, outDir, PASSWORD);

        assertArrayEquals(binaryData, Files.readAllBytes(extracted), "二进制文件应逐字节还原");
    }

    @Test
    void wrongPasswordDetectedWithMac(@TempDir Path dir) throws Exception {
        BufferedImage img = createRgbImage(200, 200);
        Path imagePath = writePng(dir, "image.png", img);

        byte[] secret = "secret data".getBytes(StandardCharsets.UTF_8);
        Path secretPath = dir.resolve("s.txt");
        Files.write(secretPath, secret);

        Path stegoPath = dir.resolve("stego.png");
        Path outDir = Files.createDirectory(dir.resolve("extracted"));

        StegoOptions opts = StegoOptions.builder().lsbDepth(1).storeMac(true).build();
        codec.hide(imagePath, secretPath, stegoPath, PASSWORD, opts);

        byte[] wrongPwd = "wrong-password".getBytes(StandardCharsets.UTF_8);
        assertThrows(ImageStegoException.class,
                () -> codec.extract(stegoPath, outDir, wrongPwd),
                "错误密码应触发 MAC 校验失败");
    }

    @Test
    void noPasswordRoundtrip(@TempDir Path dir) throws Exception {
        BufferedImage img = createRgbImage(300, 300);
        Path imagePath = writePng(dir, "image.png", img);

        byte[] secret = "no-password test".getBytes(StandardCharsets.UTF_8);
        Path secretPath = dir.resolve("s.txt");
        Files.write(secretPath, secret);

        Path stegoPath = dir.resolve("stego.png");
        Path outDir = Files.createDirectory(dir.resolve("extracted"));

        StegoOptions opts = StegoOptions.builder().lsbDepth(1).storeMac(false).build();
        codec.hide(imagePath, secretPath, stegoPath, new byte[0], opts);

        // 无密码提取也应成功
        Path extracted = codec.extract(stegoPath, outDir, new byte[0]);
        assertArrayEquals(secret, Files.readAllBytes(extracted));
    }

    @Test
    void differentLsbDepths(@TempDir Path dir) throws Exception {
        for (int depth = 1; depth <= 4; depth++) {
            BufferedImage img = createRgbImage(200, 200);
            Path imagePath = writePng(dir, "img_" + depth + ".png", img);

            byte[] secret = ("LSB depth=" + depth + " test").getBytes(StandardCharsets.UTF_8);
            Path secretPath = dir.resolve("s_" + depth + ".txt");
            Files.write(secretPath, secret);

            Path stegoPath = dir.resolve("stego_" + depth + ".png");
            Path outDir = Files.createDirectory(dir.resolve("out_" + depth));

            StegoOptions opts = StegoOptions.builder().lsbDepth(depth).storeMac(false).build();
            codec.hide(imagePath, secretPath, stegoPath, PASSWORD, opts);
            Path extracted = codec.extract(stegoPath, outDir, PASSWORD);

            assertArrayEquals(secret, Files.readAllBytes(extracted),
                    "LSB 深度 " + depth + " 应正确往返");
        }
    }

    @Test
    void capacityExceededError(@TempDir Path dir) throws Exception {
        BufferedImage img = createRgbImage(50, 50); // 小图
        Path imagePath = writePng(dir, "small.png", img);

        byte[] largeFile = randomBytes(50000);
        Path secretPath = dir.resolve("large.bin");
        Files.write(secretPath, largeFile);

        Path stegoPath = dir.resolve("stego.png");
        StegoOptions opts = StegoOptions.defaults();

        assertThrows(ImageStegoException.class,
                () -> codec.hide(imagePath, secretPath, stegoPath, PASSWORD, opts),
                "超出容量应报告错误");
    }

    @Test
    void visualSimilarityAfterEmbed(@TempDir Path dir) throws Exception {
        // 验证嵌入后图像视觉上几乎不变（检查大多数像素值差异 < 16）
        BufferedImage img = createRgbImage(200, 200);
        Path imagePath = writePng(dir, "image.png", img);

        byte[] secret = randomBytes(4096);
        Path secretPath = dir.resolve("data.bin");
        Files.write(secretPath, secret);

        Path stegoPath = dir.resolve("stego.png");
        StegoOptions opts = StegoOptions.builder().lsbDepth(1).storeMac(false).build();
        codec.hide(imagePath, secretPath, stegoPath, PASSWORD, opts);

        BufferedImage stegoImg = ImageIO.read(stegoPath.toFile());
        int maxDiff = 0;
        for (int y = 0; y < 200; y++) {
            for (int x = 0; x < 200; x++) {
                int origRgb = img.getRGB(x, y);
                int stegoRgb = stegoImg.getRGB(x, y);
                int rDiff = Math.abs(((origRgb >> 16) & 0xFF) - ((stegoRgb >> 16) & 0xFF));
                int gDiff = Math.abs(((origRgb >> 8) & 0xFF) - ((stegoRgb >> 8) & 0xFF));
                int bDiff = Math.abs((origRgb & 0xFF) - (stegoRgb & 0xFF));
                maxDiff = Math.max(maxDiff, Math.max(rDiff, Math.max(gDiff, bDiff)));
            }
        }
        // LSB 深度 1 时每个通道差异最多 1
        assertTrue(maxDiff <= 1, "1 LSB 嵌入后每通道差异应 ≤ 1，实际最大差异: " + maxDiff);
    }
}
