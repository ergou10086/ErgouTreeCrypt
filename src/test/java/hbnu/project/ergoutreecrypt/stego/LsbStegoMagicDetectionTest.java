package hbnu.project.ergoutreecrypt.stego;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import java.awt.image.BufferedImage;
import java.nio.file.Path;

import javax.imageio.ImageIO;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * 验证桌面端 LSB 图种元数据魔数可从像素 LSB 中提取。
 *
 * <p>移动端 {@code LsbStegoDetector} 用与 {@link #extractLsbFirstBytes} 完全一致的
 * 算法（R/G/B 三通道、每通道取 {@code lsbDepth} 个最低位、LSB 优先装入字节流）在
 * Android {@code Bitmap.getPixels} 上探测首 16 字节是否等于
 * {@link StegoMetadata#MAGIC}。本测试在桌面端用真实 {@link PngLsbStego#embed} 产物
 * 验证：该算法确实能在任意合法 LSB 深度（1–4）下还原出魔数，从而证明移动端探测逻辑
 * 的算法与魔数常量正确。
 *
 * @author ErgouTree
 * @since 2026/8/31
 */
class LsbStegoMagicDetectionTest {

    @Test
    void lsbEmbeddedMagicDetectableAtAllDepths(@TempDir Path dir) throws Exception {
        // 1. 生成 64x64 RGB PNG 载体
        BufferedImage img = new BufferedImage(64, 64, BufferedImage.TYPE_INT_RGB);
        for (int y = 0; y < 64; y++) {
            for (int x = 0; x < 64; x++) {
                img.setRGB(x, y, (x * 7 + y * 13) & 0xFFFFFF);
            }
        }
        Path png = dir.resolve("carrier.png");
        ImageIO.write(img, "PNG", png.toFile());

        // 2. 用 LSB 方案嵌入（header 首 16 字节即固定魔数）
        byte[] header = StegoMetadata.MAGIC.clone();
        byte[] payload = new byte[64];

        for (int depth = 1; depth <= 4; depth++) {
            Path stego = dir.resolve("stego_d" + depth + ".png");
            PngLsbStego.embed(png, stego, header, payload, depth);

            // 3. 读回像素，按镜像算法提取首 16 字节，应等于魔数
            BufferedImage read = ImageIO.read(stego.toFile());
            byte[] extracted = extractLsbFirstBytes(read, depth, StegoMetadata.MAGIC_LEN);
            assertArrayEquals(StegoMetadata.MAGIC, extracted,
                    "LSB 深度 " + depth + " 应能提取出元数据魔数");
        }
    }

    /**
     * 从位图顶部像素提取前 {@code numBytes} 字节的 LSB 流（与移动端
     * {@code LsbStegoDetector.extractFirstBytes} 及桌面端
     * {@code PngLsbStego.extractFromPixels} 逐位一致）。
     */
    private static byte[] extractLsbFirstBytes(BufferedImage img, int lsbDepth, int numBytes) {
        int w = img.getWidth();
        int h = img.getHeight();
        int[] pixels = img.getRGB(0, 0, w, h, null, 0, w);
        int mask = (1 << lsbDepth) - 1;
        int[] shifts = {16, 8, 0};
        byte[] result = new byte[numBytes];
        int byteIdx = 0;
        int bitIdx = 0;
        outer:
        for (int px : pixels) {
            for (int shift : shifts) {
                int channel = (px >> shift) & 0xFF;
                int bits = channel & mask;
                for (int b = 0; b < lsbDepth; b++) {
                    int bit = (bits >> b) & 1;
                    if (bit == 1) {
                        result[byteIdx] |= (byte) (1 << bitIdx);
                    }
                    bitIdx++;
                    if (bitIdx >= 8) {
                        bitIdx = 0;
                        byteIdx++;
                        if (byteIdx >= numBytes) {
                            break outer;
                        }
                    }
                }
            }
        }
        return result;
    }
}
