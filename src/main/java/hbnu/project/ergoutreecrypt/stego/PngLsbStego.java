package hbnu.project.ergoutreecrypt.stego;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.IOException;
import java.nio.file.Path;

/**
 * PNG LSB（最低有效位）隐写引擎（容量限制型）。
 *
 * <p>在 PNG 图像的像素 R、G、B 通道最低有效位中嵌入/提取数据。
 * Alpha 通道不参与嵌入，避免透明区域出现可见伪影。
 *
 * <p>支持 1–4 LSB 深度：深度越大容量越大，但视觉影响也越大。
 * 容量 = 图像宽度 × 高度 × 通道数 × LSB 深度 / 8 − 头大小，受限于图像像素数。
 * 未来无限制型隐写方案将使用不同的嵌入策略，不依赖像素容量。
 *
 * @author ErgouTree
 */
public final class PngLsbStego {

    private PngLsbStego() {
    }

    /**
     * 将数据嵌入 PNG 图像。
     *
     * @param source   原始 PNG 文件路径
     * @param output   输出隐写 PNG 文件路径
     * @param header   元数据头字节数组
     * @param payload  加密后的文件内容字节数组
     * @param lsbDepth LSB 深度（1–4）
     * @throws IOException         图像读写失败
     * @throws ImageStegoException 容量不足或格式不支持
     */
    public static void embed(final Path source, final Path output,
                             final byte[] header, final byte[] payload,
                             final int lsbDepth) throws IOException, ImageStegoException {
        BufferedImage image = readImage(source);
        // 确保图像可写（灰度→RGB 转换在这里完成）
        BufferedImage workImage = ensureWritable(image);
        int channels = getRgbChannels(workImage);
        // 验证容量
        long available = StegoCapacity.availableBytes(
                workImage.getWidth(), workImage.getHeight(), channels, lsbDepth, header.length);
        if (available < payload.length) {
            throw new ImageStegoException(String.format(
                    "图像容量不足：需要 %d 字节，可用 %d 字节。请使用更大的图像或更高的 LSB 深度。",
                    payload.length, available));
        }
        // 合并数据
        byte[] allData = new byte[header.length + payload.length];
        System.arraycopy(header, 0, allData, 0, header.length);
        System.arraycopy(payload, 0, allData, header.length, payload.length);
        // 嵌入
        embedIntoPixels(workImage, channels, lsbDepth, allData);
        // 写出 PNG
        boolean ok = ImageIO.write(workImage, "PNG", output.toFile());
        if (!ok) {
            throw new IOException("写入 PNG 失败（无合适的编码器）: " + output.getFileName());
        }
    }

    /**
     * 从 PNG 图像中提取数据。
     *
     * @param source             隐写 PNG 文件路径
     * @param expectedHeaderSize 预期的元数据头字节数
     * @param lsbDepth           LSB 深度（1–4）
     * @param password           密码（隐蔽模式需要；普通模式可为 null）
     * @return 提取结果：{@link ExtractResult}
     * @throws IOException         图像读取失败
     * @throws ImageStegoException 未检测到隐写数据或密码错误
     */
    public static ExtractResult extract(final Path source, final int expectedHeaderSize,
                                        final int lsbDepth, final byte[] password)
            throws IOException, ImageStegoException {
        BufferedImage image = readImage(source);
        int channels = getRgbChannels(image);
        long totalBits = (long) image.getWidth() * image.getHeight() * channels * lsbDepth;
        long requiredBits = (long) expectedHeaderSize * 8;
        if (totalBits < requiredBits) {
            throw new ImageStegoException("图像容量不足以包含隐写数据");
        }
        byte[] extracted = extractFromPixels(image, channels, lsbDepth);
        if (extracted.length < expectedHeaderSize) {
            throw new ImageStegoException("提取数据短于预期头长度");
        }
        byte[] headerBytes = new byte[expectedHeaderSize];
        System.arraycopy(extracted, 0, headerBytes, 0, expectedHeaderSize);
        // 传入密码以支持隐蔽模式
        StegoMetadata meta = StegoMetadata.fromBytes(headerBytes, password);
        long dataLen = meta.payloadSize();
        if (dataLen < 0 || dataLen > extracted.length - expectedHeaderSize) {
            throw new ImageStegoException("文件大小异常或数据不完整: " + dataLen);
        }
        byte[] encryptedPayload = new byte[(int) dataLen];
        System.arraycopy(extracted, expectedHeaderSize, encryptedPayload, 0, (int) dataLen);
        return new ExtractResult(meta, encryptedPayload);
    }

    /**
     * 向后兼容：不带密码的提取（仅支持普通模式）。
     */
    public static ExtractResult extract(final Path source, final int expectedHeaderSize,
                                        final int lsbDepth) throws IOException, ImageStegoException {
        return extract(source, expectedHeaderSize, lsbDepth, null);
    }

    /**
     * 读取图像并验证格式支持。
     */
    private static BufferedImage readImage(final Path path) throws IOException, ImageStegoException {
        BufferedImage image = ImageIO.read(path.toFile());
        if (image == null) {
            throw new ImageStegoException("无法读取图像文件（格式不受支持或文件损坏）: "
                    + path.getFileName());
        }
        int type = image.getType();
        if (type == BufferedImage.TYPE_BYTE_INDEXED || type == BufferedImage.TYPE_BYTE_BINARY) {
            throw new ImageStegoException(
                    "调色板/索引色 PNG 不支持隐写。请使用真彩色（RGB/RGBA）PNG 图像。");
        }
        return image;
    }

    // ---- 内部实现 ----

    /**
     * 获取有效的 RGB 通道数（Alpha 不参与嵌入）。
     */
    private static int getRgbChannels(final BufferedImage image) {
        int type = image.getType();
        if (type == BufferedImage.TYPE_BYTE_GRAY || type == BufferedImage.TYPE_USHORT_GRAY) {
            return 1;
        }
        return 3;
    }

    /**
     * 确保图像可以被逐像素写入。灰度图像转为 RGB（避免 setRGB→getRGB 的色域转换丢失 LSB）。
     */
    private static BufferedImage ensureWritable(final BufferedImage original) {
        int type = original.getType();
        if (type == BufferedImage.TYPE_CUSTOM
                || type == BufferedImage.TYPE_BYTE_GRAY
                || type == BufferedImage.TYPE_USHORT_GRAY) {
            BufferedImage copy = new BufferedImage(
                    original.getWidth(), original.getHeight(), BufferedImage.TYPE_INT_ARGB);
            copy.getGraphics().drawImage(original, 0, 0, null);
            copy.getGraphics().dispose();
            return copy;
        }
        return original;
    }

    /**
     * 将数据字节数组按位嵌入图像像素的 LSB 中。
     *
     * <p>按行序、每像素 R→G→B 顺序处理每个通道。每个通道嵌入 lsbDepth 个比特。
     */
    private static void embedIntoPixels(final BufferedImage image, final int channels,
                                        final int lsbDepth, final byte[] data) {
        int w = image.getWidth();
        int h = image.getHeight();
        int[] pixels = new int[w * h];
        image.getRGB(0, 0, w, h, pixels, 0, w);

        int mask = (1 << lsbDepth) - 1;
        int[] chShifts = {16, 8, 0}; // R, G, B 的位移
        int dataByteIdx = 0;
        int dataBitIdx = 0; // 在 data[dataByteIdx] 中的当前 bit 位（0 = LSB）

        for (int pxIdx = 0; pxIdx < pixels.length; pxIdx++) {
            int px = pixels[pxIdx];
            for (int ch = 0; ch < channels; ch++) {
                if (dataByteIdx >= data.length) {
                    // 数据已全部嵌入，剩余像素原样保留
                    pixels[pxIdx] = px;
                    // 快速退出：把剩余像素原样写回并返回
                    for (int j = pxIdx; j < pixels.length; j++) {
                        // 原样保留（不做修改）
                    }
                    image.setRGB(0, 0, w, h, pixels, 0, w);
                    return;
                }
                // 从数据中读取 lsbDepth 个比特
                int bits = 0;
                for (int b = 0; b < lsbDepth; b++) {
                    int dataBit = (data[dataByteIdx] >> dataBitIdx) & 1;
                    bits |= (dataBit << b);
                    dataBitIdx++;
                    if (dataBitIdx >= 8) {
                        dataBitIdx = 0;
                        dataByteIdx++;
                        if (dataByteIdx >= data.length) {
                            // 填充剩余的 b 位为 0
                            break;
                        }
                    }
                }
                // 写入通道 LSB
                int shift = chShifts[ch];
                int chVal = (px >> shift) & 0xFF;
                chVal = (chVal & ~mask) | (bits & mask);
                px = (px & ~(0xFF << shift)) | (chVal << shift);
            }
            pixels[pxIdx] = px;
        }
        image.setRGB(0, 0, w, h, pixels, 0, w);
    }

    /**
     * 从图像像素的 LSB 中提取所有数据比特，返回字节数组。
     *
     * @return 提取出的所有数据字节
     */
    private static byte[] extractFromPixels(final BufferedImage image,
                                            final int channels, final int lsbDepth) {
        int w = image.getWidth();
        int h = image.getHeight();
        int[] pixels = new int[w * h];
        image.getRGB(0, 0, w, h, pixels, 0, w);

        int mask = (1 << lsbDepth) - 1;
        int[] chShifts = {16, 8, 0};
        // 最大可能字节数
        int maxBits = pixels.length * channels * lsbDepth;
        byte[] result = new byte[(maxBits + 7) / 8];
        int byteIdx = 0;
        int bitIdx = 0;

        for (int px : pixels) {
            for (int ch = 0; ch < channels; ch++) {
                int shift = chShifts[ch];
                int chVal = (px >> shift) & 0xFF;
                int bits = chVal & mask;
                // 将 lsbDepth 个比特写入结果
                for (int b = 0; b < lsbDepth; b++) {
                    int bit = (bits >> b) & 1;
                    if (bit == 1) {
                        result[byteIdx] |= (byte) (1 << bitIdx);
                    }
                    bitIdx++;
                    if (bitIdx >= 8) {
                        bitIdx = 0;
                        byteIdx++;
                        if (byteIdx >= result.length) {
                            return result;
                        }
                    }
                }
            }
        }
        return result;
    }

    /**
     * 提取结果：包含元数据与加密后的文件内容。
     */
    public record ExtractResult(StegoMetadata metadata, byte[] encryptedPayload) {
    }
}
