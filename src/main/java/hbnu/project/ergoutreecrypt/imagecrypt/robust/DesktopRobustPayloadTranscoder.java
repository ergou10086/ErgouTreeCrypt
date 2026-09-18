package hbnu.project.ergoutreecrypt.imagecrypt.robust;

import hbnu.project.ergoutreecrypt.exception.ErrorKind;
import hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptException;

import javax.imageio.IIOImage;
import javax.imageio.ImageIO;
import javax.imageio.ImageWriteParam;
import javax.imageio.ImageWriter;
import javax.imageio.stream.ImageOutputStream;
import java.awt.Color;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.image.BufferedImage;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Iterator;

/**
 * 为超出纠错载体容量的图片生成受控大小 JPEG 恢复副本。
 *
 * <p>该步骤只在用户显式启用纠错选项且原文件过大时执行。它会丢弃动画、透明度与元数据，
 * 以清晰度和文件语义换取聊天软件重编码后的可恢复性。
 *
 * @author ErgouTree
 * @since 2026/9/17
 */
public final class DesktopRobustPayloadTranscoder {

    /** JPEG 尝试质量，从高到低。 */
    private static final float[] QUALITIES = {
            0.92f, 0.86f, 0.78f, 0.68f, 0.58f, 0.48f, 0.38f
    };

    /** 为极强档小容量恢复副本保留的最大缩放轮数。 */
    private static final int SCALE_PASSES = 8;

    /** 工具类不允许实例化。 */
    private DesktopRobustPayloadTranscoder() {
    }

    /**
     * 把输入的首帧转换为不超过目标长度的 JPEG。
     *
     * @param input 输入图片
     * @param output JPEG 临时文件
     * @param maximumBytes 最大文件字节数
     * @return 实际写出的临时文件
     * @throws ImageCryptException 图片无法解码或多轮压缩后仍超限
     * @throws IOException 文件读写失败
     */
    public static Path transcode(final Path input, final Path output, final long maximumBytes)
            throws ImageCryptException, IOException {
        BufferedImage decoded = ImageIO.read(input.toFile());
        if (decoded == null) {
            throw new ImageCryptException(ErrorKind.UNSUPPORTED_FORMAT,
                    "无法为超大图片生成纠错模式 JPEG 恢复副本");
        }
        BufferedImage image = flatten(decoded);
        try {
            for (int scalePass = 0; scalePass < SCALE_PASSES; scalePass++) {
                for (float quality : QUALITIES) {
                    writeJpeg(image, output, quality);
                    if (Files.size(output) <= maximumBytes) {
                        return output;
                    }
                }
                int nextWidth = Math.max(1, (int) Math.round(image.getWidth() * 0.82));
                int nextHeight = Math.max(1, (int) Math.round(image.getHeight() * 0.82));
                BufferedImage scaled = scale(image, nextWidth, nextHeight);
                image.flush();
                image = scaled;
            }
        } finally {
            image.flush();
        }
        throw new ImageCryptException(ErrorKind.CAPACITY_INSUFFICIENT,
                "图片在降低 JPEG 质量与尺寸后仍超过纠错载体容量");
    }

    /**
     * 把透明或其它颜色模型合成为白底三通道 RGB。
     *
     * @param source 解码图片
     * @return RGB 图片
     */
    private static BufferedImage flatten(final BufferedImage source) {
        BufferedImage rgb = new BufferedImage(source.getWidth(), source.getHeight(),
                BufferedImage.TYPE_INT_RGB);
        Graphics2D graphics = rgb.createGraphics();
        try {
            graphics.setColor(Color.WHITE);
            graphics.fillRect(0, 0, rgb.getWidth(), rgb.getHeight());
            graphics.drawImage(source, 0, 0, null);
        } finally {
            graphics.dispose();
        }
        return rgb;
    }

    /**
     * 高质量缩放图片。
     *
     * @param source 源图片
     * @param width 目标宽度
     * @param height 目标高度
     * @return 缩放后的 RGB 图片
     */
    private static BufferedImage scale(final BufferedImage source, final int width,
                                       final int height) {
        BufferedImage target = new BufferedImage(width, height, BufferedImage.TYPE_INT_RGB);
        Graphics2D graphics = target.createGraphics();
        try {
            graphics.setRenderingHint(RenderingHints.KEY_INTERPOLATION,
                    RenderingHints.VALUE_INTERPOLATION_BICUBIC);
            graphics.setRenderingHint(RenderingHints.KEY_RENDERING,
                    RenderingHints.VALUE_RENDER_QUALITY);
            graphics.drawImage(source, 0, 0, width, height, null);
        } finally {
            graphics.dispose();
        }
        return target;
    }

    /**
     * 用指定显式质量写 JPEG。
     *
     * @param image RGB 图片
     * @param output 输出路径
     * @param quality 0 至 1 的 JPEG 质量
     * @throws ImageCryptException 当前 JRE 缺少 JPEG writer
     * @throws IOException 写入失败
     */
    private static void writeJpeg(final BufferedImage image, final Path output,
                                  final float quality)
            throws ImageCryptException, IOException {
        Iterator<ImageWriter> writers = ImageIO.getImageWritersByFormatName("jpeg");
        if (!writers.hasNext()) {
            throw new ImageCryptException(ErrorKind.UNSUPPORTED_FORMAT,
                    "当前运行环境缺少 JPEG 编码器");
        }
        ImageWriter writer = writers.next();
        ImageWriteParam param = writer.getDefaultWriteParam();
        param.setCompressionMode(ImageWriteParam.MODE_EXPLICIT);
        param.setCompressionQuality(quality);
        try (ImageOutputStream stream = ImageIO.createImageOutputStream(
                Files.newOutputStream(output, StandardOpenOption.WRITE,
                        StandardOpenOption.TRUNCATE_EXISTING))) {
            writer.setOutput(stream);
            writer.write(null, new IIOImage(image, null, null), param);
        } finally {
            writer.dispose();
        }
    }
}
