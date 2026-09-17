package hbnu.project.ergoutreecrypt.ui.support;

import javafx.scene.image.Image;
import javafx.scene.image.PixelWriter;
import javafx.scene.image.WritableImage;

import javax.imageio.ImageIO;
import javax.imageio.ImageReadParam;
import javax.imageio.ImageReader;
import javax.imageio.stream.ImageInputStream;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.image.BufferedImage;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Iterator;

/**
 * 桌面图片预览的有界解码器。
 *
 * <p>通过 ImageIO reader 的源采样先降低大图尺寸，再把首帧缩放到目标边界。WebP 由
 * TwelveMonkeys ImageIO 插件提供 reader；PNG、JPEG、GIF 与 BMP 使用同一条路径。
 * 解码结果只用于界面缩略图，不参与 EGTC-IMG 协议处理。
 */
public final class BoundedImagePreviewLoader {

    /** 禁止实例化工具类。 */
    private BoundedImagePreviewLoader() {
    }

    /**
     * 解码图片首帧并约束到指定边界。
     *
     * @param path 图片路径
     * @param maxWidth 最大输出宽度
     * @param maxHeight 最大输出高度
     * @return 有界首帧；没有可用 reader 时返回 {@code null}
     * @throws IOException 图片读取失败
     */
    public static BufferedImage readThumbnail(final Path path, final int maxWidth,
                                               final int maxHeight) throws IOException {
        if (path == null || !Files.isRegularFile(path) || maxWidth <= 0 || maxHeight <= 0) {
            return null;
        }
        try (ImageInputStream input = ImageIO.createImageInputStream(path.toFile())) {
            if (input == null) {
                return null;
            }
            Iterator<ImageReader> readers = ImageIO.getImageReaders(input);
            if (!readers.hasNext()) {
                return null;
            }
            ImageReader reader = readers.next();
            try {
                reader.setInput(input, true, true);
                int width = reader.getWidth(0);
                int height = reader.getHeight(0);
                int sample = sourceSample(width, height, maxWidth, maxHeight);
                ImageReadParam parameter = reader.getDefaultReadParam();
                parameter.setSourceSubsampling(sample, sample, 0, 0);
                BufferedImage decoded = reader.read(0, parameter);
                return scaleToFit(decoded, maxWidth, maxHeight);
            } finally {
                reader.dispose();
            }
        }
    }

    /**
     * 把有界 AWT 图片复制为 JavaFX 图片。
     *
     * @param source 有界图片
     * @return JavaFX 图片；输入为 {@code null} 时返回 {@code null}
     */
    public static Image toFxImage(final BufferedImage source) {
        if (source == null) {
            return null;
        }
        WritableImage output = new WritableImage(source.getWidth(), source.getHeight());
        PixelWriter writer = output.getPixelWriter();
        int[] row = new int[source.getWidth()];
        for (int y = 0; y < source.getHeight(); y++) {
            source.getRGB(0, y, source.getWidth(), 1, row, 0, source.getWidth());
            writer.setPixels(0, y, source.getWidth(), 1,
                    javafx.scene.image.PixelFormat.getIntArgbInstance(), row, 0, source.getWidth());
        }
        return output;
    }

    /**
     * 计算不会低于目标边界的二次幂源采样率。
     *
     * @param width 原始宽度
     * @param height 原始高度
     * @param maxWidth 最大宽度
     * @param maxHeight 最大高度
     * @return 至少为 1 的采样率
     */
    private static int sourceSample(final int width, final int height,
                                    final int maxWidth, final int maxHeight) {
        int sample = 1;
        while (sample <= Integer.MAX_VALUE / 2
                && (width / (sample * 2) >= maxWidth
                || height / (sample * 2) >= maxHeight)) {
            sample *= 2;
        }
        return sample;
    }

    /**
     * 按原比例缩放到目标边界内。
     *
     * @param source 已完成源采样的图片
     * @param maxWidth 最大宽度
     * @param maxHeight 最大高度
     * @return 边界内图片
     */
    private static BufferedImage scaleToFit(final BufferedImage source, final int maxWidth,
                                            final int maxHeight) {
        double scale = Math.min(1.0, Math.min(
                (double) maxWidth / source.getWidth(),
                (double) maxHeight / source.getHeight()));
        int width = Math.max(1, (int) Math.round(source.getWidth() * scale));
        int height = Math.max(1, (int) Math.round(source.getHeight() * scale));
        if (width == source.getWidth() && height == source.getHeight()) {
            return source;
        }
        BufferedImage scaled = new BufferedImage(width, height, BufferedImage.TYPE_INT_ARGB);
        Graphics2D graphics = scaled.createGraphics();
        try {
            graphics.setRenderingHint(RenderingHints.KEY_INTERPOLATION,
                    RenderingHints.VALUE_INTERPOLATION_BILINEAR);
            graphics.setRenderingHint(RenderingHints.KEY_RENDERING,
                    RenderingHints.VALUE_RENDER_QUALITY);
            graphics.drawImage(source, 0, 0, width, height, null);
        } finally {
            graphics.dispose();
            source.flush();
        }
        return scaled;
    }
}
