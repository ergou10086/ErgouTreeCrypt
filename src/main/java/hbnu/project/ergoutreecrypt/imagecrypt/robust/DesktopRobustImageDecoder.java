package hbnu.project.ergoutreecrypt.imagecrypt.robust;

import hbnu.project.ergoutreecrypt.exception.ErrorKind;
import hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptException;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.IOException;
import java.nio.file.Path;

/**
 * 基于桌面 ImageIO 的抗重编码载体像素解码桥。
 *
 * <p>该类由共享核心反射加载，使不具备 {@code java.desktop} 的平台仍可编译核心协议代码。
 *
 * @author ErgouTree
 * @since 2026/9/17
 */
public final class DesktopRobustImageDecoder {

    /** 工具类不允许实例化。 */
    private DesktopRobustImageDecoder() {
    }

    /**
     * 把 PNG 或 JPEG 解码为亮度平面。
     *
     * @param input 图片路径
     * @return 亮度栅格
     * @throws ImageCryptException 图片无法解码或尺寸越界
     * @throws IOException 读取失败
     */
    public static RobustRaster decode(final Path input)
            throws ImageCryptException, IOException {
        BufferedImage image;
        try {
            image = ImageIO.read(input.toFile());
        } catch (IOException e) {
            throw new ImageCryptException(ErrorKind.NOT_IMAGE_CRYPT,
                    "图片结构损坏，无法识别为纠错载体", e);
        }
        if (image == null) {
            throw new ImageCryptException(ErrorKind.NOT_IMAGE_CRYPT,
                    "图片解码器无法识别纠错载体");
        }
        int width = image.getWidth();
        int height = image.getHeight();
        if (width <= 0 || height <= 0 || width > RobustCarrier.MAX_CANVAS_SIDE
                || height > RobustCarrier.MAX_CANVAS_SIDE) {
            throw new ImageCryptException(ErrorKind.INVALID_HEADER,
                    "纠错载体尺寸越界: " + width + "×" + height);
        }
        int[] rgb = image.getRGB(0, 0, width, height, null, 0, width);
        byte[] luminance = new byte[rgb.length];
        for (int i = 0; i < rgb.length; i++) {
            int red = (rgb[i] >>> 16) & 0xff;
            int green = (rgb[i] >>> 8) & 0xff;
            int blue = rgb[i] & 0xff;
            luminance[i] = (byte) ((red * 77 + green * 150 + blue * 29 + 128) >>> 8);
        }
        return new RobustRaster(width, height, luminance);
    }
}
