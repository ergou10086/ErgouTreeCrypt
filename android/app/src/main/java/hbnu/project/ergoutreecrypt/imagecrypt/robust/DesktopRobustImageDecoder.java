package hbnu.project.ergoutreecrypt.imagecrypt.robust;

import android.graphics.Bitmap;
import android.graphics.BitmapFactory;

import hbnu.project.ergoutreecrypt.exception.ErrorKind;
import hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptException;

import java.io.IOException;
import java.nio.file.Path;

/**
 * Android Bitmap 实现的纠错载体像素解码桥。
 *
 * <p>类名与共享核心反射入口保持一致；Android 构建会排除桌面 AWT 实现并采用本类。
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
     * @throws IOException 保留给跨平台反射签名
     */
    public static RobustRaster decode(final Path input)
            throws ImageCryptException, IOException {
        Bitmap bitmap = BitmapFactory.decodeFile(input.toString());
        if (bitmap == null) {
            throw new ImageCryptException(ErrorKind.NOT_IMAGE_CRYPT,
                    "Android 图片解码器无法识别纠错载体");
        }
        try {
            int width = bitmap.getWidth();
            int height = bitmap.getHeight();
            if (width <= 0 || height <= 0 || width > RobustCarrier.MAX_CANVAS_SIDE
                    || height > RobustCarrier.MAX_CANVAS_SIDE) {
                throw new ImageCryptException(ErrorKind.INVALID_HEADER,
                        "纠错载体尺寸越界: " + width + "×" + height);
            }
            byte[] luminance = new byte[width * height];
            int[] row = new int[width];
            for (int y = 0; y < height; y++) {
                bitmap.getPixels(row, 0, width, 0, y, width, 1);
                for (int x = 0; x < width; x++) {
                    int pixel = row[x];
                    int red = (pixel >>> 16) & 0xff;
                    int green = (pixel >>> 8) & 0xff;
                    int blue = pixel & 0xff;
                    luminance[y * width + x] =
                            (byte) ((red * 77 + green * 150 + blue * 29 + 128) >>> 8);
                }
            }
            return new RobustRaster(width, height, luminance);
        } finally {
            bitmap.recycle();
        }
    }
}
