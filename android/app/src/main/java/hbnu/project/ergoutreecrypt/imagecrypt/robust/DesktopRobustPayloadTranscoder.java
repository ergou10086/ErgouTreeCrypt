package hbnu.project.ergoutreecrypt.imagecrypt.robust;

import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.Canvas;
import android.graphics.Color;

import hbnu.project.ergoutreecrypt.exception.ErrorKind;
import hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptException;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

/**
 * Android Bitmap 实现的超大图片 JPEG 恢复副本转码桥。
 *
 * @author ErgouTree
 * @since 2026/9/17
 */
public final class DesktopRobustPayloadTranscoder {

    /** JPEG 尝试质量百分比。 */
    private static final int[] QUALITIES = {92, 86, 78, 68, 58, 48, 38};

    /** 为极强档小容量恢复副本保留的最大缩放轮数。 */
    private static final int SCALE_PASSES = 8;

    /** 工具类不允许实例化。 */
    private DesktopRobustPayloadTranscoder() {
    }

    /**
     * 把输入首帧转换为限定大小的 JPEG。
     *
     * @param input 输入图片
     * @param output JPEG 临时文件
     * @param maximumBytes 最大字节数
     * @return 输出路径
     * @throws ImageCryptException 图片无法解码或多轮压缩后仍超限
     * @throws IOException 文件读写失败
     */
    public static Path transcode(final Path input, final Path output, final long maximumBytes)
            throws ImageCryptException, IOException {
        Bitmap decoded = BitmapFactory.decodeFile(input.toString());
        if (decoded == null) {
            throw new ImageCryptException(ErrorKind.UNSUPPORTED_FORMAT,
                    "无法为超大图片生成纠错模式 JPEG 恢复副本");
        }
        Bitmap image = flatten(decoded);
        decoded.recycle();
        try {
            for (int scalePass = 0; scalePass < SCALE_PASSES; scalePass++) {
                for (int quality : QUALITIES) {
                    writeJpeg(image, output, quality);
                    if (Files.size(output) <= maximumBytes) {
                        return output;
                    }
                }
                int width = Math.max(1, Math.round(image.getWidth() * 0.82f));
                int height = Math.max(1, Math.round(image.getHeight() * 0.82f));
                Bitmap scaled = Bitmap.createScaledBitmap(image, width, height, true);
                image.recycle();
                image = scaled;
            }
        } finally {
            image.recycle();
        }
        throw new ImageCryptException(ErrorKind.CAPACITY_INSUFFICIENT,
                "图片在降低 JPEG 质量与尺寸后仍超过纠错载体容量");
    }

    /**
     * 把透明图片合成为白底 ARGB 图片。
     *
     * @param source 源图片
     * @return 白底图片
     */
    private static Bitmap flatten(final Bitmap source) {
        Bitmap target = Bitmap.createBitmap(source.getWidth(), source.getHeight(),
                Bitmap.Config.ARGB_8888);
        Canvas canvas = new Canvas(target);
        canvas.drawColor(Color.WHITE);
        canvas.drawBitmap(source, 0, 0, null);
        return target;
    }

    /**
     * 用指定质量写 JPEG。
     *
     * @param image 图片
     * @param output 输出路径
     * @param quality 质量百分比
     * @throws IOException 写入失败
     */
    private static void writeJpeg(final Bitmap image, final Path output, final int quality)
            throws IOException {
        try (OutputStream stream = Files.newOutputStream(output, StandardOpenOption.WRITE,
                StandardOpenOption.TRUNCATE_EXISTING)) {
            if (!image.compress(Bitmap.CompressFormat.JPEG, quality, stream)) {
                throw new IOException("Android JPEG 编码器返回失败");
            }
        }
    }
}
