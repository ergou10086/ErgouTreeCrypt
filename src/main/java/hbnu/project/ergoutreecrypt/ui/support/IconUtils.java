package hbnu.project.ergoutreecrypt.ui.support;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * 图标格式工具从 PNG 资源生成 Windows .ico 文件。
 *
 * <p>Windows Vista 及以上版本原生支持 PNG-in-ICO，因此只需要将 PNG 数据包入 ICO 容器即可，无需转换为 BMP。生成的 .ico 可用于注册表 {@code DefaultIcon} 值和 JavaFX {@link javafx.stage.Stage#getIcons()}。
 *
 * @author ErgouTree
 */
public final class IconUtils {

    /** ICO 文件类型标识。 */
    private static final short ICO_TYPE = 1;

    private IconUtils() {
    }

    /**
     * 将输入流中的 PNG 图片包装为 ICO 格式并返回字节数组。
     *
     * <p>调用者负责关闭 {@code pngStream}。ICO 只包含单张图标，
     * 尺寸从 PNG 的 IHDR 块中读取。
     *
     * @param pngStream PNG 数据输入流
     * @return 完整的 .ico 文件字节
     * @throws IOException 读取或格式错误
     */
    public static byte[] pngToIco(InputStream pngStream) throws IOException {
        byte[] pngData = pngStream.readAllBytes();
        if (pngData.length < 24) {
            throw new IOException("PNG 文件太小");
        }

        // 读取 IHDR 中的宽高（大端序）
        int width = ByteBuffer.wrap(pngData, 16, 4).order(ByteOrder.BIG_ENDIAN).getInt();
        int height = ByteBuffer.wrap(pngData, 20, 4).order(ByteOrder.BIG_ENDIAN).getInt();

        // ICO 条目中的宽/高为 1 字节，0 表示 256
        int wByte = width >= 256 ? 0 : width;
        int hByte = height >= 256 ? 0 : height;

        // ICONDIR (6) + ICONDIRENTRY (16) = 22 字节头
        int dataOffset = 6 + 16;
        ByteArrayOutputStream bos = new ByteArrayOutputStream(dataOffset + pngData.length);

        // --- 图标目录头 ---
        // 保留字段（2字节）
        bos.write(0);
        bos.write(0);
        // ICO 类型（2字节）
        writeLE16(bos, ICO_TYPE);
        // 图像数量为一（2字节）
        writeLE16(bos, 1);

        // --- 图标目录条目 ---
        bos.write(wByte);          // 宽度
        bos.write(hByte);          // 高度
        bos.write(0);              // 调色板颜色数
        bos.write(0);              // 保留字段
        writeLE16(bos, 1);         // 颜色平面数（PNG 封装在 ICO 中时为一）
        writeLE16(bos, 32);        // 每像素位数
        writeLE32(bos, pngData.length); // 图像大小
        writeLE32(bos, dataOffset);     // 图像偏移

        // --- PNG 图像数据 ---
        bos.write(pngData);

        return bos.toByteArray();
    }

    private static void writeLE16(ByteArrayOutputStream bos, int v) {
        bos.write(v & 0xFF);
        bos.write((v >> 8) & 0xFF);
    }

    private static void writeLE32(ByteArrayOutputStream bos, int v) {
        bos.write(v & 0xFF);
        bos.write((v >> 8) & 0xFF);
        bos.write((v >> 16) & 0xFF);
        bos.write((v >> 24) & 0xFF);
    }
}
