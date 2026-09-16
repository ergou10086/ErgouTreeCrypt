package hbnu.project.ergoutreecrypt.imagecrypt;

import java.util.Locale;

/**
 * EGTC-IMG 首期支持的输入图片格式。
 *
 * <p>核心按"完整原文件字节"处理输入，不解码、不重编码，因此这里只描述格式身份、兜底扩展名与 MIME，不携带任何编解码器。
 * 动画、色彩配置与元数据都只是原文件字节的一部分，随密文完整往返。
 *
 * <p>{@link #id()} 是写入 InnerManifest 的稳定数值标识，<b>一经发布不得更改</b>，
 * 也不得使用 Java 枚举 ordinal。APNG 属于 PNG 变体，共享 {@link #PNG} 标识：
 * 恢复只需要正确的扩展名，而"是否动画"只是清单里的一条展示性提示。
 *
 * @author ErgouTree
 * @since 2026/9/15
 */
public enum ImageFormat {

    /**
     * PNG / APNG。探测依据：PNG 标准 8 字节签名 + IHDR。
     */
    PNG(1, "png", "image/png"),

    /**
     * JPEG / JPG（baseline、progressive、CMYK 等变体统一处理）。
     */
    JPEG(2, "jpg", "image/jpeg"),

    /**
     * GIF87a / GIF89a（静态、透明、动画统一处理）。
     */
    GIF(3, "gif", "image/gif"),

    /**
     * BMP / DIB（24-bit、32-bit、top-down 统一处理）。
     */
    BMP(4, "bmp", "image/bmp"),

    /**
     * WebP（RIFF 容器；有损、无损、透明、动画统一处理）。
     */
    WEBP(5, "webp", "image/webp");

    /**
     * 写入 InnerManifest 的稳定数值标识。6–9 预留给 Phase 2 的 TIFF / HEIF / AVIF / JPEG 2000。
     */
    private final int id;

    /**
     * 恢复时使用的兜底扩展名（小写，不含点）。
     */
    private final String defaultExtension;

    /**
     * 清单中写入的默认 MIME 类型。
     */
    private final String defaultMimeType;

    /**
     * @param id               稳定的协议数值标识
     * @param defaultExtension 恢复时的兜底扩展名
     * @param defaultMimeType  清单中的默认 MIME 类型
     */
    ImageFormat(final int id, final String defaultExtension, final String defaultMimeType) {
        this.id = id;
        this.defaultExtension = defaultExtension;
        this.defaultMimeType = defaultMimeType;
    }

    /**
     * 返回写入清单的稳定数值标识。
     *
     * @return 协议数值标识
     */
    public int id() {
        return id;
    }

    /**
     * 返回恢复时使用的兜底扩展名。
     *
     * @return 小写扩展名，不含点，例如 {@code "jpg"}
     */
    public String defaultExtension() {
        return defaultExtension;
    }

    /**
     * 返回清单中写入的默认 MIME 类型。
     *
     * @return MIME 类型，例如 {@code "image/jpeg"}
     */
    public String defaultMimeType() {
        return defaultMimeType;
    }

    /**
     * 由清单中的数值标识反查格式。
     *
     * @param id 协议数值标识
     * @return 对应格式
     * @throws IllegalArgumentException 未知标识
     */
    public static ImageFormat fromId(final int id) {
        for (ImageFormat format : values()) {
            if (format.id == id) {
                return format;
            }
        }
        throw new IllegalArgumentException("未知的图片格式 id: " + id);
    }

    /**
     * 按扩展名猜测格式，仅用于生成提示与命名建议。
     *
     * <p>扩展名<b>不是</b>权威来源：真正的格式身份由 {@link ImageProbe} 依据魔数判定。
     *
     * @param fileName 文件名（可含路径，可为 null）
     * @return 匹配的格式；无法识别时返回 {@code null}
     */
    public static ImageFormat fromExtension(final String fileName) {
        String extension = extensionOf(fileName);
        if (extension.isEmpty()) {
            return null;
        }
        if ("jpeg".equals(extension)) {
            return JPEG;
        }
        for (ImageFormat format : values()) {
            if (format.defaultExtension.equals(extension)) {
                return format;
            }
        }
        return null;
    }

    /**
     * 提取并规范化文件扩展名。
     *
     * @param fileName 文件名（可含路径，可为 null）
     * @return 小写扩展名（不含点）；无扩展名时返回空串
     */
    public static String extensionOf(final String fileName) {
        if (fileName == null) {
            return "";
        }
        String name = fileName;
        int slash = Math.max(name.lastIndexOf('/'), name.lastIndexOf('\\'));
        if (slash >= 0) {
            name = name.substring(slash + 1);
        }
        int dot = name.lastIndexOf('.');
        if (dot <= 0 || dot == name.length() - 1) {
            return "";
        }
        return name.substring(dot + 1).toLowerCase(Locale.ROOT);
    }
}
