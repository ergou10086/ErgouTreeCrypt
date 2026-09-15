package hbnu.project.ergoutreecrypt.imagecrypt;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * 图片格式的有界只读探测。
 *
 * <h3>职责边界</h3>
 * <p>本类只回答两件事：输入是不是受支持的图片，以及它的原始宽高提示是多少。
 * 它<b>不解码像素</b>、不创建 {@code BufferedImage}/Bitmap、不遍历任意长度的元数据，
 * 因此调用开销固定且与图片分辨率无关。
 *
 * <h3>判定规则</h3>
 * <ul>
 *   <li>魔数与容器结构是格式身份的权威来源，扩展名只用于命名建议与冲突提示；</li>
 *   <li>只读取有界前缀（{@value #PROBE_PREFIX_BYTES} 字节）与必要的 marker；</li>
 *   <li>宽高解析失败时返回 0/0（画布改用方形），但格式身份校验失败必须由调用方拒绝；</li>
 *   <li>解析出的宽高若超出 {@link #LIMIT_HINT_SIDE} 或为非正值，一律视为未知。</li>
 * </ul>
 *
 * @author ErgouTree
 * @since 2026/9/15
 */
public final class ImageProbe {

    /**
     * 探测读取的前缀字节上限。足以覆盖 PNG IHDR、GIF 逻辑屏幕描述符、BMP DIB 头、
     * WebP 首个 chunk，以及带常见 EXIF/ICC 段的 JPEG 首个 SOF marker。
     */
    public static final int PROBE_PREFIX_BYTES = 8192;

    /**
     * 尺寸提示的可信上限，超出即视为未知。
     *
     * <p>提示仅用于给画布挑选接近原图的长宽比，恶意文件写入的荒谬数值不应影响画布计算。
     */
    public static final int LIMIT_HINT_SIDE = 1 << 20;

    /**
     * PNG 标准 8 字节签名。
     */
    private static final int[] PNG_SIGNATURE = {
            0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A
    };

    /**
     * GIF 逻辑屏幕描述符之前的固定前缀长度（6 字节）。
     */
    private static final int GIF_HEADER_LENGTH = 6;

    /**
     * BMP 文件头长度（14 字节），其后紧跟 DIB 头。
     */
    private static final int BMP_FILE_HEADER_LENGTH = 14;

    /**
     * BMP DIB 头的合法 {@code biSize} 取值集合。
     */
    private static final int[] BMP_DIB_SIZES = {12, 16, 40, 52, 56, 64, 108, 124};

    /**
     * WebP 首个 chunk 的头部偏移（RIFF 4 + 文件长度 4 + WEBP 4）。
     */
    private static final int WEBP_FIRST_CHUNK_OFFSET = 12;

    private ImageProbe() {
    }

    /**
     * 探测结果。
     *
     * @param format            由魔数判定的格式；无法识别时为 {@code null}
     * @param width             原始宽度提示；未知为 0
     * @param height            原始高度提示；未知为 0
     * @param extension         文件名扩展名（小写，不含点）；无扩展名时为空串
     * @param extensionConflict true 表示扩展名指向了另一种已知图片格式
     */
    public record Result(ImageFormat format, int width, int height,
                         String extension, boolean extensionConflict) {

        /**
         * 是否识别出受支持的图片格式。
         *
         * @return true 表示魔数与容器结构校验通过
         */
        public boolean recognized() {
            return format != null;
        }

        /**
         * 是否具备可用的宽高提示。
         *
         * @return true 表示宽高均已知且为正
         */
        public boolean hasSizeHint() {
            return width > 0 && height > 0;
        }
    }

    /**
     * 未识别格式的探测结果。
     *
     * @param extension         文件名扩展名
     * @param extensionConflict 是否存在扩展名冲突
     * @return 格式为 {@code null} 的结果
     */
    public static Result unrecognized(final String extension, final boolean extensionConflict) {
        return new Result(null, 0, 0, extension == null ? "" : extension, extensionConflict);
    }

    /**
     * 读取文件的<b>有界前缀</b>并探测格式与尺寸提示。
     *
     * <p>只读取至多 {@value #PROBE_PREFIX_BYTES} 字节，不加载完整文件，也不解码像素。
     *
     * @param input 输入文件路径
     * @return 探测结果，恒非 null；无法识别时 {@link Result#format()} 为 {@code null}
     * @throws IOException 读取失败
     */
    public static Result probe(final Path input) throws IOException {
        String fileName = input.getFileName() == null ? "" : input.getFileName().toString();
        byte[] prefix;
        try (InputStream in = Files.newInputStream(input)) {
            prefix = in.readNBytes(PROBE_PREFIX_BYTES);
        }
        return probeBytes(prefix, fileName);
    }

    /**
     * 在内存中的有界前缀上执行探测，便于单测直接构造样本。
     *
     * @param prefix   文件前缀字节（长度不超过 {@value #PROBE_PREFIX_BYTES} 时结果最可靠）
     * @param fileName 文件名，仅用于扩展名提示
     * @return 探测结果，恒非 null
     */
    public static Result probeBytes(final byte[] prefix, final String fileName) {
        String extension = ImageFormat.extensionOf(fileName);
        if (prefix == null || prefix.length < 8) {
            return unrecognized(extension, false);
        }

        ImageFormat format = detectFormat(prefix);
        if (format == null) {
            return unrecognized(extension, false);
        }

        int[] size = readSize(format, prefix);
        int width = saneSide(size[0]);
        int height = saneSide(size[1]);
        boolean conflict = isExtensionConflict(format, extension);
        return new Result(format, width, height, extension, conflict);
    }

    /**
     * 依据魔数与容器结构判定格式身份。
     *
     * @param prefix 文件前缀
     * @return 识别出的格式；无法识别时返回 {@code null}
     */
    private static ImageFormat detectFormat(final byte[] prefix) {
        if (matchesPngSignature(prefix)) {
            return ImageFormat.PNG;
        }
        if (isJpeg(prefix)) {
            return ImageFormat.JPEG;
        }
        if (isGif(prefix)) {
            return ImageFormat.GIF;
        }
        if (isBmp(prefix)) {
            return ImageFormat.BMP;
        }
        if (isWebp(prefix)) {
            return ImageFormat.WEBP;
        }
        return null;
    }

    /**
     * 判断扩展名是否指向了另一种已知图片格式。
     *
     * <p>扩展名缺失或不属于任何已知图片格式时不算冲突——此时没有可提示的矛盾。
     *
     * @param detected  魔数判定出的格式
     * @param extension 小写扩展名
     * @return true 表示扩展名明确指向另一种格式
     */
    private static boolean isExtensionConflict(final ImageFormat detected, final String extension) {
        ImageFormat byExtension = ImageFormat.fromExtension("x." + extension);
        return byExtension != null && byExtension != detected;
    }

    /**
     * 把探测出的边长规整为可信提示。
     *
     * @param side 原始边长
     * @return 合法边长；非法或超限时返回 0
     */
    private static int saneSide(final int side) {
        if (side <= 0 || side > LIMIT_HINT_SIDE) {
            return 0;
        }
        return side;
    }

    /**
     * 按格式解析原始宽高。
     *
     * @param format 已判定的格式
     * @param prefix 文件前缀
     * @return 二元数组 {@code [width, height]}；任一无法解析时为 0
     */
    private static int[] readSize(final ImageFormat format, final byte[] prefix) {
        return switch (format) {
            case PNG -> readPngSize(prefix);
            case JPEG -> readJpegSize(prefix);
            case GIF -> readGifSize(prefix);
            case BMP -> readBmpSize(prefix);
            case WEBP -> readWebpSize(prefix);
        };
    }

    // ==================== PNG ====================

    /**
     * 校验 PNG 标准签名。
     *
     * @param prefix 文件前缀
     * @return true 表示签名匹配
     */
    private static boolean matchesPngSignature(final byte[] prefix) {
        if (prefix.length < PNG_SIGNATURE.length) {
            return false;
        }
        for (int i = 0; i < PNG_SIGNATURE.length; i++) {
            if ((prefix[i] & 0xff) != PNG_SIGNATURE[i]) {
                return false;
            }
        }
        return true;
    }

    /**
     * 读取 PNG IHDR 中的宽高。
     *
     * <p>PNG 规范要求 IHDR 为第一个块，布局为：长度(4) + 类型(4) + 宽(4 大端) + 高(4 大端)。
     *
     * @param prefix 文件前缀
     * @return {@code [width, height]}；IHDR 缺失或越界时为 {@code [0, 0]}
     */
    private static int[] readPngSize(final byte[] prefix) {
        if (prefix.length < 24 || !chunkTypeEquals(prefix, 12, "IHDR")) {
            return new int[] {0, 0};
        }
        return new int[] {beInt32(prefix, 16), beInt32(prefix, 20)};
    }

    // ==================== JPEG ====================

    /**
     * 校验 JPEG SOI 与首个 marker 前缀。
     *
     * @param prefix 文件前缀
     * @return true 表示形如 JPEG
     */
    private static boolean isJpeg(final byte[] prefix) {
        return prefix.length >= 3
                && (prefix[0] & 0xff) == 0xFF
                && (prefix[1] & 0xff) == 0xD8
                && (prefix[2] & 0xff) == 0xFF;
    }

    /**
     * 在 JPEG marker 序列中定位首个 SOF 段并读取宽高。
     *
     * <p>只扫描有界前缀，遇到 SOS（{@code 0xFFDA}）或非法 marker 立即停止，不进入熵编码数据。
     *
     * @param prefix 文件前缀
     * @return {@code [width, height]}；未找到 SOF 时为 {@code [0, 0]}
     */
    private static int[] readJpegSize(final byte[] prefix) {
        int offset = 2;
        while (offset + 1 < prefix.length) {
            if ((prefix[offset] & 0xff) != 0xFF) {
                return new int[] {0, 0};
            }
            int marker = prefix[offset + 1] & 0xff;
            if (marker == 0xFF) {
                offset++;
                continue;
            }
            if (marker == 0xD8 || (marker >= 0xD0 && marker <= 0xD7) || marker == 0x01) {
                offset += 2;
                continue;
            }
            if (marker == 0xDA) {
                return new int[] {0, 0};
            }
            if (offset + 4 > prefix.length) {
                return new int[] {0, 0};
            }
            int segmentLength = beUInt16(prefix, offset + 2);
            if (segmentLength < 2) {
                return new int[] {0, 0};
            }
            if (isStartOfFrame(marker)) {
                if (offset + 9 > prefix.length) {
                    return new int[] {0, 0};
                }
                return new int[] {beUInt16(prefix, offset + 7), beUInt16(prefix, offset + 5)};
            }
            offset += 2 + segmentLength;
        }
        return new int[] {0, 0};
    }

    /**
     * 判断 marker 是否为 SOF 系列（含高度/宽度字段）。
     *
     * <p>排除 {@code 0xC4}（DHT）、{@code 0xC8}（JPG）与 {@code 0xCC}（DAC），它们不是 SOF。
     *
     * @param marker marker 字节（不含前缀 0xFF）
     * @return true 表示该 marker 携带帧尺寸
     */
    private static boolean isStartOfFrame(final int marker) {
        return marker >= 0xC0 && marker <= 0xCF
                && marker != 0xC4 && marker != 0xC8 && marker != 0xCC;
    }

    // ==================== GIF ====================

    /**
     * 校验 GIF87a / GIF89a 头。
     *
     * @param prefix 文件前缀
     * @return true 表示形如 GIF
     */
    private static boolean isGif(final byte[] prefix) {
        if (prefix.length < GIF_HEADER_LENGTH) {
            return false;
        }
        String signature = new String(prefix, 0, GIF_HEADER_LENGTH, java.nio.charset.StandardCharsets.US_ASCII);
        return "GIF87a".equals(signature) || "GIF89a".equals(signature);
    }

    /**
     * 读取 GIF 逻辑屏幕描述符中的宽高（小端）。
     *
     * @param prefix 文件前缀
     * @return {@code [width, height]}；越界时为 {@code [0, 0]}
     */
    private static int[] readGifSize(final byte[] prefix) {
        if (prefix.length < 10) {
            return new int[] {0, 0};
        }
        return new int[] {leUInt16(prefix, 6), leUInt16(prefix, 8)};
    }

    // ==================== BMP ====================

    /**
     * 校验 BMP 文件头与 DIB 头长度。
     *
     * <p>{@code "BM"} 只有 2 字节，碰撞概率不可忽略，因此额外要求 DIB 头长度为已知取值。
     *
     * @param prefix 文件前缀
     * @return true 表示形如 BMP
     */
    private static boolean isBmp(final byte[] prefix) {
        if (prefix.length < BMP_FILE_HEADER_LENGTH + 4) {
            return false;
        }
        if (prefix[0] != 'B' || prefix[1] != 'M') {
            return false;
        }
        int dibSize = leInt32(prefix, BMP_FILE_HEADER_LENGTH);
        for (int candidate : BMP_DIB_SIZES) {
            if (dibSize == candidate) {
                return true;
            }
        }
        return false;
    }

    /**
     * 读取 BMP DIB 头中的宽高。
     *
     * <p>高度为负数表示 top-down 位图，取绝对值。BITMAPCOREHEADER（12 字节）使用 16 位字段。
     *
     * @param prefix 文件前缀
     * @return {@code [width, height]}；越界或无有效尺寸时为 {@code [0, 0]}
     */
    private static int[] readBmpSize(final byte[] prefix) {
        int dibSize = leInt32(prefix, BMP_FILE_HEADER_LENGTH);
        if (dibSize == 12) {
            if (prefix.length < 22) {
                return new int[] {0, 0};
            }
            return new int[] {leUInt16(prefix, 18), leUInt16(prefix, 20)};
        }
        if (prefix.length < 26) {
            return new int[] {0, 0};
        }
        int width = leInt32(prefix, 18);
        int height = leInt32(prefix, 22);
        if (height < 0) {
            height = height == Integer.MIN_VALUE ? 0 : -height;
        }
        return new int[] {width, height};
    }

    // ==================== WebP ====================

    /**
     * 校验 RIFF/WEBP 容器头。
     *
     * @param prefix 文件前缀
     * @return true 表示形如 WebP
     */
    private static boolean isWebp(final byte[] prefix) {
        return prefix.length >= WEBP_FIRST_CHUNK_OFFSET + 8
                && chunkTypeEquals(prefix, 0, "RIFF")
                && chunkTypeEquals(prefix, 8, "WEBP");
    }

    /**
     * 按 WebP 首个 chunk 的类型读取画布宽高。
     *
     * <p>覆盖 {@code VP8 }（有损）、{@code VP8L}（无损）与 {@code VP8X}（扩展，含动画与 alpha）。
     *
     * @param prefix 文件前缀
     * @return {@code [width, height]}；chunk 类型未知或数据不足时为 {@code [0, 0]}
     */
    private static int[] readWebpSize(final byte[] prefix) {
        if (prefix.length < WEBP_FIRST_CHUNK_OFFSET + 8) {
            return new int[] {0, 0};
        }
        int dataOffset = WEBP_FIRST_CHUNK_OFFSET + 8;
        if (chunkTypeEquals(prefix, WEBP_FIRST_CHUNK_OFFSET, "VP8X")) {
            if (prefix.length < dataOffset + 10) {
                return new int[] {0, 0};
            }
            return new int[] {leUInt24(prefix, dataOffset + 4) + 1, leUInt24(prefix, dataOffset + 7) + 1};
        }
        if (chunkTypeEquals(prefix, WEBP_FIRST_CHUNK_OFFSET, "VP8 ")) {
            if (prefix.length < dataOffset + 10) {
                return new int[] {0, 0};
            }
            int width = leUInt16(prefix, dataOffset + 6) & 0x3FFF;
            int height = leUInt16(prefix, dataOffset + 8) & 0x3FFF;
            return new int[] {width, height};
        }
        if (chunkTypeEquals(prefix, WEBP_FIRST_CHUNK_OFFSET, "VP8L")) {
            if (prefix.length < dataOffset + 5 || (prefix[dataOffset] & 0xff) != 0x2F) {
                return new int[] {0, 0};
            }
            int b1 = prefix[dataOffset + 1] & 0xff;
            int b2 = prefix[dataOffset + 2] & 0xff;
            int b3 = prefix[dataOffset + 3] & 0xff;
            int b4 = prefix[dataOffset + 4] & 0xff;
            int width = (b1 | ((b2 & 0x3F) << 8)) + 1;
            int height = (((b2 >> 6) | (b3 << 2) | ((b4 & 0x0F) << 10))) + 1;
            return new int[] {width, height};
        }
        return new int[] {0, 0};
    }

    // ==================== 字节读取工具（显式字节序，不依赖平台默认） ====================

    /**
     * 比较指定偏移处的四字节 ASCII 块类型。
     *
     * @param data   字节数组
     * @param offset 起始偏移
     * @param type   期望的 4 字符 ASCII 类型
     * @return true 表示匹配
     */
    private static boolean chunkTypeEquals(final byte[] data, final int offset, final String type) {
        if (offset < 0 || offset + 4 > data.length) {
            return false;
        }
        for (int i = 0; i < 4; i++) {
            if ((data[offset + i] & 0xff) != type.charAt(i)) {
                return false;
            }
        }
        return true;
    }

    /**
     * 读取 4 字节大端无符号整数的高 32 位语义（作为有符号 int 返回，调用方负责取值范围判定）。
     *
     * @param data   字节数组
     * @param offset 起始偏移
     * @return 大端 32 位整数
     */
    private static int beInt32(final byte[] data, final int offset) {
        return ((data[offset] & 0xff) << 24)
                | ((data[offset + 1] & 0xff) << 16)
                | ((data[offset + 2] & 0xff) << 8)
                | (data[offset + 3] & 0xff);
    }

    /**
     * 读取 2 字节大端无符号整数。
     *
     * @param data   字节数组
     * @param offset 起始偏移
     * @return 0–65535
     */
    private static int beUInt16(final byte[] data, final int offset) {
        return ((data[offset] & 0xff) << 8) | (data[offset + 1] & 0xff);
    }

    /**
     * 读取 4 字节小端 32 位整数。
     *
     * @param data   字节数组
     * @param offset 起始偏移
     * @return 小端 32 位整数
     */
    private static int leInt32(final byte[] data, final int offset) {
        return (data[offset] & 0xff)
                | ((data[offset + 1] & 0xff) << 8)
                | ((data[offset + 2] & 0xff) << 16)
                | ((data[offset + 3] & 0xff) << 24);
    }

    /**
     * 读取 2 字节小端无符号整数。
     *
     * @param data   字节数组
     * @param offset 起始偏移
     * @return 0–65535
     */
    private static int leUInt16(final byte[] data, final int offset) {
        return (data[offset] & 0xff) | ((data[offset + 1] & 0xff) << 8);
    }

    /**
     * 读取 3 字节小端无符号整数（WebP VP8X 的画布尺寸使用该宽度）。
     *
     * @param data   字节数组
     * @param offset 起始偏移
     * @return 0–16777215
     */
    private static int leUInt24(final byte[] data, final int offset) {
        return (data[offset] & 0xff)
                | ((data[offset + 1] & 0xff) << 8)
                | ((data[offset + 2] & 0xff) << 16);
    }
}
