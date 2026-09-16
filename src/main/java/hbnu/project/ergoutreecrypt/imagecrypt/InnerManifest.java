package hbnu.project.ergoutreecrypt.imagecrypt;

import hbnu.project.ergoutreecrypt.exception.ErrorKind;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

/**
 * EGTC-IMG v1 内层清单（InnerManifest）。
 *
 * <h3>为什么放在加密区</h3>
 * <p>清单携带原始文件名、MIME 和扩展名。若放在明文协议头里，密码模式会直接泄漏用户的文件命名与格式偏好。
 * 因此清单整体位于加密封装区之内，只有密钥正确时才能读出。
 *
 * <h3>二进制布局（全部大端）</h3>
 * <pre>
 *   innerMagic       8    ASCII "EGTC-INR"
 *   innerVersion     1    1
 *   formatId         1    见 {@link ImageFormat#id()}
 *   flags            2    bit0 动画 / bit1 多页 / bit2 携带名称
 *   manifestLength   4    描述区长度（= 28 + nameLength + mimeLength + extensionLength）
 *   originalFileLength 8  原文件字节数
 *   nameLength       2    UTF-8 字节数，上限 1024
 *   mimeLength       1    ASCII/UTF-8 字节数，上限 127
 *   extensionLength  1    小写扩展名字节数，上限 16
 *   originalName     变长 仅 basename
 *   mediaType        变长 例如 image/jpeg
 *   extension        变长 例如 jpg
 * </pre>
 *
 * <p>{@code manifestLength} <b>不含</b> originalFile 载荷，这样 reader 在开始读取大载荷前就能完成描述区的边界校验；{@link #totalLength()} 才是清单在原文件之前的完整占位长度。
 *
 * <h3>路径安全</h3>
 * <p>写入侧只接受 basename 并拒绝任何路径分隔符；读取侧不信任文件内容，
 * {@link #safeBasename()} 会剥离目录、盘符与非法字符，平台侧仍需再过
 * {@code FileNameSanitizer} 与覆盖确认。
 *
 * @author ErgouTree
 * @since 2026/9/15
 */
public final class InnerManifest {

    /**
     * Windows 保留设备名，不能作为文件名主干。
     */
    private static final String[] WINDOWS_RESERVED_NAMES = {
            "CON", "PRN", "AUX", "NUL",
            "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
            "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"
    };

    /**
     * 文件名中不允许出现的字符（沿用 Windows 限制，保证恢复产物在两端都可写）。
     */
    private static final String ILLEGAL_NAME_CHARS = "<>:\"/\\|?*";

    /**
     * 原图片格式。
     */
    private final ImageFormat format;

    /**
     * 原文件是否为动画/多帧内容（展示性提示，不参与恢复）。
     */
    private final boolean animated;

    /**
     * 原文件是否为多页内容（v1 未使用，为 Phase 2 预留）。
     */
    private final boolean multiPage;

    /**
     * 原文件字节数。
     */
    private final long originalFileLength;

    /**
     * 原始文件 basename（UTF-8）。无名称时为空串。
     */
    private final String originalName;

    /**
     * MIME 类型。
     */
    private final String mediaType;

    /**
     * 规范化小写扩展名（不含点）。
     */
    private final String extension;

    /**
     * 完整构造。
     *
     * @param format             原图片格式
     * @param animated           是否为动画内容
     * @param multiPage          是否为多页内容
     * @param originalFileLength 原文件字节数
     * @param originalName       原始 basename
     * @param mediaType          MIME 类型
     * @param extension          规范化小写扩展名
     */
    private InnerManifest(final ImageFormat format, final boolean animated, final boolean multiPage,
                          final long originalFileLength, final String originalName,
                          final String mediaType, final String extension) {
        this.format = format;
        this.animated = animated;
        this.multiPage = multiPage;
        this.originalFileLength = originalFileLength;
        this.originalName = originalName;
        this.mediaType = mediaType;
        this.extension = extension;
    }

    // ==================== 构造 ====================

    /**
     * 构造清单。
     *
     * <p>{@code originalName} 只接受 basename：任何路径分隔符、盘符或非法字符都会导致拒绝，
     * 避免写出路径穿越信息。传空串表示不携带文件名（恢复时改用格式兜底名）。
     *
     * @param format             原图片格式
     * @param originalFileLength 原文件字节数
     * @param originalName       原始 basename，可为空串
     * @param mediaType          MIME 类型，可为空串（回退为格式默认值）
     * @param extension          小写扩展名，可为空串（回退为格式默认扩展名）
     * @param animated           是否为动画内容
     * @return 清单实例
     * @throws ImageCryptException 名称非法、长度越界或字节数溢出
     */
    public static InnerManifest create(final ImageFormat format, final long originalFileLength,
                                       final String originalName, final String mediaType,
                                       final String extension, final boolean animated)
            throws ImageCryptException {
        if (format == null) {
            throw new ImageCryptException(ErrorKind.INTERNAL_ERROR, "清单必须携带图片格式");
        }
        if (originalFileLength < 0) {
            throw new ImageCryptException(ErrorKind.INTERNAL_ERROR, "原文件长度不得为负");
        }
        String name = originalName == null ? "" : originalName;
        if (!name.isEmpty()) {
            validateWritableBasename(name);
        }
        String mime = mediaType == null || mediaType.isEmpty()
                ? format.defaultMimeType() : mediaType;
        String ext = extension == null || extension.isEmpty()
                ? format.defaultExtension() : extension.toLowerCase(Locale.ROOT);
        if (!ext.isEmpty()) {
            validateWritableExtension(ext);
        }
        InnerManifest manifest = new InnerManifest(format, animated, false,
                originalFileLength, name, mime, ext);
        manifest.validateDescriptorLimits();
        return manifest;
    }

    /**
     * 解析并校验清单描述区。
     *
     * <p>只解析描述区，不读取 originalFile 载荷；调用方据此获得原文件长度后再流式处理载荷。
     *
     * @param raw 描述区字节（长度必须等于 {@code manifestLength}）
     * @return 解析结果
     * @throws ImageCryptException 魔数/版本/flags 未知、长度自洽性失败、UTF-8 非法或上限越界
     */
    public static InnerManifest fromBytes(final byte[] raw) throws ImageCryptException {
        if (raw == null || raw.length < ImageCryptProtocol.INNER_MANIFEST_FIXED_LENGTH) {
            throw new ImageCryptException(ErrorKind.INVALID_HEADER, "内层清单长度不足");
        }
        if (!hasInnerMagic(raw)) {
            throw new ImageCryptException(ErrorKind.INVALID_HEADER, "未检测到 EGTC-INR 内层魔数");
        }
        int version = raw[8] & 0xff;
        if (version != ImageCryptProtocol.INNER_VERSION) {
            throw new ImageCryptException(ErrorKind.UNSUPPORTED_VERSION,
                    "不支持的内层清单版本: " + version);
        }

        ByteBuffer buffer = ByteBuffer.wrap(raw).order(ByteOrder.BIG_ENDIAN);
        int formatId = raw[9] & 0xff;
        ImageFormat format;
        try {
            format = ImageFormat.fromId(formatId);
        } catch (IllegalArgumentException e) {
            throw new ImageCryptException(ErrorKind.INVALID_HEADER, e.getMessage(), e);
        }

        int flags = buffer.getShort(10) & 0xffff;
        if ((flags & ~ImageCryptProtocol.INNER_FLAG_KNOWN_MASK) != 0) {
            throw new ImageCryptException(ErrorKind.INVALID_HEADER,
                    "内层清单存在 v1 未定义的 flags 位: 0x" + Integer.toHexString(flags));
        }
        long manifestLength = buffer.getInt(12) & 0xffffffffL;
        long originalFileLength = buffer.getLong(16);
        int nameLength = buffer.getShort(24) & 0xffff;
        int mimeLength = raw[26] & 0xff;
        int extensionLength = raw[27] & 0xff;

        if (nameLength > ImageCryptProtocol.LIMIT_NAME_BYTES) {
            throw new ImageCryptException(ErrorKind.INVALID_HEADER, "清单文件名超长");
        }
        if (mimeLength > ImageCryptProtocol.LIMIT_MIME_BYTES) {
            throw new ImageCryptException(ErrorKind.INVALID_HEADER, "清单 MIME 超长");
        }
        if (extensionLength > ImageCryptProtocol.LIMIT_EXTENSION_BYTES) {
            throw new ImageCryptException(ErrorKind.INVALID_HEADER, "清单扩展名超长");
        }

        long expectedLength = ImageCryptProtocol.INNER_MANIFEST_FIXED_LENGTH
                + (long) nameLength + mimeLength + extensionLength;
        if (manifestLength != expectedLength) {
            throw new ImageCryptException(ErrorKind.INVALID_HEADER,
                    "清单描述长度与字段不自洽: 声明 " + manifestLength + "，实际应为 " + expectedLength);
        }
        if (manifestLength > ImageCryptProtocol.LIMIT_MANIFEST_BYTES) {
            throw new ImageCryptException(ErrorKind.INVALID_HEADER, "清单描述区超过 64 KiB 上限");
        }
        if (raw.length < manifestLength) {
            throw new ImageCryptException(ErrorKind.INVALID_HEADER,
                    "清单实际字节数少于其声明的描述长度");
        }

        int cursor = ImageCryptProtocol.INNER_MANIFEST_FIXED_LENGTH;
        String name = decodeUtf8(raw, cursor, nameLength, "originalName");
        cursor += nameLength;
        String mime = decodeUtf8(raw, cursor, mimeLength, "mediaType");
        cursor += mimeLength;
        String extension = decodeUtf8(raw, cursor, extensionLength, "extension");

        boolean hasNameFlag = (flags & ImageCryptProtocol.INNER_FLAG_HAS_NAME) != 0;
        if (hasNameFlag != (nameLength > 0)) {
            throw new ImageCryptException(ErrorKind.INVALID_HEADER,
                    "内层清单的名称标志与名称长度不一致");
        }
        if (!extension.isEmpty()) {
            validateReadExtension(extension);
        }

        return new InnerManifest(format, (flags & ImageCryptProtocol.INNER_FLAG_ANIMATED) != 0,
                (flags & ImageCryptProtocol.INNER_FLAG_MULTI_PAGE) != 0,
                originalFileLength, name, mime, extension);
    }

    // ==================== 编码 ====================

    /**
     * 序列化清单描述区（不含 originalFile 载荷）。
     *
     * @return 描述区字节
     * @throws ImageCryptException 描述区超过上限或长度溢出
     */
    public byte[] toBytes() throws ImageCryptException {
        byte[] nameBytes = originalName.getBytes(StandardCharsets.UTF_8);
        byte[] mimeBytes = mediaType.getBytes(StandardCharsets.UTF_8);
        byte[] extensionBytes = extension.getBytes(StandardCharsets.US_ASCII);
        int descriptorLength = ImageCryptProtocol.INNER_MANIFEST_FIXED_LENGTH
                + nameBytes.length + mimeBytes.length + extensionBytes.length;
        if (descriptorLength > ImageCryptProtocol.LIMIT_MANIFEST_BYTES) {
            throw new ImageCryptException(ErrorKind.INTERNAL_ERROR, "内层清单描述区超过 64 KiB 上限");
        }

        ByteBuffer buffer = ByteBuffer.allocate(descriptorLength).order(ByteOrder.BIG_ENDIAN);
        buffer.put(ImageCryptProtocol.INNER_MAGIC.getBytes(StandardCharsets.US_ASCII));
        buffer.put((byte) ImageCryptProtocol.INNER_VERSION);
        buffer.put((byte) format.id());
        buffer.putShort((short) flagsValue());
        buffer.putInt(descriptorLength);
        buffer.putLong(originalFileLength);
        buffer.putShort((short) nameBytes.length);
        buffer.put((byte) mimeBytes.length);
        buffer.put((byte) extensionBytes.length);
        buffer.put(nameBytes);
        buffer.put(mimeBytes);
        buffer.put(extensionBytes);
        return buffer.array();
    }

    /**
     * 计算清单描述区的字节长度，即协议字段 {@code manifestLength}。
     *
     * @return 描述区字节数（不含 originalFile）
     */
    public int descriptorLength() {
        return ImageCryptProtocol.INNER_MANIFEST_FIXED_LENGTH
                + originalName.getBytes(StandardCharsets.UTF_8).length
                + mediaType.getBytes(StandardCharsets.UTF_8).length
                + extension.length();
    }

    /**
     * 计算清单在原文件载荷之前的完整占位长度。
     *
     * <p>协议头中的 {@code innerPlainLength} 应等于 {@code totalLength() + originalFileLength}。
     *
     * @return 描述区长度与原文件长度之和
     * @throws ImageCryptException 相加溢出
     */
    public long totalLength() throws ImageCryptException {
        try {
            return Math.addExact((long) descriptorLength(), originalFileLength);
        } catch (ArithmeticException e) {
            throw new ImageCryptException(ErrorKind.INTERNAL_ERROR, "清单总长度溢出", e);
        }
    }

    // ==================== 访问器 ====================

    /**
     * 返回原图片格式。
     *
     * @return 格式
     */
    public ImageFormat format() {
        return format;
    }

    /**
     * 返回原文件是否为动画内容。
     *
     * @return true 表示动画/多帧
     */
    public boolean animated() {
        return animated;
    }

    /**
     * 返回原文件是否为多页内容。
     *
     * @return true 表示多页（v1 恒为 false）
     */
    public boolean multiPage() {
        return multiPage;
    }

    /**
     * 返回原文件字节数。
     *
     * @return 字节数
     */
    public long originalFileLength() {
        return originalFileLength;
    }

    /**
     * 返回原始文件名（basename）。
     *
     * @return 文件名；未携带时为空串
     */
    public String originalName() {
        return originalName;
    }

    /**
     * 返回 MIME 类型。
     *
     * @return MIME 类型
     */
    public String mediaType() {
        return mediaType;
    }

    /**
     * 返回规范化小写扩展名。
     *
     * @return 扩展名（不含点）
     */
    public String extension() {
        return extension;
    }

    /**
     * 返回一个可安全用作恢复文件名的 basename。
     *
     * <p>不信任文件内容：剥离任何目录成分与盘符，移除平台非法字符，拒绝 {@code .}/{@code ..}，
     * 并为 Windows 保留设备名追加前缀。调用方仍须再经过平台 {@code FileNameSanitizer}
     * 与覆盖确认；本方法只保证"不会把路径穿越信息当成文件名"。
     *
     * @return 清洗后的 basename；原名不可用时返回空串，由调用方回退到格式兜底名
     */
    public String safeBasename() {
        if (originalName.isEmpty()) {
            return "";
        }
        String name = stripDirectory(originalName);
        StringBuilder cleaned = new StringBuilder(name.length());
        for (int i = 0; i < name.length(); i++) {
            char c = name.charAt(i);
            if (c < 0x20 || c == 0x7f || ILLEGAL_NAME_CHARS.indexOf(c) >= 0) {
                continue;
            }
            cleaned.append(c);
        }
        String result = cleaned.toString();
        while (result.endsWith(".") || result.endsWith(" ")) {
            result = result.substring(0, result.length() - 1);
        }
        if (result.isEmpty() || ".".equals(result) || "..".equals(result)) {
            return "";
        }
        return applyWindowsReservedGuard(result);
    }

    /**
     * 计算描述区 flags 字段取值。
     *
     * @return flags 位组合
     */
    private int flagsValue() {
        int value = 0;
        if (animated) {
            value |= ImageCryptProtocol.INNER_FLAG_ANIMATED;
        }
        if (multiPage) {
            value |= ImageCryptProtocol.INNER_FLAG_MULTI_PAGE;
        }
        if (!originalName.isEmpty()) {
            value |= ImageCryptProtocol.INNER_FLAG_HAS_NAME;
        }
        return value;
    }

    /**
     * 返回不含敏感路径的调试描述。
     *
     * @return 描述文本
     */
    @Override
    public String toString() {
        return "InnerManifest{format=" + format
                + ", animated=" + animated
                + ", originalFileLength=" + originalFileLength
                + ", extension=" + extension + '}';
    }

    // ==================== 校验与清洗工具 ====================

    /**
     * 校验将要写入清单的描述区长度是否越界。
     *
     * @throws ImageCryptException 名称/MIME/扩展名或描述区超限
     */
    private void validateDescriptorLimits() throws ImageCryptException {
        if (originalName.getBytes(StandardCharsets.UTF_8).length > ImageCryptProtocol.LIMIT_NAME_BYTES) {
            throw new ImageCryptException(ErrorKind.INTERNAL_ERROR, "文件名超过 1024 字节上限");
        }
        if (mediaType.getBytes(StandardCharsets.UTF_8).length > ImageCryptProtocol.LIMIT_MIME_BYTES) {
            throw new ImageCryptException(ErrorKind.INTERNAL_ERROR, "MIME 超过 127 字节上限");
        }
        if (descriptorLength() > ImageCryptProtocol.LIMIT_MANIFEST_BYTES) {
            throw new ImageCryptException(ErrorKind.INTERNAL_ERROR, "清单描述区超过 64 KiB 上限");
        }
    }

    /**
     * 校验待写入的文件名是合规 basename。
     *
     * @param name 文件名
     * @throws ImageCryptException 含路径分隔符、盘符或非法字符
     */
    private static void validateWritableBasename(final String name) throws ImageCryptException {
        for (int i = 0; i < name.length(); i++) {
            char c = name.charAt(i);
            if (c == '/' || c == '\\') {
                throw new ImageCryptException(ErrorKind.INTERNAL_ERROR,
                        "清单文件名不得包含路径分隔符");
            }
            if (ILLEGAL_NAME_CHARS.indexOf(c) >= 0 || c < 0x20) {
                throw new ImageCryptException(ErrorKind.INTERNAL_ERROR,
                        "清单文件名包含非法字符");
            }
        }
        if (".".equals(name) || "..".equals(name)) {
            throw new ImageCryptException(ErrorKind.INTERNAL_ERROR, "清单文件名不得为 ./..");
        }
    }

    /**
     * 校验待写入的扩展名只含小写字母与数字。
     *
     * @param extension 小写扩展名
     * @throws ImageCryptException 含非法字符或超长
     */
    private static void validateWritableExtension(final String extension) throws ImageCryptException {
        if (extension.length() > ImageCryptProtocol.LIMIT_EXTENSION_BYTES) {
            throw new ImageCryptException(ErrorKind.INTERNAL_ERROR, "扩展名超过 16 字节上限");
        }
        for (int i = 0; i < extension.length(); i++) {
            char c = extension.charAt(i);
            boolean allowed = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
            if (!allowed) {
                throw new ImageCryptException(ErrorKind.INTERNAL_ERROR,
                        "扩展名只能由小写字母与数字构成");
            }
        }
    }

    /**
     * 校验从文件中读出的扩展名是否规范。
     *
     * @param extension 扩展名
     * @throws ImageCryptException 长度或字符集不合规
     */
    private static void validateReadExtension(final String extension) throws ImageCryptException {
        if (extension.length() > ImageCryptProtocol.LIMIT_EXTENSION_BYTES) {
            throw new ImageCryptException(ErrorKind.INVALID_HEADER, "清单扩展名超长");
        }
        for (int i = 0; i < extension.length(); i++) {
            char c = extension.charAt(i);
            boolean allowed = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
            if (!allowed) {
                throw new ImageCryptException(ErrorKind.INVALID_HEADER,
                        "清单扩展名不是规范的小写形式");
            }
        }
    }

    /**
     * 以严格模式解码一段 UTF-8，并剥离可能的 BOM。
     *
     * @param data   字节数组
     * @param offset 起始偏移
     * @param length 字节数
     * @param field  字段名（用于诊断消息）
     * @return 解码字符串
     * @throws ImageCryptException 字节序列不是合法 UTF-8
     */
    private static String decodeUtf8(final byte[] data, final int offset, final int length,
                                     final String field) throws ImageCryptException {
        if (length == 0) {
            return "";
        }
        if (offset + length > data.length) {
            throw new ImageCryptException(ErrorKind.INVALID_HEADER, "清单字段 " + field + " 越界");
        }
        CharsetDecoder decoder = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT);
        String text;
        try {
            text = decoder.decode(ByteBuffer.wrap(data, offset, length)).toString();
        } catch (CharacterCodingException e) {
            throw new ImageCryptException(ErrorKind.INVALID_HEADER,
                    "清单字段 " + field + " 不是合法 UTF-8", e);
        }
        return stripBom(text);
    }

    /**
     * 剥离一个前导 BOM（U+FEFF）。
     *
     * <p>写入侧恒为无 BOM 的规范 UTF-8；读取侧容忍外部工具补上的 BOM，避免为一个无害字符拒绝整份文件。
     *
     * @param text 解码结果
     * @return 去掉前导 BOM 的文本
     */
    private static String stripBom(final String text) {
        if (!text.isEmpty() && text.charAt(0) == 0xFEFF) {
            return text.substring(1);
        }
        return text;
    }

    /**
     * 校验内层魔数。
     *
     * @param raw 描述区字节
     * @return true 表示魔数匹配
     */
    private static boolean hasInnerMagic(final byte[] raw) {
        for (int i = 0; i < ImageCryptProtocol.INNER_MAGIC.length(); i++) {
            if ((raw[i] & 0xff) != ImageCryptProtocol.INNER_MAGIC.charAt(i)) {
                return false;
            }
        }
        return true;
    }

    /**
     * 剥离文件名中的目录成分与盘符。
     *
     * @param name 原始名称
     * @return 仅剩 basename 的名称
     */
    private static String stripDirectory(final String name) {
        String result = name;
        int separator = Math.max(result.lastIndexOf('/'), result.lastIndexOf('\\'));
        if (separator >= 0) {
            result = result.substring(separator + 1);
        }
        if (result.length() >= 2 && result.charAt(1) == ':') {
            result = result.substring(2);
        }
        return result;
    }

    /**
     * 为 Windows 保留设备名追加下划线前缀，避免恢复产物无法落盘。
     *
     * @param name 文件名
     * @return 处理后的文件名
     */
    private static String applyWindowsReservedGuard(final String name) {
        int dot = name.indexOf('.');
        String stem = dot < 0 ? name : name.substring(0, dot);
        for (String reserved : WINDOWS_RESERVED_NAMES) {
            if (reserved.equalsIgnoreCase(stem)) {
                return "_" + name;
            }
        }
        return name;
    }
}
