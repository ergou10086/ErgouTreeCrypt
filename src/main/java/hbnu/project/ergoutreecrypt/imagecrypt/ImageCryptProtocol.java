package hbnu.project.ergoutreecrypt.imagecrypt;

import hbnu.project.ergoutreecrypt.exception.ErrorKind;

/**
 * EGTC-IMG v1 图片密文协议的<b>唯一常量来源</b>。
 *
 * <h3>定位</h3>
 * <p>本类冻结 v1 的全部字节偏移、长度、字节序、算法 ID、认证覆盖范围、KDF 参数与硬上限。
 * 桌面端（JavaFX）与 Android 端（Compose）共享同一份纯 Java 核心，两端都必须从本类取值，
 * 禁止任一端自行定义第二套常量或按平台默认值推断。
 *
 * <h3>冻结规则</h3>
 * <p>本类中任何随稳定版发布的取值，其语义、偏移与字节序都<b>不可原位修改</b>。需要变更时
 * 只能提升 {@link #VERSION} 并把新语义放进新版本，旧版本 reader 必须长期保留。规范正文见
 * {@code docs/EGTC-IMG-v1协议规范.md}。
 *
 * <h3>安全语义</h3>
 * <p>公开恢复（{@link ImageCryptMode#PUBLIC_RECOVERY}）把每文件随机主密钥明文写入协议头，
 * 因此只阻止直接查看，<b>不提供任何保密性</b>，不宣称来源真实性。只有密码保护模式通过
 * Argon2id 派生密钥提供机密性与完整性。
 *
 * @author ErgouTree
 * @since 2026/9/15
 */
public final class ImageCryptProtocol {

    // ==================== 魔数与版本 ====================

    /**
     * 外层协议魔数（8 字节 ASCII），位于 RGB 像素逻辑字节流的起始处。
     */
    public static final String MAGIC = "EGTC-IMG";

    /**
     * EGTC-IMG 协议版本号。v1 固定为 1。
     */
    public static final int VERSION = 1;

    /**
     * 内层清单魔数（8 字节 ASCII），位于加密区，避免密码模式泄漏文件名与格式。
     */
    public static final String INNER_MAGIC = "EGTC-INR";

    /**
     * 内层清单版本号。v1 固定为 1。
     */
    public static final int INNER_VERSION = 1;

    // ==================== 密码学上下文串 ====================

    /**
     * HKDF-SHA3-256 的 info 参数，用于把子密钥绑定到图片协议域。
     *
     * <p>RFC 5869 要求 info 绑定应用与协议上下文。本协议<b>不得</b>复用媒体协议
     * 当前的空 info，否则同一主密钥在不同场景会派生出相同材料。
     */
    public static final String HKDF_INFO = "ErgouTreeCrypt/EGTC-IMG/v1";

    /**
     * 完整认证标签的 MAC 输入前缀（15 字节 ASCII）。
     */
    public static final String MAC_CONTEXT = "EGTC-IMG-MAC-V1";

    /**
     * keyConfirm 的 MAC 输入前缀（21 字节 ASCII）。
     */
    public static final String KEY_CHECK_CONTEXT = "EGTC-IMG-KEY-CHECK-V1";

    // ==================== 算法标识（协议 ID，禁用枚举 ordinal） ====================

    /**
     * 内容密码算法 ID：XChaCha20（24 字节 nonce，非认证流密码）。
     */
    public static final int CIPHER_ID_XCHACHA20 = 1;

    /**
     * 完整性算法 ID：keyed BLAKE2b-512（64 字节标签）。
     */
    public static final int MAC_ID_BLAKE2B_KEYED = 1;

    /**
     * KDF 分支 ID：主密钥随文件保存（公开恢复模式）。
     */
    public static final int KDF_ID_EMBEDDED_MASTER_KEY = 0;

    /**
     * KDF 分支 ID：Argon2id 从密码派生主密钥（密码保护模式）。
     */
    public static final int KDF_ID_ARGON2ID = 1;

    // ==================== OuterHeader v1 字段偏移 ====================

    /**
     * magic 偏移（8 字节 ASCII）。
     */
    public static final int OFF_MAGIC = 0;

    /**
     * version 偏移（1 字节）。
     */
    public static final int OFF_VERSION = 8;

    /**
     * protectionMode 偏移（1 字节，0=公开恢复，1=密码保护）。
     */
    public static final int OFF_PROTECTION_MODE = 9;

    /**
     * cipherId 偏移（1 字节）。
     */
    public static final int OFF_CIPHER_ID = 10;

    /**
     * macId 偏移（1 字节）。
     */
    public static final int OFF_MAC_ID = 11;

    /**
     * kdfId 偏移（1 字节）。
     */
    public static final int OFF_KDF_ID = 12;

    /**
     * flags 偏移（1 字节）。
     */
    public static final int OFF_FLAGS = 13;

    /**
     * headerLength 偏移（2 字节大端）。
     */
    public static final int OFF_HEADER_LENGTH = 14;

    /**
     * canvasWidth 偏移（4 字节大端，必须等于 PNG IHDR）。
     */
    public static final int OFF_CANVAS_WIDTH = 16;

    /**
     * canvasHeight 偏移（4 字节大端，必须等于 PNG IHDR）。
     */
    public static final int OFF_CANVAS_HEIGHT = 20;

    /**
     * innerPlainLength 偏移（8 字节大端）。
     */
    public static final int OFF_INNER_PLAIN_LENGTH = 24;

    /**
     * ciphertextLength 偏移（8 字节大端，v1 等于 innerPlainLength）。
     */
    public static final int OFF_CIPHERTEXT_LENGTH = 32;

    /**
     * sourceWidthHint 偏移（4 字节大端，未知为 0）。
     */
    public static final int OFF_SOURCE_WIDTH_HINT = 40;

    /**
     * sourceHeightHint 偏移（4 字节大端，未知为 0）。
     */
    public static final int OFF_SOURCE_HEIGHT_HINT = 44;

    /**
     * argon2MemoryKiB 偏移（4 字节大端）。
     */
    public static final int OFF_ARGON2_MEMORY_KIB = 48;

    /**
     * argon2Passes 偏移（4 字节大端）。
     */
    public static final int OFF_ARGON2_PASSES = 52;

    /**
     * argon2Lanes 偏移（2 字节大端）。
     */
    public static final int OFF_ARGON2_LANES = 56;

    /**
     * reserved 偏移（2 字节大端，必须为 0）。
     */
    public static final int OFF_RESERVED = 58;

    /**
     * argon2Salt 偏移（16 字节）。
     */
    public static final int OFF_ARGON2_SALT = 60;

    /**
     * hkdfSalt 偏移（32 字节，每文件随机）。
     */
    public static final int OFF_HKDF_SALT = 76;

    /**
     * nonce 偏移（24 字节，每文件随机）。
     */
    public static final int OFF_NONCE = 108;

    /**
     * embeddedMasterKey 偏移（32 字节，仅公开恢复模式使用）。
     */
    public static final int OFF_EMBEDDED_MASTER_KEY = 132;

    /**
     * keyConfirm 偏移（16 字节截断 MAC）。
     */
    public static final int OFF_KEY_CONFIRM = 164;

    /**
     * headerCrc32 偏移（4 字节大端）。
     */
    public static final int OFF_HEADER_CRC32 = 180;

    /**
     * OuterHeader v1 的固定总长度（字节）。v1 reader 必须要求 headerLength 等于该值。
     */
    public static final int OUTER_HEADER_LENGTH = 184;

    /**
     * 完整认证标签覆盖的头字节数：{@code [0, 180)}，即除 headerCrc32 外的全部头字段。
     */
    public static final int MAC_COVERED_HEADER_LENGTH = 180;

    /**
     * keyConfirm 覆盖的头字节数：{@code [0, 164)}，即除 keyConfirm 与 headerCrc32 外的字段。
     */
    public static final int KEY_CONFIRM_COVERED_HEADER_LENGTH = 164;

    // ==================== PNG 外层容器 ====================

    /**
     * PNG 每个像素承载的逻辑字节数：R、G、B 各 1 字节。
     */
    public static final int PNG_BYTES_PER_PIXEL = 3;

    /**
     * PNG IHDR 的固定长度（字节）。
     */
    public static final int PNG_IHDR_LENGTH = 13;

    /**
     * PNG 标准 8 字节签名。
     */
    public static final byte[] PNG_SIGNATURE = {
            (byte) 0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a
    };

    /**
     * v1 外层 PNG 位深，固定为 8-bit。
     */
    public static final int PNG_BIT_DEPTH = 8;

    /**
     * v1 外层 PNG 颜色类型，固定为 2（RGB truecolour）。
     */
    public static final int PNG_COLOR_TYPE_RGB = 2;

    /**
     * v1 外层 PNG 压缩方法，固定为 zlib/deflate 方法 0。
     */
    public static final int PNG_COMPRESSION_METHOD = 0;

    /**
     * v1 外层 PNG 过滤方法，固定为自适应过滤方法 0。
     */
    public static final int PNG_FILTER_METHOD = 0;

    /**
     * v1 外层 PNG 隔行方法，固定为非隔行 0。
     */
    public static final int PNG_INTERLACE_NONE = 0;

    /**
     * writer 的默认 IDAT 数据块大小（字节）。
     *
     * <p>分块位置不属于跨端相等条件；该值只限制工作内存并避免产生过多小块。
     */
    public static final int PNG_IDAT_CHUNK_BYTES = 1 << 20;

    // ==================== flags 位定义 ====================

    /**
     * bit0：头部携带 keyConfirm。v1 writer 恒置位，v1 reader 必须要求置位。
     */
    public static final int FLAG_KEY_CONFIRM = 0x01;

    /**
     * bit1：头部携带原图尺寸提示。
     */
    public static final int FLAG_SOURCE_SIZE_HINT = 0x02;

    /**
     * v1 已定义的 flags 掩码。读取时其余位必须为 0。
     */
    public static final int FLAG_KNOWN_MASK = FLAG_KEY_CONFIRM | FLAG_SOURCE_SIZE_HINT;

    // ==================== 固定长度字段 ====================

    /**
     * Argon2id salt 长度（字节）。
     */
    public static final int ARGON2_SALT_LENGTH = 16;

    /**
     * HKDF salt 长度（字节）。
     */
    public static final int HKDF_SALT_LENGTH = 32;

    /**
     * XChaCha20 nonce 长度（字节）。
     */
    public static final int NONCE_LENGTH = 24;

    /**
     * 主密钥长度（字节）。
     */
    public static final int MASTER_KEY_LENGTH = 32;

    /**
     * keyConfirm 长度（字节）。
     */
    public static final int KEY_CONFIRM_LENGTH = 16;

    /**
     * 完整认证标签长度（字节）。
     */
    public static final int AUTH_TAG_LENGTH = 64;

    /**
     * HKDF 派生的加密子密钥长度（字节）。
     */
    public static final int ENC_KEY_LENGTH = 32;

    /**
     * HKDF 派生的 MAC 子密钥长度（字节）。
     */
    public static final int MAC_KEY_LENGTH = 32;

    /**
     * HKDF 单次展开的总长度（字节）：加密子密钥 + MAC 子密钥。
     */
    public static final int KEY_MATERIAL_LENGTH = ENC_KEY_LENGTH + MAC_KEY_LENGTH;

    // ==================== 密码模式 Argon2id 互操作档（规范性固定值） ====================

    /**
     * v1 固定的 Argon2id 内存参数（KiB）。等于 RFC 9106 的 64 MiB 内存受限推荐值。
     *
     * <p>不可提供桌面专属高内存档：任一端写出另一端无法承受的档位会直接破坏
     * "任意端生成、任意端恢复"的硬约束。
     */
    public static final int ARGON2_MEMORY_KIB = 65_536;

    /**
     * v1 固定的 Argon2id 迭代次数。
     */
    public static final int ARGON2_PASSES = 3;

    /**
     * v1 固定的 Argon2id lane 并行度。
     */
    public static final int ARGON2_LANES = 4;

    /**
     * v1 固定的 Argon2id 输出长度（字节）。
     */
    public static final int ARGON2_OUTPUT_LENGTH = 32;

    // ==================== InnerManifest v1 ====================

    /**
     * InnerManifest 固定描述区长度（字节）：魔数 8 + 版本 1 + 格式 1 + flags 2 +
     * 描述长度 4 + 原文件长度 8 + 名称长度 2 + MIME 长度 1 + 扩展名长度 1。
     */
    public static final int INNER_MANIFEST_FIXED_LENGTH = 28;

    /**
     * InnerManifest flags bit0：原文件为动画/多帧内容。
     */
    public static final int INNER_FLAG_ANIMATED = 0x01;

    /**
     * InnerManifest flags bit1：原文件为多页内容（v1 未使用，为 Phase 2 预留）。
     */
    public static final int INNER_FLAG_MULTI_PAGE = 0x02;

    /**
     * InnerManifest flags bit2：清单携带原始文件名。
     */
    public static final int INNER_FLAG_HAS_NAME = 0x04;

    /**
     * InnerManifest 已定义的 flags 掩码。读取时其余位必须为 0。
     */
    public static final int INNER_FLAG_KNOWN_MASK =
            INNER_FLAG_ANIMATED | INNER_FLAG_MULTI_PAGE | INNER_FLAG_HAS_NAME;

    // ==================== 硬上限 ====================

    /**
     * InnerManifest 描述区（不含原文件载荷）的字节上限：64 KiB。
     */
    public static final int LIMIT_MANIFEST_BYTES = 64 * 1024;

    /**
     * 原始文件名（basename）的 UTF-8 字节上限。
     */
    public static final int LIMIT_NAME_BYTES = 1024;

    /**
     * MIME 类型文本的字节上限。
     */
    public static final int LIMIT_MIME_BYTES = 127;

    /**
     * 规范化扩展名的字节上限。
     */
    public static final int LIMIT_EXTENSION_BYTES = 16;

    /**
     * 单边画布像素上限。
     *
     * <p>8192 × 8192 RGB 可承载约 192 MiB 载荷，但普通查看器解码为 ARGB_8888 时
     * 可能需要约 256 MiB，因此产品级推荐上限另见 {@link #RECOMMENDED_MAX_INPUT_BYTES}。
     */
    public static final int LIMIT_CANVAS_SIDE = 8192;

    /**
     * 密码 UTF-8 字节上限，避免超长粘贴文本进入 KDF。
     */
    public static final int LIMIT_PASSWORD_BYTES = 1024;

    /**
     * MVP 产品级推荐输入上限：64 MiB。超出应引导使用通用文件加密。
     */
    public static final long RECOMMENDED_MAX_INPUT_BYTES = 64L << 20;

    private ImageCryptProtocol() {
    }

    /**
     * 判断给定字节偏移处是否为 EGTC-IMG 外层魔数。
     *
     * <p>该方法只比较 ASCII 魔数本身，不做任何长度以外的解释，供上层做轻量探测。
     *
     * @param data   字节数组
     * @param offset 起始偏移
     * @return true 表示该处为 {@link #MAGIC}
     */
    public static boolean hasMagicAt(final byte[] data, final int offset) {
        if (data == null || offset < 0 || offset + MAGIC.length() > data.length) {
            return false;
        }
        for (int i = 0; i < MAGIC.length(); i++) {
            if ((data[offset + i] & 0xff) != MAGIC.charAt(i)) {
                return false;
            }
        }
        return true;
    }

    /**
     * 计算外层头声明的画布可承载的最大载荷字节数。
     *
     * <p>使用 {@link Math#multiplyExact(long, long)} 做饱和溢出保护：任一维度非法或
     * 乘积溢出时返回 0，调用方据此判定容量不足，而不会分配内存或出现整型回绕。
     *
     * @param canvasWidth  画布宽度（像素）
     * @param canvasHeight 画布高度（像素）
     * @return 可用载荷字节数；维度非法或溢出时返回 0
     */
    public static long canvasCapacity(final int canvasWidth, final int canvasHeight) {
        if (canvasWidth <= 0 || canvasHeight <= 0) {
            return 0;
        }
        if (canvasWidth > LIMIT_CANVAS_SIDE || canvasHeight > LIMIT_CANVAS_SIDE) {
            return 0;
        }
        try {
            long pixels = Math.multiplyExact((long) canvasWidth, (long) canvasHeight);
            return Math.multiplyExact(pixels, (long) PNG_BYTES_PER_PIXEL);
        } catch (ArithmeticException e) {
            return 0;
        }
    }

    /**
     * 判断画布尺寸是否落在 v1 允许范围内。
     *
     * @param canvasWidth  画布宽度（像素）
     * @param canvasHeight 画布高度（像素）
     * @return true 表示两个维度都在 {@code (0, }{@link #LIMIT_CANVAS_SIDE}{@code ]} 内
     */
    public static boolean isCanvasSideValid(final int canvasWidth, final int canvasHeight) {
        return canvasWidth > 0 && canvasWidth <= LIMIT_CANVAS_SIDE
                && canvasHeight > 0 && canvasHeight <= LIMIT_CANVAS_SIDE;
    }

    /**
     * 计算容纳给定逻辑帧所需的最小画布像素数。
     *
     * <p>{@code frameBytes = headerLength + ciphertextLength + AUTH_TAG_LENGTH}，
     * {@code requiredPixels = ceil(frameBytes / 3)}。
     *
     * @param ciphertextLength 密文字节数
     * @return 所需像素数；长度非法或溢出时返回 -1
     */
    public static long requiredPixels(final long ciphertextLength) {
        if (ciphertextLength < 0) {
            return -1L;
        }
        try {
            long frameBytes = Math.addExact((long) OUTER_HEADER_LENGTH, ciphertextLength);
            frameBytes = Math.addExact(frameBytes, (long) AUTH_TAG_LENGTH);
            return (frameBytes + PNG_BYTES_PER_PIXEL - 1L) / PNG_BYTES_PER_PIXEL;
        } catch (ArithmeticException e) {
            return -1L;
        }
    }

    /**
     * 原图长宽比的裁剪区间下限：1/16。
     */
    public static final double CANVAS_RATIO_MIN = 1.0 / 16.0;

    /**
     * 原图长宽比的裁剪区间上限：16。
     */
    public static final double CANVAS_RATIO_MAX = 16.0;

    /**
     * 为给定载荷挑选外层 PNG 画布尺寸。
     *
     * <p>规则见协议规范"画布尺寸"一节：优先按原图长宽比挑选接近 {@code requiredPixels} 的矩形，
     * 长宽比先裁剪到 {@code [1/16, 16]}，避免极端长条图产生无法打开的画布；当某一维触碰
     * {@link #LIMIT_CANVAS_SIDE} 时按上限回退重算另一维。所有运算使用 {@code long} 且带显式
     * 溢出检查，因此伪造的超大载荷不会导致整数回绕或数组分配。
     *
     * <p>返回的画布保证 {@code 3 × width × height ≥ frameBytes}，因此调用方无需再做容量判定；
     * 但画布仍需由 writer 写入 IHDR，并由 reader 复核与协议头 {@code canvasWidth/Height} 一致。
     *
     * @param requiredPixels 所需像素数，来自 {@link #requiredPixels(long)}
     * @param sourceWidth    原图宽度提示，未知或非法时传 0
     * @param sourceHeight   原图高度提示，未知或非法时传 0
     * @return 二元数组 {@code [width, height]}
     * @throws ImageCryptException 载荷超过画布总容量上限
     */
    public static int[] chooseCanvasSize(final long requiredPixels, final int sourceWidth,
                                         final int sourceHeight) throws ImageCryptException {
        if (requiredPixels <= 0) {
            throw new ImageCryptException(ErrorKind.CAPACITY_INSUFFICIENT, "载荷长度非法，无法编排画布");
        }
        long maxPixels = (long) LIMIT_CANVAS_SIDE * LIMIT_CANVAS_SIDE;
        if (requiredPixels > maxPixels) {
            throw new ImageCryptException(ErrorKind.CAPACITY_INSUFFICIENT,
                    "载荷需要 " + requiredPixels + " 像素，超过画布上限 " + maxPixels);
        }

        double ratio = 1.0;
        if (sourceWidth > 0 && sourceHeight > 0) {
            ratio = (double) sourceWidth / (double) sourceHeight;
            ratio = Math.max(CANVAS_RATIO_MIN, Math.min(CANVAS_RATIO_MAX, ratio));
        }

        long width = (long) Math.ceil(Math.sqrt((double) requiredPixels * ratio));
        width = Math.max(1L, Math.min(width, LIMIT_CANVAS_SIDE));
        long height = (requiredPixels + width - 1L) / width;
        if (height > LIMIT_CANVAS_SIDE) {
            height = LIMIT_CANVAS_SIDE;
            width = (requiredPixels + height - 1L) / height;
        }
        if (width <= 0 || width > LIMIT_CANVAS_SIDE
                || height <= 0 || height > LIMIT_CANVAS_SIDE) {
            throw new ImageCryptException(ErrorKind.CAPACITY_INSUFFICIENT,
                    "无法在画布上限内编排载荷: " + requiredPixels + " 像素");
        }
        return new int[]{(int) width, (int) height};
    }
}
