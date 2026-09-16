package hbnu.project.ergoutreecrypt.imagecrypt;

import hbnu.project.ergoutreecrypt.exception.ErrorKind;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.zip.CRC32;

/**
 * EGTC-IMG v1 外层协议头（184 字节固定长度）。
 *
 * <h3>布局</h3>
 * <p>字段偏移、字节序与合法值全部来自 {@link ImageCryptProtocol}，本类只负责编解码与合法性校验，不持有任何密钥生命周期语义。
 * 所有整数为无符号语义、大端序，读取后立即扩展到 {@code long} 并检查上限，禁止依赖平台默认字节序。
 *
 * <h3>认证关系</h3>
 * <ul>
 *   <li>{@link #keyConfirmPrefixBytes()} 返回 {@code [0, 164)}，是 keyConfirm 的 MAC 输入前缀；</li>
 *   <li>{@link #authenticationPrefixBytes()} 返回 {@code [0, 180)}，是完整认证标签的头覆盖范围；</li>
 *   <li>{@code headerCrc32} 只用于在进入 KDF 或载荷处理前快速发现传输错误，<b>不纳入 MAC</b>，避免把可重算的校验值当作认证数据。</li>
 * </ul>
 *
 * <h3>不可变性</h3>
 * <p>返回 {@code byte[]} 的访问器返回内部引用以避免复制密钥材料，调用方不得修改。
 *
 * @author ErgouTree
 * @since 2026/9/15
 */
public final class ImageCryptFrame {

    /**
     * 保护模式。
     */
    private final ImageCryptMode protectionMode;

    /**
     * flags 字节。
     */
    private final int flags;

    /**
     * 画布宽度（像素），必须等于外层 PNG 的 IHDR 宽度。
     */
    private final int canvasWidth;

    /**
     * 画布高度（像素），必须等于外层 PNG 的 IHDR 高度。
     */
    private final int canvasHeight;

    /**
     * 加密封装区的明文长度（manifest 描述区 + 原文件字节）。
     */
    private final long innerPlainLength;

    /**
     * 原图宽度提示，未知为 0。
     */
    private final int sourceWidthHint;

    /**
     * 原图高度提示，未知为 0。
     */
    private final int sourceHeightHint;

    /**
     * Argon2id 内存参数（KiB）。公开恢复模式恒为 0。
     */
    private final int argon2MemoryKiB;

    /**
     * Argon2id 迭代次数。公开恢复模式恒为 0。
     */
    private final int argon2Passes;

    /**
     * Argon2id lane 并行度。公开恢复模式恒为 0。
     */
    private final int argon2Lanes;

    /**
     * Argon2id salt（16 字节）。公开恢复模式全 0。
     */
    private final byte[] argon2Salt;

    /**
     * HKDF salt（32 字节），每文件随机。
     */
    private final byte[] hkdfSalt;

    /**
     * XChaCha20 nonce（24 字节），每文件随机。
     */
    private final byte[] nonce;

    /**
     * 公开恢复模式嵌入的主密钥（32 字节）。密码保护模式全 0。
     */
    private final byte[] embeddedMasterKey;

    /**
     * keyConfirm（16 字节），未计算时为 {@code null}。
     */
    private final byte[] keyConfirm;

    /**
     * 完整构造。
     *
     * @param protectionMode    保护模式
     * @param flags             flags 字节
     * @param canvasWidth       画布宽度
     * @param canvasHeight      画布高度
     * @param innerPlainLength  加密封装区明文长度
     * @param sourceWidthHint   原图宽度提示
     * @param sourceHeightHint  原图高度提示
     * @param argon2MemoryKiB   Argon2id 内存参数（KiB）
     * @param argon2Passes      Argon2id 迭代次数
     * @param argon2Lanes       Argon2id lane 并行度
     * @param argon2Salt        Argon2id salt（16 字节）
     * @param hkdfSalt          HKDF salt（32 字节）
     * @param nonce             XChaCha20 nonce（24 字节）
     * @param embeddedMasterKey 公开模式嵌入主密钥（32 字节）
     * @param keyConfirm        keyConfirm（16 字节），可为 null
     */
    private ImageCryptFrame(final ImageCryptMode protectionMode, final int flags,
                            final int canvasWidth, final int canvasHeight,
                            final long innerPlainLength,
                            final int sourceWidthHint, final int sourceHeightHint,
                            final int argon2MemoryKiB, final int argon2Passes, final int argon2Lanes,
                            final byte[] argon2Salt, final byte[] hkdfSalt, final byte[] nonce,
                            final byte[] embeddedMasterKey, final byte[] keyConfirm) {
        this.protectionMode = protectionMode;
        this.flags = flags;
        this.canvasWidth = canvasWidth;
        this.canvasHeight = canvasHeight;
        this.innerPlainLength = innerPlainLength;
        this.sourceWidthHint = sourceWidthHint;
        this.sourceHeightHint = sourceHeightHint;
        this.argon2MemoryKiB = argon2MemoryKiB;
        this.argon2Passes = argon2Passes;
        this.argon2Lanes = argon2Lanes;
        this.argon2Salt = argon2Salt.clone();
        this.hkdfSalt = hkdfSalt.clone();
        this.nonce = nonce.clone();
        this.embeddedMasterKey = embeddedMasterKey.clone();
        this.keyConfirm = keyConfirm == null ? null : keyConfirm.clone();
    }

    // ==================== 构造 ====================

    /**
     * 构造公开恢复模式的协议头。
     *
     * <p>该模式不执行 Argon2：主密钥由 {@link ImageCryptRandomSource} 每文件随机生成，
     * 并明文写入协议头。任何拿到文件的人都能恢复，因此<b>不提供保密性</b>。
     *
     * @param canvasWidth       画布宽度（像素）
     * @param canvasHeight      画布高度（像素）
     * @param innerPlainLength  加密封装区明文长度
     * @param sourceWidthHint   原图宽度提示，未知为 0
     * @param sourceHeightHint  原图高度提示，未知为 0
     * @param hkdfSalt          HKDF salt（32 字节）
     * @param nonce             XChaCha20 nonce（24 字节）
     * @param embeddedMasterKey 随机主密钥（32 字节）
     * @return 已构造但尚未写入 keyConfirm 的协议头
     * @throws ImageCryptException 参数非法
     */
    public static ImageCryptFrame newPublicFrame(final int canvasWidth, final int canvasHeight,
                                                 final long innerPlainLength,
                                                 final int sourceWidthHint, final int sourceHeightHint,
                                                 final byte[] hkdfSalt, final byte[] nonce,
                                                 final byte[] embeddedMasterKey)
            throws ImageCryptException {
        requireLength(hkdfSalt, ImageCryptProtocol.HKDF_SALT_LENGTH, "hkdfSalt");
        requireLength(nonce, ImageCryptProtocol.NONCE_LENGTH, "nonce");
        requireLength(embeddedMasterKey, ImageCryptProtocol.MASTER_KEY_LENGTH, "embeddedMasterKey");
        if (isAllZero(embeddedMasterKey)) {
            throw new ImageCryptException(ErrorKind.INTERNAL_ERROR,
                    "公开恢复模式的嵌入主密钥不得为全零");
        }
        int flags = ImageCryptProtocol.FLAG_KEY_CONFIRM;
        int widthHint = 0;
        int heightHint = 0;
        if (sourceWidthHint > 0 && sourceHeightHint > 0) {
            flags |= ImageCryptProtocol.FLAG_SOURCE_SIZE_HINT;
            widthHint = sourceWidthHint;
            heightHint = sourceHeightHint;
        }
        ImageCryptFrame frame = new ImageCryptFrame(ImageCryptMode.PUBLIC_RECOVERY, flags,
                canvasWidth, canvasHeight, innerPlainLength, widthHint, heightHint,
                0, 0, 0,
                new byte[ImageCryptProtocol.ARGON2_SALT_LENGTH],
                hkdfSalt, nonce, embeddedMasterKey, null);
        frame.validateSelf();
        return frame;
    }

    /**
     * 构造密码保护模式的协议头。
     *
     * <p>Argon2id 参数为 v1 规范性固定值（64 MiB / 3 passes / 4 lanes），文件内不保存
     * 可恢复密钥，因此忘记密码后无法恢复。
     *
     * @param canvasWidth      画布宽度（像素）
     * @param canvasHeight     画布高度（像素）
     * @param innerPlainLength 加密封装区明文长度
     * @param sourceWidthHint  原图宽度提示，未知为 0
     * @param sourceHeightHint 原图高度提示，未知为 0
     * @param argon2Salt       Argon2id salt（16 字节）
     * @param hkdfSalt         HKDF salt（32 字节）
     * @param nonce            XChaCha20 nonce（24 字节）
     * @return 已构造但尚未写入 keyConfirm 的协议头
     * @throws ImageCryptException 参数非法
     */
    public static ImageCryptFrame newPasswordFrame(final int canvasWidth, final int canvasHeight,
                                                   final long innerPlainLength,
                                                   final int sourceWidthHint, final int sourceHeightHint,
                                                   final byte[] argon2Salt, final byte[] hkdfSalt,
                                                   final byte[] nonce)
            throws ImageCryptException {
        requireLength(argon2Salt, ImageCryptProtocol.ARGON2_SALT_LENGTH, "argon2Salt");
        requireLength(hkdfSalt, ImageCryptProtocol.HKDF_SALT_LENGTH, "hkdfSalt");
        requireLength(nonce, ImageCryptProtocol.NONCE_LENGTH, "nonce");
        int flags = ImageCryptProtocol.FLAG_KEY_CONFIRM;
        int widthHint = 0;
        int heightHint = 0;
        if (sourceWidthHint > 0 && sourceHeightHint > 0) {
            flags |= ImageCryptProtocol.FLAG_SOURCE_SIZE_HINT;
            widthHint = sourceWidthHint;
            heightHint = sourceHeightHint;
        }
        ImageCryptFrame frame = new ImageCryptFrame(ImageCryptMode.PASSWORD, flags,
                canvasWidth, canvasHeight, innerPlainLength, widthHint, heightHint,
                ImageCryptProtocol.ARGON2_MEMORY_KIB,
                ImageCryptProtocol.ARGON2_PASSES,
                ImageCryptProtocol.ARGON2_LANES,
                argon2Salt, hkdfSalt, nonce,
                new byte[ImageCryptProtocol.MASTER_KEY_LENGTH], null);
        frame.validateSelf();
        return frame;
    }

    /**
     * 在已构造的协议头上写入 keyConfirm，返回新实例。
     *
     * <p>keyConfirm 只覆盖 {@code [0, 164)}，因此不存在"先有 keyConfirm 才能算 keyConfirm"
     * 的循环依赖；而 headerCrc32 在 {@link #toBytes()} 时才计算，覆盖写入 keyConfirm 之后的
     * {@code [0, 180)}。
     *
     * @param keyConfirm 16 字节 keyConfirm
     * @return 带 keyConfirm 的新协议头
     * @throws ImageCryptException 长度非法
     */
    public ImageCryptFrame withKeyConfirm(final byte[] keyConfirm) throws ImageCryptException {
        requireLength(keyConfirm, ImageCryptProtocol.KEY_CONFIRM_LENGTH, "keyConfirm");
        return new ImageCryptFrame(protectionMode, flags, canvasWidth, canvasHeight,
                innerPlainLength, sourceWidthHint, sourceHeightHint,
                argon2MemoryKiB, argon2Passes, argon2Lanes,
                argon2Salt, hkdfSalt, nonce, embeddedMasterKey, keyConfirm);
    }

    // ==================== 编解码 ====================

    /**
     * 序列化为 184 字节协议头，并把 headerCrc32 写入末尾。
     *
     * @return 184 字节大端序协议头
     * @throws ImageCryptException keyConfirm 尚未写入
     */
    public byte[] toBytes() throws ImageCryptException {
        if (keyConfirm == null) {
            throw new ImageCryptException(ErrorKind.INTERNAL_ERROR,
                    "写出协议头前必须先写入 keyConfirm");
        }
        ByteBuffer buffer = ByteBuffer.allocate(ImageCryptProtocol.OUTER_HEADER_LENGTH)
                .order(ByteOrder.BIG_ENDIAN);
        buffer.put(ImageCryptProtocol.MAGIC.getBytes(StandardCharsets.US_ASCII));
        buffer.put((byte) ImageCryptProtocol.VERSION);
        buffer.put((byte) protectionMode.id());
        buffer.put((byte) cipherId());
        buffer.put((byte) macId());
        buffer.put((byte) kdfId());
        buffer.put((byte) flags);
        buffer.putShort((short) ImageCryptProtocol.OUTER_HEADER_LENGTH);
        buffer.putInt(canvasWidth);
        buffer.putInt(canvasHeight);
        buffer.putLong(innerPlainLength);
        buffer.putLong(ciphertextLength());
        buffer.putInt(sourceWidthHint);
        buffer.putInt(sourceHeightHint);
        buffer.putInt(argon2MemoryKiB);
        buffer.putInt(argon2Passes);
        buffer.putShort((short) argon2Lanes);
        buffer.putShort((short) 0);
        buffer.put(argon2Salt);
        buffer.put(hkdfSalt);
        buffer.put(nonce);
        buffer.put(embeddedMasterKey);
        buffer.put(keyConfirm);
        buffer.putInt(0);

        byte[] raw = buffer.array();
        int crc = crc32Of(raw, ImageCryptProtocol.MAC_COVERED_HEADER_LENGTH);
        ByteBuffer.wrap(raw)
                .order(ByteOrder.BIG_ENDIAN)
                .putInt(ImageCryptProtocol.OFF_HEADER_CRC32, crc);
        return raw;
    }

    /**
     * 解析并校验 184 字节协议头。
     *
     * <p>校验顺序刻意把"便宜且能快速失败"的检查放在前面：长度 → magic → 版本 → 算法 ID →
     * flags → Reserved → CRC → 数值范围 → 画布容量。任何一项不合法都抛出分类异常，不尝试猜测。
     *
     * @param raw 协议头字节
     * @return 解析结果
     * @throws ImageCryptException 长度不符、魔数不符、版本/ID/flags 未知、CRC 错误或字段越界
     */
    public static ImageCryptFrame fromBytes(final byte[] raw) throws ImageCryptException {
        if (raw == null || raw.length != ImageCryptProtocol.OUTER_HEADER_LENGTH) {
            throw new ImageCryptException(ErrorKind.INVALID_HEADER,
                    "EGTC-IMG 头部长度必须为 " + ImageCryptProtocol.OUTER_HEADER_LENGTH
                            + " 字节，实际 " + (raw == null ? "null" : raw.length));
        }
        if (!ImageCryptProtocol.hasMagicAt(raw, ImageCryptProtocol.OFF_MAGIC)) {
            throw new ImageCryptException(ErrorKind.NOT_IMAGE_CRYPT,
                    "未检测到 EGTC-IMG 协议魔数");
        }

        ByteBuffer buffer = ByteBuffer.wrap(raw).order(ByteOrder.BIG_ENDIAN);
        int version = raw[ImageCryptProtocol.OFF_VERSION] & 0xff;
        if (version != ImageCryptProtocol.VERSION) {
            throw new ImageCryptException(ErrorKind.UNSUPPORTED_VERSION,
                    "不支持的 EGTC-IMG 协议版本: " + version);
        }

        int protectionModeId = raw[ImageCryptProtocol.OFF_PROTECTION_MODE] & 0xff;
        if (!ImageCryptMode.isKnownId(protectionModeId)) {
            throw new ImageCryptException(ErrorKind.INVALID_HEADER,
                    "未知的 protectionMode: " + protectionModeId);
        }
        ImageCryptMode mode = ImageCryptMode.fromId(protectionModeId);

        int cipherId = raw[ImageCryptProtocol.OFF_CIPHER_ID] & 0xff;
        if (cipherId != ImageCryptProtocol.CIPHER_ID_XCHACHA20) {
            throw new ImageCryptException(ErrorKind.INVALID_HEADER, "未知的 cipherId: " + cipherId);
        }
        int macId = raw[ImageCryptProtocol.OFF_MAC_ID] & 0xff;
        if (macId != ImageCryptProtocol.MAC_ID_BLAKE2B_KEYED) {
            throw new ImageCryptException(ErrorKind.INVALID_HEADER, "未知的 macId: " + macId);
        }
        int kdfId = raw[ImageCryptProtocol.OFF_KDF_ID] & 0xff;
        int expectedKdfId = mode == ImageCryptMode.PASSWORD
                ? ImageCryptProtocol.KDF_ID_ARGON2ID
                : ImageCryptProtocol.KDF_ID_EMBEDDED_MASTER_KEY;
        if (kdfId != expectedKdfId) {
            throw new ImageCryptException(ErrorKind.INVALID_HEADER,
                    "kdfId 与 protectionMode 不一致: kdfId=" + kdfId + ", mode=" + mode);
        }

        int flags = raw[ImageCryptProtocol.OFF_FLAGS] & 0xff;
        if ((flags & ~ImageCryptProtocol.FLAG_KNOWN_MASK) != 0) {
            throw new ImageCryptException(ErrorKind.INVALID_HEADER,
                    "存在 v1 未定义的 flags 位: 0x" + Integer.toHexString(flags));
        }
        if ((flags & ImageCryptProtocol.FLAG_KEY_CONFIRM) == 0) {
            throw new ImageCryptException(ErrorKind.INVALID_HEADER, "v1 头部必须携带 keyConfirm");
        }

        int headerLength = buffer.getShort(ImageCryptProtocol.OFF_HEADER_LENGTH) & 0xffff;
        if (headerLength != ImageCryptProtocol.OUTER_HEADER_LENGTH) {
            throw new ImageCryptException(ErrorKind.INVALID_HEADER,
                    "v1 headerLength 必须为 " + ImageCryptProtocol.OUTER_HEADER_LENGTH
                            + "，实际 " + headerLength);
        }

        int reserved = buffer.getShort(ImageCryptProtocol.OFF_RESERVED) & 0xffff;
        if (reserved != 0) {
            throw new ImageCryptException(ErrorKind.INVALID_HEADER, "保留字段必须为 0");
        }

        int expectedCrc = crc32Of(raw, ImageCryptProtocol.MAC_COVERED_HEADER_LENGTH);
        int actualCrc = buffer.getInt(ImageCryptProtocol.OFF_HEADER_CRC32);
        if (expectedCrc != actualCrc) {
            throw new ImageCryptException(ErrorKind.INVALID_HEADER, "协议头 CRC32 校验失败");
        }

        int canvasWidth = buffer.getInt(ImageCryptProtocol.OFF_CANVAS_WIDTH);
        int canvasHeight = buffer.getInt(ImageCryptProtocol.OFF_CANVAS_HEIGHT);
        long innerPlainLength = buffer.getLong(ImageCryptProtocol.OFF_INNER_PLAIN_LENGTH);
        long ciphertextLength = buffer.getLong(ImageCryptProtocol.OFF_CIPHERTEXT_LENGTH);
        int sourceWidthHint = buffer.getInt(ImageCryptProtocol.OFF_SOURCE_WIDTH_HINT);
        int sourceHeightHint = buffer.getInt(ImageCryptProtocol.OFF_SOURCE_HEIGHT_HINT);

        if ((flags & ImageCryptProtocol.FLAG_SOURCE_SIZE_HINT) == 0) {
            if (sourceWidthHint != 0 || sourceHeightHint != 0) {
                throw new ImageCryptException(ErrorKind.INVALID_HEADER,
                        "未置位尺寸提示标志时 sourceWidthHint/sourceHeightHint 必须为 0");
            }
        } else if (sourceWidthHint <= 0 || sourceHeightHint <= 0) {
            throw new ImageCryptException(ErrorKind.INVALID_HEADER,
                    "置位尺寸提示标志时原图宽高必须为正");
        }

        if (innerPlainLength < 0 || ciphertextLength < 0) {
            throw new ImageCryptException(ErrorKind.INVALID_HEADER, "载荷长度不得为负");
        }
        if (innerPlainLength != ciphertextLength) {
            throw new ImageCryptException(ErrorKind.INVALID_HEADER,
                    "v1 要求 innerPlainLength 等于 ciphertextLength");
        }

        byte[] argon2Salt = slice(raw, ImageCryptProtocol.OFF_ARGON2_SALT,
                ImageCryptProtocol.ARGON2_SALT_LENGTH);
        byte[] hkdfSalt = slice(raw, ImageCryptProtocol.OFF_HKDF_SALT,
                ImageCryptProtocol.HKDF_SALT_LENGTH);
        byte[] nonce = slice(raw, ImageCryptProtocol.OFF_NONCE, ImageCryptProtocol.NONCE_LENGTH);
        byte[] embeddedMasterKey = slice(raw, ImageCryptProtocol.OFF_EMBEDDED_MASTER_KEY,
                ImageCryptProtocol.MASTER_KEY_LENGTH);
        byte[] keyConfirm = slice(raw, ImageCryptProtocol.OFF_KEY_CONFIRM,
                ImageCryptProtocol.KEY_CONFIRM_LENGTH);

        int argon2MemoryKiB = buffer.getInt(ImageCryptProtocol.OFF_ARGON2_MEMORY_KIB);
        int argon2Passes = buffer.getInt(ImageCryptProtocol.OFF_ARGON2_PASSES);
        int argon2Lanes = buffer.getShort(ImageCryptProtocol.OFF_ARGON2_LANES) & 0xffff;

        ImageCryptFrame frame = new ImageCryptFrame(mode, flags, canvasWidth, canvasHeight,
                innerPlainLength, sourceWidthHint, sourceHeightHint,
                argon2MemoryKiB, argon2Passes, argon2Lanes,
                argon2Salt, hkdfSalt, nonce, embeddedMasterKey, keyConfirm);
        frame.validateSelf();
        return frame;
    }

    /**
     * 校验当前实例的字段组合是否落在 v1 规范性配置内。
     *
     * @throws ImageCryptException 画布越界、容量不足或 KDF 字段组合非规范
     */
    private void validateSelf() throws ImageCryptException {
        if (!ImageCryptProtocol.isCanvasSideValid(canvasWidth, canvasHeight)) {
            throw new ImageCryptException(ErrorKind.INVALID_HEADER,
                    "画布尺寸越界: " + canvasWidth + "x" + canvasHeight);
        }
        if (innerPlainLength < 0) {
            throw new ImageCryptException(ErrorKind.INVALID_HEADER, "载荷长度不得为负");
        }
        long required;
        try {
            required = Math.addExact((long) ImageCryptProtocol.OUTER_HEADER_LENGTH, ciphertextLength());
            required = Math.addExact(required, (long) ImageCryptProtocol.AUTH_TAG_LENGTH);
        } catch (ArithmeticException e) {
            throw new ImageCryptException(ErrorKind.INVALID_HEADER, "载荷长度溢出", e);
        }
        long capacity = ImageCryptProtocol.canvasCapacity(canvasWidth, canvasHeight);
        if (capacity < required) {
            throw new ImageCryptException(ErrorKind.INVALID_HEADER,
                    "画布容量不足: 需要 " + required + " 字节，画布仅可承载 " + capacity + " 字节");
        }
        validateKdfFields();
    }

    /**
     * 校验 KDF 相关字段是否与保护模式匹配。
     *
     * <p>v1 密码模式只接受 {@code 65,536 KiB / 3 passes / 4 lanes} 这一组跨端互操作档；
     * 其余组合一律拒绝，避免桌面写出移动端无法承受的参数。公开模式对应字段必须全为 0。
     *
     * @throws ImageCryptException 非规范组合
     */
    private void validateKdfFields() throws ImageCryptException {
        if (protectionMode == ImageCryptMode.PUBLIC_RECOVERY) {
            if (argon2MemoryKiB != 0 || argon2Passes != 0 || argon2Lanes != 0) {
                throw new ImageCryptException(ErrorKind.INVALID_HEADER,
                        "公开恢复模式的 Argon2 参数字段必须全为 0");
            }
            if (!isAllZero(argon2Salt)) {
                throw new ImageCryptException(ErrorKind.INVALID_HEADER,
                        "公开恢复模式的 argon2Salt 必须全为 0");
            }
            if (isAllZero(embeddedMasterKey)) {
                throw new ImageCryptException(ErrorKind.INVALID_HEADER,
                        "公开恢复模式的嵌入主密钥不得为全零");
            }
            return;
        }
        if (argon2MemoryKiB != ImageCryptProtocol.ARGON2_MEMORY_KIB
                || argon2Passes != ImageCryptProtocol.ARGON2_PASSES
                || argon2Lanes != ImageCryptProtocol.ARGON2_LANES) {
            throw new ImageCryptException(ErrorKind.INVALID_HEADER,
                    "v1 密码模式只接受 Argon2id " + ImageCryptProtocol.ARGON2_MEMORY_KIB
                            + " KiB / " + ImageCryptProtocol.ARGON2_PASSES + " passes / "
                            + ImageCryptProtocol.ARGON2_LANES + " lanes");
        }
        if (isAllZero(argon2Salt)) {
            throw new ImageCryptException(ErrorKind.INVALID_HEADER, "密码模式的 argon2Salt 不得全为 0");
        }
        if (!isAllZero(embeddedMasterKey)) {
            throw new ImageCryptException(ErrorKind.INVALID_HEADER,
                    "密码保护模式的 embeddedMasterKey 必须全为 0");
        }
    }

    // ==================== 认证输入构造 ====================

    /**
     * 返回 keyConfirm 的 MAC 输入前缀，即协议头 {@code [0, 164)}。
     *
     * @return 164 字节前缀
     */
    public byte[] keyConfirmPrefixBytes() {
        return slice(serializeForPrefix(), 0, ImageCryptProtocol.KEY_CONFIRM_COVERED_HEADER_LENGTH);
    }

    /**
     * 返回完整认证标签的头覆盖范围，即协议头 {@code [0, 180)}（不含 headerCrc32）。
     *
     * <p>该范围包含 keyConfirm，因此必须在 {@link #withKeyConfirm(byte[])} 之后调用；
     * 提前调用会以零值冒充 keyConfirm，让计算出的标签永远无法通过校验，这里直接快速失败。
     *
     * @return 180 字节前缀
     * @throws ImageCryptException keyConfirm 尚未写入
     */
    public byte[] authenticationPrefixBytes() throws ImageCryptException {
        if (keyConfirm == null) {
            throw new ImageCryptException(ErrorKind.INTERNAL_ERROR,
                    "计算认证前缀前必须先写入 keyConfirm");
        }
        return slice(serializeForPrefix(), 0, ImageCryptProtocol.MAC_COVERED_HEADER_LENGTH);
    }

    /**
     * 序列化不含 headerCrc32 的前缀区，供认证输入构造使用。
     *
     * <p>写出 {@code [0, 180)}：keyConfirm 已写入时同样落在其中，因为它是被认证的字段；
     * 只有 headerCrc32 被排除在外。keyConfirm 尚未写入时该区段保持为零，此时
     * {@link #keyConfirmPrefixBytes()} 仍可取到正确的 {@code [0, 164)} 前缀。
     *
     * @return 184 字节缓冲区，{@code [180, 184)} 区段为零
     */
    private byte[] serializeForPrefix() {
        byte[] raw = new byte[ImageCryptProtocol.OUTER_HEADER_LENGTH];
        ByteBuffer buffer = ByteBuffer.wrap(raw).order(ByteOrder.BIG_ENDIAN);
        buffer.put(ImageCryptProtocol.MAGIC.getBytes(StandardCharsets.US_ASCII));
        buffer.put((byte) ImageCryptProtocol.VERSION);
        buffer.put((byte) protectionMode.id());
        buffer.put((byte) cipherId());
        buffer.put((byte) macId());
        buffer.put((byte) kdfId());
        buffer.put((byte) flags);
        buffer.putShort((short) ImageCryptProtocol.OUTER_HEADER_LENGTH);
        buffer.putInt(canvasWidth);
        buffer.putInt(canvasHeight);
        buffer.putLong(innerPlainLength);
        buffer.putLong(ciphertextLength());
        buffer.putInt(sourceWidthHint);
        buffer.putInt(sourceHeightHint);
        buffer.putInt(argon2MemoryKiB);
        buffer.putInt(argon2Passes);
        buffer.putShort((short) argon2Lanes);
        buffer.putShort((short) 0);
        buffer.put(argon2Salt);
        buffer.put(hkdfSalt);
        buffer.put(nonce);
        buffer.put(embeddedMasterKey);
        if (keyConfirm != null) {
            buffer.put(keyConfirm);
        }
        return raw;
    }

    // ==================== 访问器 ====================

    /**
     * 返回保护模式。
     *
     * @return 保护模式
     */
    public ImageCryptMode protectionMode() {
        return protectionMode;
    }

    /**
     * 返回内容密码算法 ID。
     *
     * @return 固定为 {@link ImageCryptProtocol#CIPHER_ID_XCHACHA20}
     */
    public int cipherId() {
        return ImageCryptProtocol.CIPHER_ID_XCHACHA20;
    }

    /**
     * 返回完整性算法 ID。
     *
     * @return 固定为 {@link ImageCryptProtocol#MAC_ID_BLAKE2B_KEYED}
     */
    public int macId() {
        return ImageCryptProtocol.MAC_ID_BLAKE2B_KEYED;
    }

    /**
     * 返回 KDF 分支 ID。
     *
     * @return 密码模式为 Argon2id，公开模式为嵌入主密钥
     */
    public int kdfId() {
        return protectionMode == ImageCryptMode.PASSWORD
                ? ImageCryptProtocol.KDF_ID_ARGON2ID
                : ImageCryptProtocol.KDF_ID_EMBEDDED_MASTER_KEY;
    }

    /**
     * 返回 flags 字节。
     *
     * @return flags
     */
    public int flags() {
        return flags;
    }

    /**
     * 返回画布宽度。
     *
     * @return 像素宽度
     */
    public int canvasWidth() {
        return canvasWidth;
    }

    /**
     * 返回画布高度。
     *
     * @return 像素高度
     */
    public int canvasHeight() {
        return canvasHeight;
    }

    /**
     * 返回加密封装区明文长度。
     *
     * @return 字节数
     */
    public long innerPlainLength() {
        return innerPlainLength;
    }

    /**
     * 返回密文长度。v1 恒等于 {@link #innerPlainLength()}。
     *
     * @return 字节数
     */
    public long ciphertextLength() {
        return innerPlainLength;
    }

    /**
     * 返回原图宽度提示。
     *
     * @return 像素宽度；未知为 0
     */
    public int sourceWidthHint() {
        return sourceWidthHint;
    }

    /**
     * 返回原图高度提示。
     *
     * @return 像素高度；未知为 0
     */
    public int sourceHeightHint() {
        return sourceHeightHint;
    }

    /**
     * 返回 Argon2id 内存参数。
     *
     * @return KiB；公开模式为 0
     */
    public int argon2MemoryKiB() {
        return argon2MemoryKiB;
    }

    /**
     * 返回 Argon2id 迭代次数。
     *
     * @return 迭代次数；公开模式为 0
     */
    public int argon2Passes() {
        return argon2Passes;
    }

    /**
     * 返回 Argon2id lane 并行度。
     *
     * @return lane 数；公开模式为 0
     */
    public int argon2Lanes() {
        return argon2Lanes;
    }

    /**
     * 返回 Argon2id salt（内部引用，请勿修改）。
     *
     * @return 16 字节 salt
     */
    public byte[] argon2Salt() {
        return argon2Salt;
    }

    /**
     * 返回 HKDF salt（内部引用，请勿修改）。
     *
     * @return 32 字节 salt
     */
    public byte[] hkdfSalt() {
        return hkdfSalt;
    }

    /**
     * 返回 XChaCha20 nonce（内部引用，请勿修改）。
     *
     * @return 24 字节 nonce
     */
    public byte[] nonce() {
        return nonce;
    }

    /**
     * 返回嵌入主密钥（内部引用，请勿修改）。
     *
     * @return 公开模式为 32 字节随机密钥，密码模式为 32 个零字节
     */
    public byte[] embeddedMasterKey() {
        return embeddedMasterKey;
    }

    /**
     * 返回 keyConfirm（内部引用，请勿修改）。
     *
     * @return 16 字节；尚未写入时为 {@code null}
     */
    public byte[] keyConfirm() {
        return keyConfirm;
    }

    /**
     * 返回不含敏感材料的诊断描述。
     *
     * <p>刻意不输出 nonce、salt 与主密钥，避免密钥材料进入日志。
     *
     * @return 可安全写入日志的描述
     */
    @Override
    public String toString() {
        return "ImageCryptFrame{mode=" + protectionMode
                + ", canvas=" + canvasWidth + "x" + canvasHeight
                + ", innerPlainLength=" + innerPlainLength
                + ", sourceHint=" + sourceWidthHint + "x" + sourceHeightHint
                + ", argon2=" + argon2MemoryKiB + "KiB/" + argon2Passes + "p/" + argon2Lanes + "l"
                + ", keyConfirm=" + (keyConfirm == null ? "未写入" : "已写入") + '}';
    }

    // ==================== 工具方法 ====================

    /**
     * 计算字节数组指定前缀的 CRC32。
     *
     * @param data   字节数组
     * @param length 参与计算的字节数
     * @return CRC32 值
     */
    private static int crc32Of(final byte[] data, final int length) {
        CRC32 crc = new CRC32();
        crc.update(data, 0, length);
        return (int) crc.getValue();
    }

    /**
     * 复制字节数组的指定区段。
     *
     * @param source 源数组
     * @param offset 起始偏移
     * @param length 长度
     * @return 新数组
     */
    private static byte[] slice(final byte[] source, final int offset, final int length) {
        return Arrays.copyOfRange(source, offset, offset + length);
    }

    /**
     * 判断字节数组是否全为 0。
     *
     * @param data 字节数组
     * @return true 表示全为 0
     */
    private static boolean isAllZero(final byte[] data) {
        for (byte b : data) {
            if (b != 0) {
                return false;
            }
        }
        return true;
    }

    /**
     * 校验字节数组长度。
     *
     * @param data     字节数组
     * @param expected 期望长度
     * @param name     字段名（用于诊断消息）
     * @throws ImageCryptException 长度不符
     */
    private static void requireLength(final byte[] data, final int expected, final String name)
            throws ImageCryptException {
        if (data == null || data.length != expected) {
            throw new ImageCryptException(ErrorKind.INTERNAL_ERROR,
                    name + " 长度必须为 " + expected + " 字节");
        }
    }
}
