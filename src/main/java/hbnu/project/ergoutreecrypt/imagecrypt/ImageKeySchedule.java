package hbnu.project.ergoutreecrypt.imagecrypt;

import hbnu.project.ergoutreecrypt.crypto.Argon2Kdf;
import hbnu.project.ergoutreecrypt.crypto.HkdfStream;
import hbnu.project.ergoutreecrypt.crypto.KdfProgress;
import hbnu.project.ergoutreecrypt.crypto.Mac;
import hbnu.project.ergoutreecrypt.crypto.MacFactory;
import hbnu.project.ergoutreecrypt.crypto.SecureZero;
import hbnu.project.ergoutreecrypt.exception.ErrorKind;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;

/**
 * EGTC-IMG 的密钥编排与认证标签构造。
 *
 * <h3>密钥编排</h3>
 * <pre>
 *   公开恢复：masterKey = SecureRandom(32)，随协议头保存
 *   密码保护：masterKey = Argon2id(密码, argon2Salt, 65536 KiB, 3 passes, 4 lanes, 32B)
 *
 *   keyMaterial = HKDF-SHA3-256(IKM = masterKey,
 *                               salt = hkdfSalt,
 *                               info = "ErgouTreeCrypt/EGTC-IMG/v1")
 *   encKey = keyMaterial[0..31]    （XChaCha20）
 *   macKey = keyMaterial[32..63]   （keyed BLAKE2b-512）
 * </pre>
 *
 * <p>HKDF 的 info 必须绑定到图片协议域：直接复用媒体协议的空 info 会让同一主密钥在
 * 不同场景派生出相同材料。两条分支之后完全相同，因此解密端只依赖文件头中的
 * {@code protectionMode} 与 KDF 参数即可复现。
 *
 * <h3>KDF 参数是规范性固定值</h3>
 * <p>v1 密码模式只使用 {@link ImageCryptProtocol#ARGON2_MEMORY_KIB} /
 * {@link ImageCryptProtocol#ARGON2_PASSES} / {@link ImageCryptProtocol#ARGON2_LANES}。
 * 全局移动端 Argon2 档位<b>不</b>参与本协议：档位差异会直接破坏"所有产物都可跨端"的承诺。
 * 若 64 MiB 在当前设备上无法完成，只会明确报告资源不足，而不会降档后产生另一把密钥。
 *
 * <h3>生命周期</h3>
 * <p>本类实现 {@link AutoCloseable}，{@link #close()} 清零全部派生密钥；务必以
 * try-with-resources 使用。密码与主密钥的生命周期由调用方负责。
 *
 * @author ErgouTree
 * @since 2026/9/15
 */
public final class ImageKeySchedule implements AutoCloseable {

    /**
     * HKDF info 的 ASCII 字节，避免每次派生都重新编码。
     */
    private static final byte[] HKDF_INFO_BYTES =
            ImageCryptProtocol.HKDF_INFO.getBytes(StandardCharsets.US_ASCII);

    /**
     * MAC 上下文前缀的 ASCII 字节。
     */
    private static final byte[] MAC_CONTEXT_BYTES =
            ImageCryptProtocol.MAC_CONTEXT.getBytes(StandardCharsets.US_ASCII);

    /**
     * keyConfirm 上下文前缀的 ASCII 字节。
     */
    private static final byte[] KEY_CHECK_CONTEXT_BYTES =
            ImageCryptProtocol.KEY_CHECK_CONTEXT.getBytes(StandardCharsets.US_ASCII);

    /**
     * XChaCha20 加密子密钥。
     */
    private final byte[] encKey;

    /**
     * 完整性 MAC 子密钥。
     */
    private final byte[] macKey;

    /**
     * 私有构造，只接受已经域分离完成的子密钥。
     *
     * @param encKey 加密子密钥（32 字节）
     * @param macKey MAC 子密钥（32 字节）
     */
    private ImageKeySchedule(final byte[] encKey, final byte[] macKey) {
        this.encKey = encKey;
        this.macKey = macKey;
    }

    // ==================== 构造 ====================

    /**
     * 由公开恢复模式的嵌入主密钥构造密钥编排。
     *
     * <p>该路径<b>不</b>调用 Argon2：公开主密钥由文件提供，任何拿到文件的人都能恢复，
     * 因此这里只做域分离，不提供也不假装提供保密性。
     *
     * @param masterKey 嵌入主密钥（32 字节）
     * @param hkdfSalt  HKDF salt（32 字节）
     * @return 密钥编排实例
     * @throws ImageCryptException 长度不符或 HKDF 失败
     */
    public static ImageKeySchedule fromPublicMasterKey(final byte[] masterKey, final byte[] hkdfSalt)
            throws ImageCryptException {
        requireLength(masterKey, ImageCryptProtocol.MASTER_KEY_LENGTH, "masterKey");
        requireLength(hkdfSalt, ImageCryptProtocol.HKDF_SALT_LENGTH, "hkdfSalt");
        return deriveFromMasterKey(masterKey, hkdfSalt);
    }

    /**
     * 由密码经固定互操作档 Argon2id 构造密钥编排。
     *
     * @param password   已由 {@link ImageCryptPassword#encodeForV1(String)} 规范化的 UTF-8 字节
     * @param argon2Salt Argon2id salt（16 字节）
     * @param hkdfSalt   HKDF salt（32 字节）
     * @param progress   Argon2 进度/取消回调，可为 null
     * @return 密钥编排实例
     * @throws ImageCryptException 长度不符、内存不足或 Argon2 故障
     */
    public static ImageKeySchedule fromPassword(final byte[] password, final byte[] argon2Salt,
                                                final byte[] hkdfSalt, final KdfProgress progress)
            throws ImageCryptException {
        requireLength(argon2Salt, ImageCryptProtocol.ARGON2_SALT_LENGTH, "argon2Salt");
        requireLength(hkdfSalt, ImageCryptProtocol.HKDF_SALT_LENGTH, "hkdfSalt");
        if (password == null || password.length == 0) {
            throw new ImageCryptException(ErrorKind.INTERNAL_ERROR, "密码模式必须提供非空密码");
        }
        byte[] masterKey;
        try {
            masterKey = Argon2Kdf.deriveKey(password, argon2Salt, false,
                    ImageCryptProtocol.ARGON2_MEMORY_KIB,
                    ImageCryptProtocol.ARGON2_PASSES,
                    ImageCryptProtocol.ARGON2_LANES,
                    progress);
        } catch (IllegalStateException e) {
            throw new ImageCryptException(ErrorKind.OUT_OF_MEMORY,
                    "Argon2id 密钥派生失败（需 " + (ImageCryptProtocol.ARGON2_MEMORY_KIB >> 10)
                            + " MiB 内存）: " + e.getMessage(), e);
        }
        try {
            return deriveFromMasterKey(masterKey, hkdfSalt);
        } finally {
            SecureZero.zero(masterKey);
        }
    }

    /**
     * 对主密钥做 HKDF 域分离，得到加密与 MAC 两条子密钥。
     *
     * @param masterKey 主密钥（32 字节）
     * @param hkdfSalt  HKDF salt（32 字节）
     * @return 密钥编排实例
     * @throws ImageCryptException HKDF 输出长度异常
     */
    private static ImageKeySchedule deriveFromMasterKey(final byte[] masterKey, final byte[] hkdfSalt)
            throws ImageCryptException {
        HkdfStream hkdf = new HkdfStream(masterKey, hkdfSalt, HKDF_INFO_BYTES);
        byte[] keyMaterial = hkdf.read(ImageCryptProtocol.KEY_MATERIAL_LENGTH);
        try {
            byte[] encKey = Arrays.copyOfRange(keyMaterial, 0, ImageCryptProtocol.ENC_KEY_LENGTH);
            byte[] macKey = Arrays.copyOfRange(keyMaterial, ImageCryptProtocol.ENC_KEY_LENGTH,
                    ImageCryptProtocol.KEY_MATERIAL_LENGTH);
            return new ImageKeySchedule(encKey, macKey);
        } finally {
            SecureZero.zero(keyMaterial);
        }
    }

    // ==================== 认证 ====================

    /**
     * 构造 keyConfirm 的候选值。
     *
     * <pre>
     *   first16( keyed-BLAKE2b-512(macKey, "EGTC-IMG-KEY-CHECK-V1" || OuterHeader[0..163]) )
     * </pre>
     *
     * <p>用途是让密码模式在读取大载荷<b>之前</b>快速区分"密码错误"与"载荷损坏"。
     * 每次猜测仍必须完整执行 Argon2id，不能绕过 KDF；最终成功仍以完整的 64 字节认证标签为准。
     *
     * @param headerPrefix 协议头 {@code [0, 164)} 共 164 字节
     * @return 16 字节 keyConfirm
     * @throws ImageCryptException 前缀长度不符
     */
    public byte[] computeKeyConfirm(final byte[] headerPrefix) throws ImageCryptException {
        if (headerPrefix == null
                || headerPrefix.length != ImageCryptProtocol.KEY_CONFIRM_COVERED_HEADER_LENGTH) {
            throw new ImageCryptException(ErrorKind.INTERNAL_ERROR,
                    "keyConfirm 输入前缀必须为 "
                            + ImageCryptProtocol.KEY_CONFIRM_COVERED_HEADER_LENGTH + " 字节");
        }
        Mac mac = MacFactory.create(macKey, false);
        try {
            mac.update(KEY_CHECK_CONTEXT_BYTES, KEY_CHECK_CONTEXT_BYTES.length);
            mac.update(headerPrefix, headerPrefix.length);
            byte[] full = mac.doFinal();
            try {
                return Arrays.copyOf(full, ImageCryptProtocol.KEY_CONFIRM_LENGTH);
            } finally {
                SecureZero.zero(full);
            }
        } finally {
            mac.close();
        }
    }

    /**
     * 以常量时间比较 keyConfirm。
     *
     * <p>比较失败只说明"这条密码不匹配"或"头部损坏"，最终判定仍以完整认证标签为准。
     *
     * @param headerPrefix 协议头 {@code [0, 164)}
     * @param expected     文件中读出的 16 字节 keyConfirm
     * @return true 表示匹配
     * @throws ImageCryptException 参数长度不符
     */
    public boolean verifyKeyConfirm(final byte[] headerPrefix, final byte[] expected)
            throws ImageCryptException {
        requireLength(expected, ImageCryptProtocol.KEY_CONFIRM_LENGTH, "keyConfirm");
        byte[] candidate = computeKeyConfirm(headerPrefix);
        try {
            return MessageDigest.isEqual(candidate, expected);
        } finally {
            SecureZero.zero(candidate);
        }
    }

    /**
     * 开始累积完整认证标签。
     *
     * <p>MAC 输入按固定顺序拼接，调用方随后把密文逐块喂给返回的 {@link Mac}：
     * <pre>
     *   ASCII "EGTC-IMG-MAC-V1"
     *   OuterHeader[0..179]          （含 keyConfirm，不含 headerCrc32）
     *   ciphertextLength 的 8 字节大端表示
     *   Ciphertext 全部字节
     * </pre>
     *
     * <p>画布尾部的展示填充不参与认证，也不参与恢复。
     *
     * @param headerPrefix     协议头 {@code [0, 180)} 共 180 字节
     * @param ciphertextLength 密文字节数
     * @return 已完成前缀喂入的 MAC，调用方继续 update 密文并 doFinal
     * @throws ImageCryptException 前缀长度不符或密文长度为负
     */
    public Mac beginAuthTag(final byte[] headerPrefix, final long ciphertextLength)
            throws ImageCryptException {
        if (headerPrefix == null
                || headerPrefix.length != ImageCryptProtocol.MAC_COVERED_HEADER_LENGTH) {
            throw new ImageCryptException(ErrorKind.INTERNAL_ERROR,
                    "认证标签的头前缀必须为 " + ImageCryptProtocol.MAC_COVERED_HEADER_LENGTH + " 字节");
        }
        if (ciphertextLength < 0) {
            throw new ImageCryptException(ErrorKind.INTERNAL_ERROR, "密文长度不得为负");
        }
        byte[] lengthBytes = ByteBuffer.allocate(Long.BYTES)
                .order(ByteOrder.BIG_ENDIAN)
                .putLong(ciphertextLength)
                .array();
        Mac mac = MacFactory.create(macKey, false);
        mac.update(MAC_CONTEXT_BYTES, MAC_CONTEXT_BYTES.length);
        mac.update(headerPrefix, headerPrefix.length);
        mac.update(lengthBytes, lengthBytes.length);
        return mac;
    }

    /**
     * 以常量时间比较完整认证标签。
     *
     * @param computed 本地计算出的 64 字节标签
     * @param expected 文件中读出的 64 字节标签
     * @return true 表示认证通过
     */
    public static boolean verifyAuthTag(final byte[] computed, final byte[] expected) {
        if (computed == null || expected == null) {
            return false;
        }
        return MessageDigest.isEqual(computed, expected);
    }

    // ==================== 访问器 ====================

    /**
     * 返回 XChaCha20 加密子密钥（内部引用，请勿修改；由 {@link #close()} 负责清零）。
     *
     * @return 32 字节加密子密钥
     */
    public byte[] encKey() {
        return encKey;
    }

    /**
     * 返回 MAC 子密钥（内部引用，请勿修改；由 {@link #close()} 负责清零）。
     *
     * @return 32 字节 MAC 子密钥
     */
    public byte[] macKey() {
        return macKey;
    }

    @Override
    public void close() {
        SecureZero.zeroAll(encKey, macKey);
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
