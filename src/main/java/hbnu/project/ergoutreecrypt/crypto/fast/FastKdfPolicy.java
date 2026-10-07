package hbnu.project.ergoutreecrypt.crypto.fast;

import hbnu.project.ergoutreecrypt.exception.CryptoException;
import hbnu.project.ergoutreecrypt.exception.ErrorKind;
import java.nio.charset.StandardCharsets;
import java.text.Normalizer;

/** FAST-v1 唯一允许的密码编码和 Argon2id 参数，拒绝密文指定任意资源消耗。 */
public final class FastKdfPolicy {
    /** 固定内存参数，单位 KiB。 */
    public static final int MEMORY_KIB = 65536;
    /** 固定迭代次数。 */
    public static final int PASSES = 3;
    /** 固定并行通道数。 */
    public static final int LANES = 4;
    /** Argon2 版本 1.3。 */
    public static final int ARGON_VERSION = 0x13;
    /** NFC 后 UTF-8 编码标识。 */
    public static final int PASSWORD_ENCODING = 1;
    /** 规范化后密码字节上限。 */
    public static final int MAX_PASSWORD_BYTES = 1024;
    private FastKdfPolicy() { }

    /**
     * 校验唯一 KDF 参数，必须在分配 Argon2 内存前调用。
     * @param memoryKiB 内存 KiB
     * @param passes 迭代次数
     * @param lanes 并行通道数
     * @param version Argon2 版本
     * @param encoding 密码编码标识
     * @throws CryptoException 参数不受支持
     */
    public static void validate(int memoryKiB, int passes, int lanes, int version, int encoding)
            throws CryptoException {
        if (memoryKiB != MEMORY_KIB || passes != PASSES || lanes != LANES
                || version != ARGON_VERSION || encoding != PASSWORD_ENCODING) {
            throw new CryptoException(ErrorKind.UNSUPPORTED_FORMAT, "不支持的 FAST-v1 KDF 参数");
        }
    }

    /**
     * 对合法非空密码仅执行 NFC 与严格 UTF-8 编码，不尝试旧格式候选或公共密码。
     * @param password 原始密码，首尾合法空格保留
     * @return 调用方负责清零的密码字节
     * @throws CryptoException 空白、非法 UTF-16 或超长密码
     */
    public static byte[] encodePassword(String password) throws CryptoException {
        if (password == null || password.isEmpty() || password.length() > 4096
                || password.codePoints().allMatch(c -> Character.isWhitespace(c) || Character.isSpaceChar(c))) {
            throw new CryptoException(ErrorKind.WRONG_PASSWORD, "FAST 需要非空且长度受限的密码");
        }
        for (int i = 0; i < password.length(); i++) {
            char c = password.charAt(i);
            if (Character.isHighSurrogate(c)) {
                if (++i == password.length() || !Character.isLowSurrogate(password.charAt(i))) {
                    throw new CryptoException(ErrorKind.WRONG_PASSWORD, "密码包含非法 UTF-16 代理项");
                }
            } else if (Character.isLowSurrogate(c)) {
                throw new CryptoException(ErrorKind.WRONG_PASSWORD, "密码包含非法 UTF-16 代理项");
            }
        }
        byte[] bytes = Normalizer.normalize(password, Normalizer.Form.NFC).getBytes(StandardCharsets.UTF_8);
        if (bytes.length > MAX_PASSWORD_BYTES) {
            hbnu.project.ergoutreecrypt.crypto.SecureZero.zero(bytes);
            throw new CryptoException(ErrorKind.WRONG_PASSWORD, "密码 NFC/UTF-8 编码超过 1024 字节");
        }
        return bytes;
    }
}
