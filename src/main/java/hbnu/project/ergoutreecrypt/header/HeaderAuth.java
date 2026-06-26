package hbnu.project.ergoutreecrypt.header;

import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * Header 认证工具。
 *
 * <h3>v1 与 v2 差异</h3>
 * <ul>
 *   <li>v1.x：header 存储 SHA3-512(key) 做密码校验，无 header MAC（字段不受篡改保护）；</li>
 *   <li>v2.00+：header 存储 HMAC-SHA3-512(header_fields)，以 HKDF 头 64 字节为子密钥，
 *       覆盖所有 header 字段及 keyfileHash，可检测篡改。</li>
 * </ul>
 *
 * <p>所有比较均使用常量时间比较以抵御时序攻击。
 *
 * @author ErgouTree
 */
public final class HeaderAuth {

    private HeaderAuth() {
    }

    // ==================== v2 Header MAC ====================

    /**
     * 计算 v2 header HMAC-SHA3-512。
     *
     * <p>MAC 覆盖顺序（必须严格匹配）：
     * <ol>
     *   <li>version</li>
     *   <li>commentsLen（5 位十进制字符串）</li>
     *   <li>comments</li>
     *   <li>flags（5 字节）</li>
     *   <li>salt</li>
     *   <li>hkdfSalt</li>
     *   <li>serpentIV</li>
     *   <li>nonce</li>
     *   <li>keyfileHash</li>
     * </ol>
     *
     * @param subkeyHeader HKDF 头 64 字节（header 子密钥）
     * @param h            volume header
     * @param keyfileHash  32 字节 keyfile hash
     * @return 64 字节 HMAC-SHA3-512 认证码
     */
    public static byte[] computeV2HeaderMac(byte[] subkeyHeader, VolumeHeader h, byte[] keyfileHash) {
        HMac hmac = new HMac(new SHA3Digest(512));
        hmac.init(new KeyParameter(subkeyHeader));

        // 1. version
        update(hmac, h.getVersion().getBytes(StandardCharsets.UTF_8));

        // 2. commentsLen（5 位十进制，UTF-8 字节数）
        byte[] commentBytes = h.getComments() == null ? new byte[0]
                : h.getComments().getBytes(StandardCharsets.UTF_8);
        String commentsLenStr = String.format("%05d", commentBytes.length);
        update(hmac, commentsLenStr.getBytes(StandardCharsets.UTF_8));

        // 3. comments
        if (h.getComments() != null && !h.getComments().isEmpty()) {
            update(hmac, h.getComments().getBytes(StandardCharsets.UTF_8));
        }

        // 4. flags（5 字节）
        update(hmac, h.getFlags().toBytes());

        // 5. salt
        update(hmac, h.getSalt());

        // 6. hkdfSalt
        update(hmac, h.getHkdfSalt());

        // 7. serpentIV
        update(hmac, h.getSerpentIV());

        // 8. nonce
        update(hmac, h.getNonce());

        // 9. keyfileHash
        update(hmac, keyfileHash);

        byte[] out = new byte[hmac.getMacSize()];
        hmac.doFinal(out, 0);
        return out;
    }

    // ==================== v1 KeyHash（legacy） ====================

    /**
     * 计算 v1 KeyHash = SHA3-512(key)。
     *
     * @param key Argon2 派生密钥（32 字节）
     * @return 64 字节 SHA3-512 哈希
     */
    public static byte[] computeV1KeyHash(byte[] key) {
        SHA3Digest digest = new SHA3Digest(512);
        digest.update(key, 0, key.length);
        byte[] out = new byte[digest.getDigestSize()];
        digest.doFinal(out, 0);
        return out;
    }

    // ==================== 校验 ====================

    /**
     * 校验 v2 header MAC。
     *
     * @param subkeyHeader HKDF 头 64 字节（header 子密钥）
     * @param h            volume header（含待校验的 keyHash）
     * @param keyfileHash  32 字节 keyfile hash
     * @return 认证结果（含是否通过及计算值）
     */
    public static AuthResult verifyV2Header(byte[] subkeyHeader, VolumeHeader h, byte[] keyfileHash) {
        byte[] computed = computeV2HeaderMac(subkeyHeader, h, keyfileHash);
        boolean valid = constantTimeEqual(computed, h.getKeyHash());
        return new AuthResult(valid, computed);
    }

    /**
     * 校验 v1 legacy header（比对新计算的 KeyHash 与 header 中的值）。
     *
     * @param key Argon2 派生密钥（32 字节）
     * @param h   volume header（含待校验的 keyHash）
     * @return 认证结果
     */
    public static AuthResult verifyV1Header(byte[] key, VolumeHeader h) {
        byte[] computed = computeV1KeyHash(key);
        boolean valid = constantTimeEqual(computed, h.getKeyHash());
        return new AuthResult(valid, computed);
    }

    /**
     * 校验 keyfile hash 是否匹配。
     *
     * @param computed 新计算的 hash
     * @param stored   header 中存储的 hash
     * @return 若常量时间比较相等则返回 true
     */
    public static boolean verifyKeyfileHash(byte[] computed, byte[] stored) {
        return constantTimeEqual(computed, stored);
    }

    // ==================== 工具方法 ====================

    /**
     * 向 HMac 追加数据，自动跳过 null 或空数组。
     */
    private static void update(HMac hmac, byte[] data) {
        if (data != null && data.length > 0) {
            hmac.update(data, 0, data.length);
        }
    }

    /**
     * 常量时间比较两个字节数组。
     *
     * <p>长度不等时直接返回 false。长度相等时使用 {@link MessageDigest#isEqual} 做常量时间比较。
     *
     * @param a 数组一（可为 null）
     * @param b 数组二（可为 null）
     * @return 若两者均为 null 或内容相等则返回 true
     */
    public static boolean constantTimeEqual(byte[] a, byte[] b) {
        if (a == null || b == null) {
            return a == b;
        }
        if (a.length != b.length) {
            return false;
        }
        return MessageDigest.isEqual(a, b);
    }

    // ==================== 结果类 ====================

    /**
     * 认证结果，包含是否通过及计算出的 hash 值。
     */
    public static final class AuthResult {

        /**
         * 认证是否通过。
         */
        private final boolean valid;

        /**
         * 计算出的 key hash 值（用于调用方进一步处理）。
         */
        private final byte[] keyHashComputed;

        /**
         * @param valid           认证是否通过
         * @param keyHashComputed 计算出的 key hash
         */
        AuthResult(boolean valid, byte[] keyHashComputed) {
            this.valid = valid;
            this.keyHashComputed = keyHashComputed;
        }

        /**
         * 认证是否通过。
         */
        public boolean isValid() {
            return valid;
        }

        /**
         * 返回计算出的 key hash。
         */
        public byte[] getKeyHashComputed() {
            return keyHashComputed;
        }
    }

    // ==================== 错误类 ====================

    /**
     * 认证失败异常，携带失败原因分类。
     */
    public static final class AuthException extends RuntimeException {

        /**
         * 密码是否错误。
         */
        private final boolean passwordIncorrect;

        /**
         * keyfile 是否错误。
         */
        private final boolean keyfileIncorrect;

        /**
         * 是否要求 keyfile 有序。
         */
        private final boolean keyfileOrdered;

        /**
         * @param passwordIncorrect 密码错误标志
         * @param keyfileIncorrect  keyfile 错误标志
         * @param keyfileOrdered    有序标志
         * @param message           错误消息
         */
        AuthException(boolean passwordIncorrect, boolean keyfileIncorrect,
                      boolean keyfileOrdered, String message) {
            super(message);
            this.passwordIncorrect = passwordIncorrect;
            this.keyfileIncorrect = keyfileIncorrect;
            this.keyfileOrdered = keyfileOrdered;
        }

        /**
         * 创建密码错误异常。
         */
        public static AuthException passwordError() {
            return new AuthException(true, false, false,
                    "The provided password is incorrect");
        }

        /**
         * 创建 v2 密码错误或 header 被篡改异常。
         */
        public static AuthException v2PasswordOrTamperError() {
            return new AuthException(true, false, false,
                    "The password is incorrect or header is tampered");
        }

        /**
         * 创建 keyfile 错误异常。
         *
         * @param ordered 是否有序模式
         */
        public static AuthException keyfileError(boolean ordered) {
            String msg = ordered
                    ? "Incorrect keyfiles or ordering"
                    : "Incorrect keyfiles";
            return new AuthException(false, true, ordered, msg);
        }

        /**
         * 判断异常是否为密码错误（非 keyfile 错误）。
         */
        public static boolean isPasswordError(Throwable t) {
            return t instanceof AuthException ae && ae.passwordIncorrect;
        }

        /**
         * 密码是否错误。
         */
        public boolean isPasswordIncorrect() {
            return passwordIncorrect;
        }

        /**
         * keyfile 是否错误。
         */
        public boolean isKeyfileIncorrect() {
            return keyfileIncorrect;
        }

        /**
         * 是否要求 keyfile 有序。
         */
        public boolean isKeyfileOrdered() {
            return keyfileOrdered;
        }
    }
}
