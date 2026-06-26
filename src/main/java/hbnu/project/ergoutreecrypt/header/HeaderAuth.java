package hbnu.project.ergoutreecrypt.header;

import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * Header 认证（v2 HMAC-SHA3-512 / v1 SHA3-512 KeyHash）
 *
 * <h3> v1 vs v2 差异</h3>
 * <ul>
 *   <li>v1.x：header 存 SHA3-512(key) 做密码校验，无 header MAC（字段不受篡改保护）</li>
 *   <li>v2.00+：header 存 HMAC-SHA3-512(header_fields)，用 HKDF 的头 64 字节作 subkey，
 *       覆盖所有 header 字段及 keyfileHash，检测篡改。</li>
 * </ul>
 *
 * <p>所有比较均使用常量时间比较。
 *
 * @author ErgouTree
 */
public final class HeaderAuth {

    private HeaderAuth() {
    }

    // ================================================================
    // v2 Header MAC
    // ================================================================

    /**
     * 计算 v2 header HMAC-SHA3-512。对应 Go {@code ComputeV2HeaderMAC}。
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
     * @param subkeyHeader HKDF 的头 64 字节（header 子密钥）
     * @param h            volume header
     * @param keyfileHash  32 字节 keyfile hash
     * @return 64 字节 HMAC-SHA3-512
     */
    public static byte[] computeV2HeaderMac(byte[] subkeyHeader, VolumeHeader h, byte[] keyfileHash) {
        HMac hmac = new HMac(new SHA3Digest(512));
        hmac.init(new KeyParameter(subkeyHeader));

        // 1. version
        update(hmac, h.getVersion().getBytes(StandardCharsets.UTF_8));

        // 2. commentsLen（5 位十进制，UTF-8 字节数，与 Go len(string) 一致）
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

    // ================================================================
    // v1 KeyHash（legacy）
    // ================================================================

    /**
     * 计算 v1 KeyHash = SHA3-512(key)。对应 Go {@code ComputeV1KeyHash}。
     */
    public static byte[] computeV1KeyHash(byte[] key) {
        SHA3Digest digest = new SHA3Digest(512);
        digest.update(key, 0, key.length);
        byte[] out = new byte[digest.getDigestSize()];
        digest.doFinal(out, 0);
        return out;
    }

    // ================================================================
    // 校验
    // ================================================================

    /**
     * 校验 v2 header。对应 Go {@code VerifyV2Header}。
     */
    public static AuthResult verifyV2Header(byte[] subkeyHeader, VolumeHeader h, byte[] keyfileHash) {
        byte[] computed = computeV2HeaderMac(subkeyHeader, h, keyfileHash);
        boolean valid = constantTimeEqual(computed, h.getKeyHash());
        return new AuthResult(valid, computed);
    }

    /**
     * 校验 v1 legacy header。对应 Go {@code VerifyV1Header}。
     */
    public static AuthResult verifyV1Header(byte[] key, VolumeHeader h) {
        byte[] computed = computeV1KeyHash(key);
        boolean valid = constantTimeEqual(computed, h.getKeyHash());
        return new AuthResult(valid, computed);
    }

    /**
     * 校验 keyfile hash。对应 Go {@code VerifyKeyfileHash}。
     */
    public static boolean verifyKeyfileHash(byte[] computed, byte[] stored) {
        return constantTimeEqual(computed, stored);
    }

    // ================================================================
    // 工具方法
    // ================================================================

    /**
     * HMac.update，避免逐次传入 null 判空。
     */
    private static void update(HMac hmac, byte[] data) {
        if (data != null && data.length > 0) {
            hmac.update(data, 0, data.length);
        }
    }

    /**
     * 常量时间比较，与 Go {@code subtle.ConstantTimeCompare} 语义一致。
     * 两数组长度不等时直接返回 false（不泄露长度差的具体值）。
     */
    public static boolean constantTimeEqual(byte[] a, byte[] b) {
        if (a == null || b == null) {
            return a == b;
        }
        if (a.length != b.length) {
            // 仍常量时间遍历以防止旁路线索，但长度差异本身是信息泄露。
            // 与 Go subtle.ConstantTimeCompare 行为一致：也在不同长度时返回 -1/0。
            // 但 Java 版本先做长度检查再走 arrays.equals 对 header auth
            // 场景来说足够（HMAC/SHA3 输出长度固定为 64/32 字节）。
            return false;
        }
        return MessageDigest.isEqual(a, b);
    }

    // ================================================================
    // 结果类
    // ================================================================

    /**
     * 认证结果，对应 Go {@code AuthResult}。
     */
    public static final class AuthResult {
        private final boolean valid;
        private final byte[] keyHashComputed;

        AuthResult(boolean valid, byte[] keyHashComputed) {
            this.valid = valid;
            this.keyHashComputed = keyHashComputed;
        }

        public boolean isValid() {
            return valid;
        }

        public byte[] getKeyHashComputed() {
            return keyHashComputed;
        }
    }

    // ================================================================
    // 错误类
    // ================================================================

    /**
     * 认证失败错误，对应 Go {@code AuthError}。
     */
    public static final class AuthException extends RuntimeException {
        private final boolean passwordIncorrect;
        private final boolean keyfileIncorrect;
        private final boolean keyfileOrdered;

        AuthException(boolean passwordIncorrect, boolean keyfileIncorrect,
                      boolean keyfileOrdered, String message) {
            super(message);
            this.passwordIncorrect = passwordIncorrect;
            this.keyfileIncorrect = keyfileIncorrect;
            this.keyfileOrdered = keyfileOrdered;
        }

        public static AuthException passwordError() {
            return new AuthException(true, false, false,
                    "The provided password is incorrect");
        }

        public static AuthException v2PasswordOrTamperError() {
            return new AuthException(true, false, false,
                    "The password is incorrect or header is tampered");
        }

        public static AuthException keyfileError(boolean ordered) {
            String msg = ordered
                    ? "Incorrect keyfiles or ordering"
                    : "Incorrect keyfiles";
            return new AuthException(false, true, ordered, msg);
        }

        /**
         * 判断异常是否可归因于密码错误（非 keyfile），对应 Go {@code IsPasswordError}。
         */
        public static boolean isPasswordError(Throwable t) {
            return t instanceof AuthException ae && ae.passwordIncorrect;
        }

        public boolean isPasswordIncorrect() {
            return passwordIncorrect;
        }

        public boolean isKeyfileIncorrect() {
            return keyfileIncorrect;
        }

        public boolean isKeyfileOrdered() {
            return keyfileOrdered;
        }
    }
}
