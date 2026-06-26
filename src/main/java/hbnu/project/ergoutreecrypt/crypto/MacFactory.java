package hbnu.project.ergoutreecrypt.crypto;

import org.bouncycastle.crypto.digests.Blake2bDigest;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * 载荷 MAC 工厂。
 *
 * <p>根据安全模式创建对应的 MAC 实现：
 * <ul>
 *   <li>普通模式 — keyed BLAKE2b-512；</li>
 *   <li>偏执模式 — HMAC-SHA3-512。</li>
 * </ul>
 * 两者输出均为 64 字节。
 *
 * @author ErgouTree
 * @since 2026/6/16
 */
public final class MacFactory {

    private MacFactory() {
    }

    /**
     * 创建载荷 MAC 实例。
     *
     * @param subkey   32 字节 MAC 子密钥（来自 HKDF 派生）
     * @param paranoid true 使用 HMAC-SHA3-512，false 使用 keyed BLAKE2b-512
     * @return MAC 实例
     */
    public static Mac create(byte[] subkey, boolean paranoid) {
        return paranoid ? new HmacSha3Mac(subkey) : new Blake2bMac(subkey);
    }

    /**
     * keyed BLAKE2b-512 MAC 实现（普通模式）。
     */
    private static final class Blake2bMac implements Mac {

        /**
         * BLAKE2b 摘要引擎。
         */
        private final Blake2bDigest digest;

        /**
         * 密钥材料副本，用于安全清零。
         */
        private final byte[] key;

        /**
         * @param subkey 32 字节子密钥
         */
        Blake2bMac(byte[] subkey) {
            this.key = subkey.clone();
            this.digest = new Blake2bDigest(subkey, 64, null, null);
        }

        @Override
        public void update(byte[] data, int len) {
            digest.update(data, 0, len);
        }

        @Override
        public byte[] doFinal() {
            // 在副本上 doFinal，避免重置原始累积状态
            Blake2bDigest copy = new Blake2bDigest(digest);
            byte[] out = new byte[copy.getDigestSize()];
            copy.doFinal(out, 0);
            return out;
        }

        @Override
        public void close() {
            SecureZero.zero(key);
            digest.reset();
        }
    }

    /**
     * HMAC-SHA3-512 MAC 实现（偏执模式）。
     */
    private static final class HmacSha3Mac implements Mac {

        /**
         * HMAC-SHA3-512 引擎。
         */
        private final HMac hmac;

        /**
         * 密钥材料副本，用于安全清零。
         */
        private final byte[] key;

        /**
         * @param subkey 32 字节子密钥
         */
        HmacSha3Mac(byte[] subkey) {
            this.key = subkey.clone();
            this.hmac = new HMac(new SHA3Digest(512));
            this.hmac.init(new KeyParameter(subkey));
        }

        @Override
        public void update(byte[] data, int len) {
            hmac.update(data, 0, len);
        }

        @Override
        public byte[] doFinal() {
            // HMac.doFinal 会重置内部状态，在流程末尾仅取值一次
            byte[] out = new byte[hmac.getMacSize()];
            hmac.doFinal(out, 0);
            return out;
        }

        @Override
        public void close() {
            SecureZero.zero(key);
            hmac.reset();
        }
    }
}
