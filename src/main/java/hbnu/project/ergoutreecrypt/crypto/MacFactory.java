package hbnu.project.ergoutreecrypt.crypto;

import org.bouncycastle.crypto.digests.Blake2bDigest;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * 载荷 MAC 工厂
 *
 * <ul>
 *   <li>普通模式：keyed BLAKE2b-512</li>
 *   <li>偏执模式：HMAC-SHA3-512</li>
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
     * 创建载荷 MAC。
     *
     * @param subkey   32 字节 MAC 子密钥（来自 HKDF）
     * @param paranoid true 用 HMAC-SHA3-512，false 用 keyed BLAKE2b-512
     */
    public static Mac create(byte[] subkey, boolean paranoid) {
        return paranoid ? new HmacSha3Mac(subkey) : new Blake2bMac(subkey);
    }

    /**
     * keyed BLAKE2b-512（普通模式）。
     */
    private static final class Blake2bMac implements Mac {
        private final Blake2bDigest digest;
        private final byte[] key;

        Blake2bMac(byte[] subkey) {
            this.key = subkey.clone();
            // 512-bit 输出，keyed 模式。
            this.digest = new Blake2bDigest(subkey, 64, null, null);
        }

        @Override
        public void update(byte[] data, int len) {
            digest.update(data, 0, len);
        }

        @Override
        public byte[] doFinal() {
            // 在副本上 doFinal，避免重置原始累积状态（防御性，便于将来多次取值）。
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
     * HMAC-SHA3-512（偏执模式）。
     */
    private static final class HmacSha3Mac implements Mac {
        private final HMac hmac;
        private final byte[] key;

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
            // HMac.doFinal 会重置内部状态；Picocrypt 在流程末尾仅取值一次，符合该用法。
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
