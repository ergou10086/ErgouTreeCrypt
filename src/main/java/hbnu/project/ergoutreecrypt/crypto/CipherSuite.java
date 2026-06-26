package hbnu.project.ergoutreecrypt.crypto;

/**
 * 加解密套件
 * <p>
 * 组合 XChaCha20（普通）与可选的 Serpent-CTR（偏执），并维护载荷 MAC。
 * <p>
 * <b>顺序不可改：</b>
 * <ul>
 *   <li>加密：[Serpent-CTR] → XChaCha20 → MAC(密文)（encrypt-then-MAC）</li>
 *   <li>解密：MAC(密文) → XChaCha20 → [Serpent-CTR]（verify-then-decrypt）</li>
 * </ul>
 * <p>
 * 每 60 GiB 必须 {@link #rekey()} 一次，从 HKDF 流取新的 nonce/IV 以避免 nonce 溢出。
 *
 * @author ErgouTree
 */
public final class CipherSuite implements AutoCloseable {

    private final Mac mac;
    private final HkdfStream hkdf;
    private final boolean paranoid;
    // XChaCha20 主密钥，rekey 时复用
    private final byte[] key;
    // Serpent 密钥，rekey 时复用
    private final byte[] serpentKey;

    private XChaCha20 chacha;
    private SerpentCtr serpent;
    // Serpent → XChaCha20 中转缓冲，避免改写调用方输入
    private byte[] scratch;

    /**
     * @param key        XChaCha20 主密钥（32 字节）
     * @param nonce      XChaCha20 初始 nonce（24 字节）
     * @param serpentKey Serpent 密钥（32 字节，仅偏执模式使用）
     * @param serpentIV  Serpent 初始 IV（16 字节，仅偏执模式使用）
     * @param mac        载荷 MAC
     * @param hkdf       HKDF 流，rekey 时从此读取新 nonce/IV
     * @param paranoid   是否启用 Serpent 叠加层
     */
    public CipherSuite(byte[] key, byte[] nonce, byte[] serpentKey, byte[] serpentIV,
                       Mac mac, HkdfStream hkdf, boolean paranoid) {
        this.key = key.clone();
        this.serpentKey = serpentKey != null ? serpentKey.clone() : null;
        this.mac = mac;
        this.hkdf = hkdf;
        this.paranoid = paranoid;

        this.chacha = new XChaCha20(this.key, nonce);
        if (paranoid) {
            this.serpent = new SerpentCtr(this.serpentKey, serpentIV);
        }
    }

    private byte[] scratch(int len) {
        if (scratch == null || scratch.length < len) {
            scratch = new byte[len];
        }
        return scratch;
    }

    /**
     * 加密一块数据。
     * 顺序：[Serpent-CTR] → XChaCha20 → MAC(密文)。
     *
     * @param dst 输出（密文），长度 ≥ len
     * @param src 输入（明文）
     * @param len 处理字节数
     */
    public void encrypt(byte[] dst, byte[] src, int len) {
        if (paranoid) {
            serpent.process(dst, src, len);
            // serpent 输出作为 chacha 输入，使用中转缓冲避免改写调用方的 src。
            byte[] mid = scratch(len);
            System.arraycopy(dst, 0, mid, 0, len);
            chacha.process(dst, mid, len);
        } else {
            chacha.process(dst, src, len);
        }
        mac.update(dst, len);
    }

    /**
     * 解密一块数据。
     * 顺序：MAC(密文) → XChaCha20 → [Serpent-CTR]。
     *
     * @param dst 输出（明文），长度 ≥ len
     * @param src 输入（密文）
     * @param len 处理字节数
     */
    public void decrypt(byte[] dst, byte[] src, int len) {
        mac.update(src, len);
        chacha.process(dst, src, len);
        if (paranoid) {
            byte[] mid = scratch(len);
            System.arraycopy(dst, 0, mid, 0, len);
            serpent.process(dst, mid, len);
        }
    }

    /**
     * 重新派生 cipher，每 60 GiB。从 HKDF 流按序读取新 nonce(24)，偏执模式再读 IV(16)。
     *
     * <p>读取顺序必须为 nonce 在前、serpentIV 在后，与 Go 一致。
     */
    public void rekey() {
        byte[] nonce = hkdf.read(CryptoConstants.REKEY_NONCE_SIZE);
        chacha = new XChaCha20(key, nonce);
        if (paranoid) {
            byte[] iv = hkdf.read(CryptoConstants.REKEY_IV_SIZE);
            serpent = new SerpentCtr(serpentKey, iv);
        }
    }

    /**
     * 返回最终 MAC 值。
     */
    public byte[] sum() {
        return mac.doFinal();
    }

    public boolean isParanoid() {
        return paranoid;
    }

    @Override
    public void close() {
        SecureZero.zero(key);
        SecureZero.zero(serpentKey);
        SecureZero.zero(scratch);
        if (mac != null) {
            mac.close();
        }
        chacha = null;
        serpent = null;
    }
}
