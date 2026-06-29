package hbnu.project.ergoutreecrypt.crypto;

/**
 * 加解密套件，组合 XChaCha20 流密码与可选的 Serpent-CTR 叠加层，并维护载荷 MAC。
 *
 * <p><b>处理顺序不可更改：</b>
 * <ul>
 *   <li>加密：[Serpent-CTR] → XChaCha20 → MAC(密文)，即 encrypt-then-MAC；</li>
 *   <li>解密：MAC(密文) → XChaCha20 → [Serpent-CTR]，即 verify-then-decrypt。</li>
 * </ul>
 *
 * <p>每处理 60 GiB 数据必须调用一次 {@link #rekey()} 从 HKDF 流取新的 nonce 与 IV，
 * 以避免 nonce 溢出。使用完毕后调用 {@link #close()} 安全清零密钥材料。
 *
 * @author ErgouTree
 */
public final class CipherSuite implements AutoCloseable {

    /**
     * 载荷消息认证码。
     */
    private final Mac mac;

    /**
     * HKDF 扩展字节流，rekey 时从此读取新 nonce/IV。
     */
    private final HkdfStream hkdf;

    /**
     * 是否启用 Serpent 叠加层（偏执模式）。
     */
    private final boolean paranoid;

    /**
     * XChaCha20 主密钥（32 字节），rekey 时复用。
     */
    private final byte[] key;

    /**
     * Serpent 密钥（32 字节），仅偏执模式使用，rekey 时复用。
     */
    private final byte[] serpentKey;

    /**
     * 当前 XChaCha20 流密码实例。
     */
    private XChaCha20 chacha;

    /**
     * 当前 Serpent-CTR 流密码实例（仅偏执模式）。
     */
    private SerpentCtr serpent;

    /**
     * Serpent → XChaCha20 中转缓冲，避免改写调用方输入数据。
     */
    private byte[] scratch;

    /**
     * 初始化加解密套件。
     *
     * @param key        XChaCha20 主密钥（32 字节）
     * @param nonce      XChaCha20 初始 nonce（24 字节）
     * @param serpentKey Serpent 密钥（32 字节，仅偏执模式使用，可为 null）
     * @param serpentIV  Serpent 初始 IV（16 字节，仅偏执模式使用，可为 null）
     * @param mac        载荷 MAC 实例
     * @param hkdf       HKDF 字节流，rekey 时从此读取新 nonce/IV
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
            // 预分配中转缓冲区，避免热路径上的延迟分配与长度检查
            this.scratch = new byte[CryptoConstants.MIB];
        }
    }

    /**
     * 加密一块数据。
     *
     * <p>处理顺序：[Serpent-CTR] → XChaCha20 → MAC.update(密文)。
     *
     * @param dst 输出缓冲区（密文），长度须 ≥ len
     * @param src 输入数据（明文）
     * @param len 处理字节数
     */
    public void encrypt(byte[] dst, byte[] src, int len) {
        if (paranoid) {
            // 先 Serpent-CTR 加密到 dst，再经中转缓冲送入 XChaCha20
            serpent.process(dst, src, len);
            System.arraycopy(dst, 0, scratch, 0, len);
            chacha.process(dst, scratch, len);
        } else {
            chacha.process(dst, src, len);
        }

        // 对密文累积 MAC
        mac.update(dst, len);
    }

    /**
     * 解密一块数据。
     *
     * <p>处理顺序：MAC.update(密文) → XChaCha20 → [Serpent-CTR]。
     *
     * @param dst 输出缓冲区（明文），长度须 ≥ len
     * @param src 输入数据（密文）
     * @param len 处理字节数
     */
    public void decrypt(byte[] dst, byte[] src, int len) {
        // 对密文累积 MAC
        mac.update(src, len);

        // XChaCha20 解密
        chacha.process(dst, src, len);

        if (paranoid) {
            // XChaCha20 输出经中转缓冲送入 Serpent-CTR 解密
            System.arraycopy(dst, 0, scratch, 0, len);
            serpent.process(dst, scratch, len);
        }
    }

    /**
     * 重新派生 cipher，每 60 GiB 必须调用一次。
     *
     * <p>从 HKDF 流按序读取新 nonce（24 字节）；偏执模式下继续读取新 Serpent IV（16 字节）。
     * 读取顺序为 nonce 在前、IV 在后，不可调换。
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
     * 返回最终的载荷 MAC 认证标签。
     *
     * @return MAC 值（64 字节）
     */
    public byte[] sum() {
        return mac.doFinal();
    }

    /**
     * 是否启用偏执模式（Serpent 叠加层）。
     */
    public boolean isParanoid() {
        return paranoid;
    }

    /**
     * 安全清零所有密钥材料与内部状态，释放后不应再使用本实例。
     */
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
