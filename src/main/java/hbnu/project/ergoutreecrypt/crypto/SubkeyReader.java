package hbnu.project.ergoutreecrypt.crypto;

/**
 * 从 HKDF 流按序读取子密钥。
 *
 * <p>使用一次性消费标志防止重复读取，保持读取顺序约束（header → MAC → Serpent），
 * 对误用情况抛出 {@link IllegalStateException}。
 *
 * @author ErgouTree
 */
public final class SubkeyReader {

    /**
     * HKDF 扩展字节流。
     */
    private final HkdfStream hkdf;

    /**
     * 标记 header 子密钥是否已被读取。
     */
    private boolean headerRead;

    /**
     * 标记 MAC 子密钥是否已被读取。
     */
    private boolean macRead;

    /**
     * 标记 Serpent 密钥是否已被读取。
     */
    private boolean serpentRead;

    /**
     * rekey 调用次数计数器。
     */
    private int rekeyCount;

    /**
     * @param hkdf HKDF expand 字节流
     */
    public SubkeyReader(HkdfStream hkdf) {
        this.hkdf = hkdf;
    }

    /**
     * 读取 64 字节 header 子密钥（仅 v2 使用）。必须在其他子密钥之前调用。
     *
     * @return 64 字节 header 子密钥
     * @throws IllegalStateException 若已读取过
     */
    public byte[] headerSubkey() {
        if (headerRead) {
            throw new IllegalStateException("header subkey already consumed");
        }
        byte[] sk = hkdf.read(CryptoConstants.SUBKEY_HEADER_SIZE);
        headerRead = true;
        return sk;
    }

    /**
     * 读取 32 字节 MAC 子密钥。v2 必须在 {@link #headerSubkey()} 之后调用；v1 为首个读取。
     *
     * @return 32 字节 MAC 子密钥
     * @throws IllegalStateException 若已读取过
     */
    public byte[] macSubkey() {
        if (macRead) {
            throw new IllegalStateException("MAC subkey already consumed");
        }
        byte[] sk = hkdf.read(CryptoConstants.SUBKEY_MAC_SIZE);
        macRead = true;
        return sk;
    }

    /**
     * 读取 32 字节 Serpent 密钥。必须在 MAC 子密钥之后调用。
     *
     * @return 32 字节 Serpent 密钥
     * @throws IllegalStateException 若已读取过或 MAC 子密钥尚未读取
     */
    public byte[] serpentKey() {
        if (serpentRead) {
            throw new IllegalStateException("serpent key already consumed");
        }
        if (!macRead) {
            throw new IllegalStateException("must read MAC subkey before Serpent key");
        }
        byte[] k = hkdf.read(CryptoConstants.SUBKEY_SERPENT_SIZE);
        serpentRead = true;
        return k;
    }

    /**
     * 读取 rekey 用的 nonce(24 字节) 与 IV(16 字节)。每 60 GiB 调用一次。
     *
     * @return 长度为 2 的数组：{@code [0]=nonce(24), [1]=IV(16)}
     */
    public byte[][] rekeyValues() {
        byte[] nonce = hkdf.read(CryptoConstants.REKEY_NONCE_SIZE);
        byte[] iv = hkdf.read(CryptoConstants.REKEY_IV_SIZE);
        rekeyCount++;
        return new byte[][] { nonce, iv };
    }

    /**
     * 返回当前 rekey 调用次数。
     */
    public int rekeyCount() {
        return rekeyCount;
    }

    /**
     * 暴露底层 HKDF 流，供 {@link CipherSuite} 在 rekey 时直接读取新 nonce/IV。
     */
    public HkdfStream stream() {
        return hkdf;
    }
}
