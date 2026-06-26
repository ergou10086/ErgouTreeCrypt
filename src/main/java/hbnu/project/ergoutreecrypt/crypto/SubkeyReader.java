package hbnu.project.ergoutreecrypt.crypto;

/**
 * 从 HKDF 流按序读取子密钥
 *
 * <p>本类用一次性消费标志防止重复读取，保持一致的误用保护。
 *
 * @author ErgouTree
 */
public final class SubkeyReader {

    private final HkdfStream hkdf;
    private boolean headerRead;
    private boolean macRead;
    private boolean serpentRead;
    private int rekeyCount;

    public SubkeyReader(HkdfStream hkdf) {
        this.hkdf = hkdf;
    }

    /**
     * 读取 64 字节 header 子密钥（仅 v2）。必须在其他子密钥之前调用。
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
     * 读取 32 字节 MAC 子密钥。v2 必须在 {@link #headerSubkey()} 之后；v1 为首个读取。
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
     * 读取 32 字节 Serpent 密钥。必须在 MAC 子密钥之后。
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
     * 读取 rekey 用的 nonce(24) + iv(16)。每 60 GiB 调用一次。
     *
     * @return 长度 2 的数组：{@code [0]} = nonce(24)，{@code [1]} = iv(16)
     */
    public byte[][] rekeyValues() {
        byte[] nonce = hkdf.read(CryptoConstants.REKEY_NONCE_SIZE);
        byte[] iv = hkdf.read(CryptoConstants.REKEY_IV_SIZE);
        rekeyCount++;
        return new byte[][] { nonce, iv };
    }

    public int rekeyCount() {
        return rekeyCount;
    }

    /** 暴露底层 HKDF 流，供 {@link CipherSuite} 在 rekey 时直接读取。 */
    public HkdfStream stream() {
        return hkdf;
    }
}
