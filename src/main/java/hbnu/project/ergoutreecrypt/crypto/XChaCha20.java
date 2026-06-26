package hbnu.project.ergoutreecrypt.crypto;

import org.bouncycastle.crypto.engines.ChaCha7539Engine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

/**
 * XChaCha20 流密码（24 字节 nonce）
 *
 * <p>JDK 内置的 ChaCha20 仅支持 RFC 7539 的 12 字节 nonce，无法直接用于 24 字节 XNonce。因此本类按 XChaCha20 规范实现：
 * <ol>
 *   <li>用 HChaCha20(key, nonce[0:16]) 派生 32 字节子密钥；</li>
 *   <li>用该子密钥 + 12 字节 nonce（4 字节 0 || nonce[16:24]）跑标准 ChaCha20（RFC 7539）。</li>
 * </ol>
 *
 * <p>底层使用 BouncyCastle 的 {@link ChaCha7539Engine}（即 RFC 7539 ChaCha20），
 * 这是一个无认证的流密码（认证由上层 MAC 负责）。
 *
 * @author ErgouTree
 */
public final class XChaCha20 {

    private static final byte[] SIGMA = {
            'e', 'x', 'p', 'a', 'n', 'd', ' ', '3', '2', '-', 'b', 'y', 't', 'e', ' ', 'k'
    };

    private final ChaCha7539Engine engine;

    /**
     * 创建 XChaCha20 流密码。
     *
     * @param key   32 字节密钥
     * @param nonce 24 字节 nonce
     */
    public XChaCha20(byte[] key, byte[] nonce) {
        if (key.length != 32) {
            throw new IllegalArgumentException("XChaCha20 key must be 32 bytes, got " + key.length);
        }
        if (nonce.length != 24) {
            throw new IllegalArgumentException("XChaCha20 nonce must be 24 bytes, got " + nonce.length);
        }

        byte[] subKey = hChaCha20(key, nonce);

        // 子 nonce = 4 字节 0 || nonce 后 8 字节，构成 RFC 7539 的 12 字节 nonce。
        byte[] subNonce = new byte[12];
        System.arraycopy(nonce, 16, subNonce, 4, 8);

        engine = new ChaCha7539Engine();
        engine.init(true, new ParametersWithIV(new KeyParameter(subKey), subNonce));
        SecureZero.zero(subKey);
    }

    /**
     * 流加解密（XOR keystream）。{@code in} 与 {@code out} 可指向不同数组，长度需相同。
     * 由于是流密码，加密与解密为同一操作。
     */
    public void process(byte[] out, byte[] in, int len) {
        engine.processBytes(in, 0, len, out, 0);
    }

    // ---- HChaCha20：ChaCha20 块函数（20 轮），不做最终加法，取首尾 8 个 32-bit 字 ----

    public static byte[] hChaCha20(byte[] key, byte[] nonce16) {
        int[] state = new int[16];
        state[0] = le32(SIGMA, 0);
        state[1] = le32(SIGMA, 4);
        state[2] = le32(SIGMA, 8);
        state[3] = le32(SIGMA, 12);
        for (int i = 0; i < 8; i++) {
            state[4 + i] = le32(key, i * 4);
        }
        for (int i = 0; i < 4; i++) {
            state[12 + i] = le32(nonce16, i * 4);
        }

        for (int i = 0; i < 10; i++) {
            quarterRound(state, 0, 4, 8, 12);
            quarterRound(state, 1, 5, 9, 13);
            quarterRound(state, 2, 6, 10, 14);
            quarterRound(state, 3, 7, 11, 15);
            quarterRound(state, 0, 5, 10, 15);
            quarterRound(state, 1, 6, 11, 12);
            quarterRound(state, 2, 7, 8, 13);
            quarterRound(state, 3, 4, 9, 14);
        }

        byte[] out = new byte[32];
        // HChaCha20 输出 = state[0..3] || state[12..15]（不加初始状态）。
        for (int i = 0; i < 4; i++) {
            putLe32(out, i * 4, state[i]);
        }
        for (int i = 0; i < 4; i++) {
            putLe32(out, 16 + i * 4, state[12 + i]);
        }
        return out;
    }

    private static void quarterRound(int[] s, int a, int b, int c, int d) {
        s[a] += s[b];
        s[d] = Integer.rotateLeft(s[d] ^ s[a], 16);
        s[c] += s[d];
        s[b] = Integer.rotateLeft(s[b] ^ s[c], 12);
        s[a] += s[b];
        s[d] = Integer.rotateLeft(s[d] ^ s[a], 8);
        s[c] += s[d];
        s[b] = Integer.rotateLeft(s[b] ^ s[c], 7);
    }

    private static int le32(byte[] b, int off) {
        return (b[off] & 0xff)
                | ((b[off + 1] & 0xff) << 8)
                | ((b[off + 2] & 0xff) << 16)
                | ((b[off + 3] & 0xff) << 24);
    }

    private static void putLe32(byte[] b, int off, int v) {
        b[off] = (byte) v;
        b[off + 1] = (byte) (v >>> 8);
        b[off + 2] = (byte) (v >>> 16);
        b[off + 3] = (byte) (v >>> 24);
    }
}
