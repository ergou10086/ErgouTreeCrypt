package hbnu.project.ergoutreecrypt.crypto;

import org.bouncycastle.crypto.engines.ChaCha7539Engine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

/**
 * XChaCha20 流密码（24 字节 nonce，非认证）。
 *
 * <p>JDK 内置的 ChaCha20 仅支持 RFC 7539 的 12 字节 nonce，无法直接使用 24 字节 XNonce。
 * 本类按 XChaCha20 规范实现：
 * <ol>
 *   <li>用 HChaCha20(key, nonce[0:16]) 派生 32 字节子密钥；</li>
 *   <li>用该子密钥 + 12 字节子 nonce（4 字节零 || nonce[16:24]）跑标准 ChaCha20（RFC 7539）。</li>
 * </ol>
 *
 * <p>底层使用 BouncyCastle 的 {@link ChaCha7539Engine}，认证由上层 MAC 负责。
 *
 * @author ErgouTree
 */
public final class XChaCha20 {

    /**
     * ChaCha20 常量 "expand 32-byte k"（16 字节 ASCII）。
     */
    private static final byte[] SIGMA = {
            'e', 'x', 'p', 'a', 'n', 'd', ' ', '3', '2', '-', 'b', 'y', 't', 'e', ' ', 'k'
    };

    /**
     * 底层 ChaCha20（RFC 7539）引擎。
     */
    private final ChaCha7539Engine engine;

    /**
     * 创建 XChaCha20 流密码。
     *
     * @param key   32 字节密钥
     * @param nonce 24 字节 nonce
     * @throws IllegalArgumentException 若 key 或 nonce 长度不正确
     */
    public XChaCha20(byte[] key, byte[] nonce) {
        if (key.length != 32) {
            throw new IllegalArgumentException("XChaCha20 key must be 32 bytes, got " + key.length);
        }
        if (nonce.length != 24) {
            throw new IllegalArgumentException("XChaCha20 nonce must be 24 bytes, got " + nonce.length);
        }

        // HChaCha20 派生子密钥
        byte[] subKey = hChaCha20(key, nonce);

        // 子 nonce = 4 字节零 || nonce 后 8 字节，构成 RFC 7539 的 12 字节 nonce
        byte[] subNonce = new byte[12];
        System.arraycopy(nonce, 16, subNonce, 4, 8);

        engine = new ChaCha7539Engine();
        engine.init(true, new ParametersWithIV(new KeyParameter(subKey), subNonce));

        // 立即清零派生的子密钥
        SecureZero.zero(subKey);
    }

    /**
     * 流加解密处理（XOR keystream）。输入与输出可指向不同数组，长度须相同。
     * 流密码特性：加密与解密为同一操作。
     *
     * @param out 输出缓冲区
     * @param in  输入数据
     * @param len 处理字节数
     */
    public void process(byte[] out, byte[] in, int len) {
        engine.processBytes(in, 0, len, out, 0);
    }

    // ==================== HChaCha20 核心实现 ====================

    /**
     * HChaCha20：对 ChaCha20 块函数执行 20 轮（10 次双轮），不做最终加法，
     * 取首尾各 4 个 32-bit 字作为 32 字节输出。
     *
     * @param key     32 字节密钥
     * @param nonce16 16 字节 nonce（XNonce 的前 16 字节）
     * @return 32 字节派生子密钥
     */
    public static byte[] hChaCha20(byte[] key, byte[] nonce16) {
        int[] state = new int[16];

        // 填充初始状态：常数 || key || nonce
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

        // 20 轮（10 次双轮）
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

        // HChaCha20 输出 = state[0..3] || state[12..15]（不加初始状态）
        byte[] out = new byte[32];
        for (int i = 0; i < 4; i++) {
            putLe32(out, i * 4, state[i]);
        }
        for (int i = 0; i < 4; i++) {
            putLe32(out, 16 + i * 4, state[12 + i]);
        }
        return out;
    }

    /**
     * ChaCha20 四分之一轮运算：对 s[a], s[b], s[c], s[d] 执行 ARX 操作。
     */
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

    /**
     * 从字节数组偏移处读取 4 字节小端序 32 位整数。
     */
    private static int le32(byte[] b, int off) {
        return (b[off] & 0xff)
                | ((b[off + 1] & 0xff) << 8)
                | ((b[off + 2] & 0xff) << 16)
                | ((b[off + 3] & 0xff) << 24);
    }

    /**
     * 将 32 位整数以小端序写入字节数组偏移处。
     */
    private static void putLe32(byte[] b, int off, int v) {
        b[off] = (byte) v;
        b[off + 1] = (byte) (v >>> 8);
        b[off + 2] = (byte) (v >>> 16);
        b[off + 3] = (byte) (v >>> 24);
    }
}
