package hbnu.project.ergoutreecrypt.mediacrypt;

import hbnu.project.ergoutreecrypt.crypto.Argon2Kdf;
import hbnu.project.ergoutreecrypt.crypto.HkdfStream;
import hbnu.project.ergoutreecrypt.crypto.SecureZero;

/**
 * 音视频加密的密钥编排
 * 从密码派生独立的加密子密钥与 MAC 子密钥
 *
 * <p>流程复用主线 {@code crypto} 层原语：
 * <ol>
 *   <li>{@code masterKey = Argon2id(password, salt, paranoid)} —— 256 位主密钥；</li>
 *   <li>{@code HKDF-SHA3-256(masterKey, hkdfSalt)} 顺序读取 32 字节 {@code encKey}（XChaCha20）+ 32 字节 {@code macKey}（完整性 MAC）。</li>
 * </ol>
 *
 * <p>用 HKDF 分离两个子密钥，避免"用同一密钥既加密又做 MAC"的密钥复用问题。
 *
 * <p>本类实现 {@link AutoCloseable}，{@link #close()} 会清零所有派生密钥；务必以 try-with-resources 使用。
 *
 * @author ErgouTree
 */
public final class MediaKeySchedule implements AutoCloseable {

    /**
     * 加密子密钥长度（XChaCha20 key）。
     */
    public static final int ENC_KEY_LEN = 32;
    /**
     * MAC 子密钥长度。
     */
    public static final int MAC_KEY_LEN = 32;

    private final byte[] encKey;
    private final byte[] macKey;

    private MediaKeySchedule(byte[] encKey, byte[] macKey) {
        this.encKey = encKey;
        this.macKey = macKey;
    }

    /**
     * 派生密钥编排。
     *
     * @param password 已归一化（NFC）的密码 UTF-8 字节；调用方负责其生命周期
     * @param salt     16 字节 Argon2 salt
     * @param hkdfSalt 32 字节 HKDF salt
     * @param paranoid 是否使用偏执模式 Argon2 参数
     */
    public static MediaKeySchedule derive(byte[] password, byte[] salt, byte[] hkdfSalt,
                                          boolean paranoid) {
        return derive(password, salt, hkdfSalt, paranoid, null, null, null);
    }

    /**
     * 派生密钥编排（支持 Argon2 参数覆写）。
     *
     * <p>当 override 参数为非 null 时使用覆写值（Android 移动端用低内存档位适配），
     * 否则根据 paranoid 标志选择默认参数。桌面端沿用 4 参重载，行为不变。
     *
     * @param password            已归一化（NFC）的密码 UTF-8 字节；调用方负责其生命周期
     * @param salt                16 字节 Argon2 salt
     * @param hkdfSalt            32 字节 HKDF salt
     * @param paranoid            是否使用偏执模式 Argon2 参数
     * @param overrideMemoryKib   覆写内存参数（KiB），null 使用默认值
     * @param overridePasses      覆写迭代次数，null 使用默认值
     * @param overrideThreads     覆写并行线程数，null 使用默认值
     */
    public static MediaKeySchedule derive(byte[] password, byte[] salt, byte[] hkdfSalt,
                                          boolean paranoid, Integer overrideMemoryKib,
                                          Integer overridePasses, Integer overrideThreads) {
        byte[] master = Argon2Kdf.deriveKey(password, salt, paranoid,
                overrideMemoryKib, overridePasses, overrideThreads);
        try {
            HkdfStream hkdf = new HkdfStream(master, hkdfSalt);
            byte[] encKey = hkdf.read(ENC_KEY_LEN);
            byte[] macKey = hkdf.read(MAC_KEY_LEN);
            return new MediaKeySchedule(encKey, macKey);
        } finally {
            SecureZero.zero(master);
        }
    }

    /**
     * XChaCha20 加密子密钥（内部引用，请勿外部清零；由 {@link #close()} 负责）。
     */
    public byte[] encKey() {
        return encKey;
    }

    /**
     * 完整性 MAC 子密钥（内部引用，请勿外部清零；由 {@link #close()} 负责）。
     */
    public byte[] macKey() {
        return macKey;
    }

    @Override
    public void close() {
        SecureZero.zeroAll(encKey, macKey);
    }
}
