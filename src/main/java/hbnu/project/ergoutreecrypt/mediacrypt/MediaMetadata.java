package hbnu.project.ergoutreecrypt.mediacrypt;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * 音视频加密的统一元数据块
 *
 * <p>等长（流密码 XOR）加密无法在 payload 内嵌 MAC，因此解密所需的全部参数与可选完整性校验值都封装在本元数据中
 * 写入容器自身"会被解码器忽略"的区域（WAV 自定义 chunk / MP3 ID3v2 PRIV 帧 / MP4 自定义 uuid box），从而不破坏媒体可播放性、不改变音频/视频数据长度。
 *
 * <p><b>二进制布局（定长，大端，便于稳定解析）</b>：
 * <pre>
 * 偏移  长度  字段
 *   0    8   magic     固定 "EGTC-AVE"（ASCII）
 *   8    1   version   元数据格式版本（当前 = 1）
 *   9    1   formatId  媒体格式（见 MediaFormat.formatId）
 *  10    1   profile   加密档位编码（见 MediaCryptProfile.code）
 *  11    1   flags     bit0=paranoid，bit1=hasIntegrity，其余保留
 *  12   16   salt      Argon2 salt
 *  28   32   hkdfSalt  HKDF salt（用于派生 enc/mac 子密钥）
 *  60   24   nonce     XChaCha20 base nonce
 *  84   64   plainMac  原文 payload 的 MAC（仅当 hasIntegrity，否则省略）
 * </pre>
 * 总长：{@value #BASE_LEN}（无 MAC）或 {@value #BASE_LEN} + 64（含 MAC）。
 *
 * <p>本类不可变，所有字节数组在构造/读取时拷贝，避免外部篡改内部状态。
 *
 * @author ErgouTree
 */
public final class MediaMetadata {

    /**
     * 魔数：标识本工具加密的媒体文件。
     */
    public static final byte[] MAGIC = "EGTC-AVE".getBytes(StandardCharsets.US_ASCII);

    /**
     * 当前元数据格式版本（v2 新增 Argon2 参数块，向后兼容读取 v1）。
     */
    public static final byte VERSION = 2;

    /**
     * v1 元数据版本（无 Argon2 参数块），仅用于向后兼容读取旧文件。
     */
    public static final byte VERSION_V1 = 1;

    /**
     * Argon2 参数块长度：4B memoryKiB（大端）+ 1B passes + 1B threads。
     */
    public static final int ARGON2_PARAMS_LEN = 6;

    /**
     * Argon2 salt 长度。
     */
    public static final int SALT_LEN = 16;
    /**
     * HKDF salt 长度。
     */
    public static final int HKDF_SALT_LEN = 32;
    /**
     * XChaCha20 base nonce 长度。
     */
    public static final int NONCE_LEN = 24;
    /**
     * 完整性 MAC 长度（BLAKE2b-512 / HMAC-SHA3-512）。
     */
    public static final int MAC_LEN = 64;

    private static final int OFF_VERSION = 8;
    private static final int OFF_FORMAT = 9;
    private static final int OFF_PROFILE = 10;
    private static final int OFF_FLAGS = 11;
    private static final int OFF_SALT = 12;
    private static final int OFF_HKDF_SALT = OFF_SALT + SALT_LEN;       // 28
    private static final int OFF_NONCE = OFF_HKDF_SALT + HKDF_SALT_LEN; // 60
    private static final int OFF_ARGON2 = OFF_NONCE + NONCE_LEN;        // 84

    /**
     * v1（无 Argon2 参数块）不含完整性 MAC 时的元数据总长。
     */
    public static final int BASE_LEN_V1 = OFF_NONCE + NONCE_LEN;        // 84

    /**
     * 不含完整性 MAC 时的元数据总长（v2，含 Argon2 参数块）。
     */
    public static final int BASE_LEN = OFF_ARGON2 + ARGON2_PARAMS_LEN;  // 90

    private static final int FLAG_PARANOID = 0x01;
    private static final int FLAG_HAS_INTEGRITY = 0x02;
    private static final int FLAG_HAS_CANARY = 0x04;

    /** 金丝雀令牌长度（16 字节）。 */
    public static final int CANARY_LEN = 16;

    private final MediaFormat format;
    private final MediaCryptProfile profile;
    private final boolean paranoid;
    private final byte[] salt;
    private final byte[] hkdfSalt;
    private final byte[] nonce;
    /**
     * 原文 payload MAC；null 表示未存储完整性校验。
     */
    private final byte[] plainMac;
    /**
     * 金丝雀令牌（16 字节）；null 表示未存储。
     */
    private final byte[] canary;

    /**
     * Argon2 内存参数（KiB）。0 表示未设置，解密时使用 paranoid 标志推断默认值。
     */
    private final int argon2MemoryKib;

    /**
     * Argon2 迭代次数。0 表示未设置。
     */
    private final int argon2Passes;

    /**
     * Argon2 并行线程数。0 表示未设置。
     */
    private final int argon2Threads;

    /**
     * 构造元数据。除 {@code plainMac} 外参数不得为空，长度必须匹配常量。
     *
     * @param plainMac 原文 MAC（64 字节）或 {@code null}（不存完整性校验）
     */
    /**
     * 构造元数据（无金丝雀，向后兼容）。
     */
    public MediaMetadata(MediaFormat format, MediaCryptProfile profile, boolean paranoid,
                         byte[] salt, byte[] hkdfSalt, byte[] nonce, byte[] plainMac) {
        this(format, profile, paranoid, salt, hkdfSalt, nonce, plainMac, null);
    }

    /**
     * 构造元数据（含金丝雀）。
     */
    public MediaMetadata(MediaFormat format, MediaCryptProfile profile, boolean paranoid,
                         byte[] salt, byte[] hkdfSalt, byte[] nonce, byte[] plainMac,
                         byte[] canary) {
        this(format, profile, paranoid, salt, hkdfSalt, nonce, plainMac, canary, 0, 0, 0);
    }

    /**
     * 构造元数据（含金丝雀与 Argon2 参数覆写）。
     *
     * @param argon2MemoryKib Argon2 内存参数（KiB），0 表示未设置
     * @param argon2Passes    Argon2 迭代次数，0 表示未设置
     * @param argon2Threads   Argon2 并行线程数，0 表示未设置
     */
    public MediaMetadata(MediaFormat format, MediaCryptProfile profile, boolean paranoid,
                         byte[] salt, byte[] hkdfSalt, byte[] nonce, byte[] plainMac,
                         byte[] canary, int argon2MemoryKib, int argon2Passes, int argon2Threads) {
        if (format == null || profile == null) {
            throw new IllegalArgumentException("format / profile 不能为空");
        }
        if (profile.format() != format) {
            throw new IllegalArgumentException("档位 " + profile + " 与格式 " + format + " 不匹配");
        }
        requireLen("salt", salt, SALT_LEN);
        requireLen("hkdfSalt", hkdfSalt, HKDF_SALT_LEN);
        requireLen("nonce", nonce, NONCE_LEN);
        if (plainMac != null && plainMac.length != MAC_LEN) {
            throw new IllegalArgumentException("plainMac 长度必须为 " + MAC_LEN);
        }
        if (canary != null && canary.length != CANARY_LEN) {
            throw new IllegalArgumentException("canary 长度必须为 " + CANARY_LEN);
        }
        this.format = format;
        this.profile = profile;
        this.paranoid = paranoid;
        this.salt = salt.clone();
        this.hkdfSalt = hkdfSalt.clone();
        this.nonce = nonce.clone();
        this.plainMac = plainMac == null ? null : plainMac.clone();
        this.canary = canary == null ? null : canary.clone();
        this.argon2MemoryKib = argon2MemoryKib;
        this.argon2Passes = argon2Passes;
        this.argon2Threads = argon2Threads;
    }

    private static void requireLen(String name, byte[] v, int len) {
        if (v == null || v.length != len) {
            throw new IllegalArgumentException(name + " 长度必须为 " + len);
        }
    }

    /**
     * 从字节块解析元数据。
     *
     * @throws MediaCryptException 魔数不符、版本不支持或长度不足
     */
    public static MediaMetadata fromBytes(byte[] data) throws MediaCryptException {
        if (data == null || data.length < BASE_LEN_V1) {
            throw new MediaCryptException("元数据长度不足，可能不是本工具加密的文件");
        }
        if (!hasMagic(data)) {
            throw new MediaCryptException("元数据魔数不符，可能不是本工具加密的文件");
        }
        byte version = data[OFF_VERSION];
        boolean hasArgon2;
        if (version == VERSION) {
            hasArgon2 = true;
        } else if (version == VERSION_V1) {
            hasArgon2 = false;
        } else {
            throw new MediaCryptException("不支持的元数据版本: " + version);
        }
        int baseLen = hasArgon2 ? BASE_LEN : BASE_LEN_V1;

        MediaFormat format;
        MediaCryptProfile profile;
        try {
            format = MediaFormat.fromId(data[OFF_FORMAT]);
            profile = MediaCryptProfile.fromCode(data[OFF_PROFILE]);
        } catch (IllegalArgumentException e) {
            throw new MediaCryptException("元数据中的格式/档位无法识别: " + e.getMessage(), e);
        }

        int flags = data[OFF_FLAGS] & 0xff;
        boolean paranoid = (flags & FLAG_PARANOID) != 0;
        boolean hasMac = (flags & FLAG_HAS_INTEGRITY) != 0;

        if (hasMac && data.length < baseLen + MAC_LEN) {
            throw new MediaCryptException("元数据标记含完整性 MAC 但长度不足");
        }

        byte[] salt = Arrays.copyOfRange(data, OFF_SALT, OFF_SALT + SALT_LEN);
        byte[] hkdfSalt = Arrays.copyOfRange(data, OFF_HKDF_SALT, OFF_HKDF_SALT + HKDF_SALT_LEN);
        byte[] nonce = Arrays.copyOfRange(data, OFF_NONCE, OFF_NONCE + NONCE_LEN);

        int argon2MemoryKib = 0;
        int argon2Passes = 0;
        int argon2Threads = 0;
        if (hasArgon2) {
            argon2MemoryKib = ((data[OFF_ARGON2] & 0xFF) << 24)
                    | ((data[OFF_ARGON2 + 1] & 0xFF) << 16)
                    | ((data[OFF_ARGON2 + 2] & 0xFF) << 8)
                    | (data[OFF_ARGON2 + 3] & 0xFF);
            argon2Passes = data[OFF_ARGON2 + 4] & 0xFF;
            argon2Threads = data[OFF_ARGON2 + 5] & 0xFF;
        }

        byte[] mac = hasMac ? Arrays.copyOfRange(data, baseLen, baseLen + MAC_LEN) : null;

        return new MediaMetadata(format, profile, paranoid, salt, hkdfSalt, nonce, mac, null,
                argon2MemoryKib, argon2Passes, argon2Threads);
    }

    /**
     * 快速判断字节块是否以本工具魔数开头（不做完整解析）。
     */
    public static boolean hasMagic(byte[] data) {
        if (data == null || data.length < MAGIC.length) {
            return false;
        }
        for (int i = 0; i < MAGIC.length; i++) {
            if (data[i] != MAGIC[i]) {
                return false;
            }
        }
        return true;
    }

    /**
     * 序列化为定长字节块（用于写入容器元数据载体）。
     */
    public byte[] toBytes() {
        boolean hasMac = plainMac != null;
        byte[] out = new byte[hasMac ? BASE_LEN + MAC_LEN : BASE_LEN];

        System.arraycopy(MAGIC, 0, out, 0, MAGIC.length);
        out[OFF_VERSION] = VERSION;
        out[OFF_FORMAT] = format.formatId();
        out[OFF_PROFILE] = profile.code();

        int flags = 0;
        if (paranoid) {
            flags |= FLAG_PARANOID;
        }
        if (hasMac) {
            flags |= FLAG_HAS_INTEGRITY;
        }
        out[OFF_FLAGS] = (byte) flags;

        System.arraycopy(salt, 0, out, OFF_SALT, SALT_LEN);
        System.arraycopy(hkdfSalt, 0, out, OFF_HKDF_SALT, HKDF_SALT_LEN);
        System.arraycopy(nonce, 0, out, OFF_NONCE, NONCE_LEN);

        // Argon2 参数块（memoryKiB 4B 大端 + passes 1B + threads 1B）
        out[OFF_ARGON2] = (byte) (argon2MemoryKib >>> 24);
        out[OFF_ARGON2 + 1] = (byte) (argon2MemoryKib >>> 16);
        out[OFF_ARGON2 + 2] = (byte) (argon2MemoryKib >>> 8);
        out[OFF_ARGON2 + 3] = (byte) argon2MemoryKib;
        out[OFF_ARGON2 + 4] = (byte) argon2Passes;
        out[OFF_ARGON2 + 5] = (byte) argon2Threads;

        if (hasMac) {
            System.arraycopy(plainMac, 0, out, BASE_LEN, MAC_LEN);
        }
        return out;
    }

    public MediaFormat format() {
        return format;
    }

    public MediaCryptProfile profile() {
        return profile;
    }

    public boolean paranoid() {
        return paranoid;
    }

    /**
     * Argon2 内存参数（KiB）；0 表示未设置，派生时使用默认值。
     */
    public int argon2MemoryKib() {
        return argon2MemoryKib;
    }

    /**
     * Argon2 迭代次数；0 表示未设置。
     */
    public int argon2Passes() {
        return argon2Passes;
    }

    /**
     * Argon2 并行线程数；0 表示未设置。
     */
    public int argon2Threads() {
        return argon2Threads;
    }

    /**
     * 是否包含有效的 Argon2 参数覆写。
     *
     * @return 任一字段 &gt; 0 返回 true
     */
    public boolean hasArgon2Params() {
        return argon2MemoryKib > 0 || argon2Passes > 0 || argon2Threads > 0;
    }

    public boolean hasIntegrity() {
        return plainMac != null;
    }

    public byte[] salt() {
        return salt.clone();
    }

    public byte[] hkdfSalt() {
        return hkdfSalt.clone();
    }

    public byte[] nonce() {
        return nonce.clone();
    }

    /**
     * 原文 MAC 拷贝；未存储完整性校验时返回 {@code null}。
     */
    public byte[] plainMac() {
        return plainMac == null ? null : plainMac.clone();
    }
}
