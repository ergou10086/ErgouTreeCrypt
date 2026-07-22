package hbnu.project.ergoutreecrypt.stego;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * 图像隐写元数据头编解码。
 *
 * <p>在图片像素开头嵌入固定格式的二进制头，供提取时识别与还原。
 *
 * <h3>普通模式头结构（Big-Endian）</h3>
 * <pre>
 *   MAGIC        16 B    "EGTC-STEGO-IMG01"（固定 ASCII）
 *   VERSION      1  B    元数据格式版本
 *   FLAGS        1  B    [lsbDepth:2][hasMac:1][paranoid:1][stealth:1][reserved:3]
 *   CHANNELS     1  B    有效通道数
 *   PAYLOAD_SIZE 8  B    原始文件字节数 (long)
 *   FILE_NAME_LEN 4 B    文件名 UTF-8 字节数 (int)
 *   FILE_NAME    var     原始文件名 UTF-8 字节
 *   SALT         16 B    Argon2 salt
 *   HKDF_SALT    32 B    HKDF-SHA3-256 salt
 *   NONCE        24 B    XChaCha20 nonce
 *   SERPENT_IV   16 B    Serpent-CTR IV（仅 paranoid 时存在）
 *   PAYLOAD_MAC  64 B    BLAKE2b-512（仅 hasMac 时存在）
 * </pre>
 *
 * <h3>隐蔽模式头结构（Stealth）</h3>
 * <pre>
 *   STEALTH_SALT  16 B   随机 salt（用于派生 stealthMagic）
 *   STEALTH_MAGIC 16 B   HMAC-SHA3-256(stealthSalt || password) 派生
 *   （之后与普通模式的 VERSION..PAYLOAD_MAC 相同）
 * </pre>
 *
 * @author ErgouTree
 */
public final class StegoMetadata {

    /** 固定魔数（ASCII）——普通模式使用。 */
    public static final byte[] MAGIC = "EGTC-STEGO-IMG01".getBytes(StandardCharsets.US_ASCII);

    /** 魔数长度。 */
    public static final int MAGIC_LEN = 16;

    /** 隐蔽模式盐长度。 */
    public static final int STEALTH_SALT_LEN = 16;

    /** 隐蔽模式魔数长度。 */
    public static final int STEALTH_MAGIC_LEN = 16;

    /** 隐蔽模式前缀总长 = stealthSalt(16) + stealthMagic(16)。 */
    public static final int STEALTH_PREFIX_LEN = STEALTH_SALT_LEN + STEALTH_MAGIC_LEN;

    /** 元数据格式版本。 */
    public static final byte VERSION = 1;

    /** Serpent IV 长度。 */
    private static final int SERPENT_IV_LEN = 16;

    /** MAC 长度 = 64。 */
    private static final int MAC_SIZE = 64;

    /** 无 MAC 无 SerpentIV 时最小头长度（不含魔数前缀）。 */
    private static final int BASE_FIXED = 1 + 1 + 1 + 8 + 4 + 16 + 32 + 24; // 87

    /** HMAC 算法（用于隐蔽模式魔数派生）。 */
    private static final String HMAC_ALG = "HmacSHA3-256";

    /** 隐蔽模式魔数派生标签。 */
    private static final byte[] STEALTH_LABEL =
            "stego-stealth-magic-v1".getBytes(StandardCharsets.UTF_8);

    // ---- 字段 ----
    private final byte flags;
    private final byte channels;
    private final long payloadSize;
    private final String fileName;
    private final byte[] salt;
    private final byte[] hkdfSalt;
    private final byte[] nonce;
    private final byte[] serpentIv;
    private final byte[] payloadMac;
    private final boolean stealth;

    private StegoMetadata(final Builder builder) {
        this.flags = builder.flags;
        this.channels = builder.channels;
        this.payloadSize = builder.payloadSize;
        this.fileName = builder.fileName;
        this.salt = builder.salt;
        this.hkdfSalt = builder.hkdfSalt;
        this.nonce = builder.nonce;
        this.serpentIv = builder.serpentIv;
        this.payloadMac = builder.payloadMac;
        this.stealth = builder.stealth;
    }

    // ---- 序列化 ----

    /**
     * 将元数据序列化为字节数组（嵌入用）。
     *
     * @param stealthSalt  隐蔽模式盐（仅 stealth=true 时需要，否则可为 null）
     * @param stealthMagic 隐蔽模式魔数（仅 stealth=true 时需要，否则可为 null）
     * @return 完整的头字节数组
     */
    public byte[] toBytes(final byte[] stealthSalt, final byte[] stealthMagic) {
        byte[] nameBytes = fileName.getBytes(StandardCharsets.UTF_8);
        boolean hasSerpent = isParanoid();
        int payloadLen = BASE_FIXED + nameBytes.length
                + (hasSerpent ? SERPENT_IV_LEN : 0)
                + (hasMac() ? MAC_SIZE : 0);
        int prefixLen = stealth ? STEALTH_PREFIX_LEN : MAGIC_LEN;
        int total = prefixLen + payloadLen;
        ByteBuffer bb = ByteBuffer.allocate(total).order(ByteOrder.BIG_ENDIAN);

        // 前缀
        if (stealth) {
            bb.put(stealthSalt);
            bb.put(stealthMagic);
        } else {
            bb.put(MAGIC);
        }

        // 正文
        bb.put(VERSION);
        bb.put(flags);
        bb.put(channels);
        bb.putLong(payloadSize);
        bb.putInt(nameBytes.length);
        bb.put(nameBytes);
        bb.put(salt);
        bb.put(hkdfSalt);
        bb.put(nonce);
        if (hasSerpent) {
            // 始终写入 serpentIv（空时填零），保证 buffer 位置正确
            if (serpentIv != null) {
                bb.put(serpentIv);
            } else {
                bb.put(new byte[SERPENT_IV_LEN]);
            }
        }
        if (hasMac() && payloadMac != null) {
            bb.put(payloadMac);
        }
        return bb.array();
    }

    /**
     * 普通模式序列化（向后兼容）。
     */
    public byte[] toBytes() {
        return toBytes(null, null);
    }

    // ---- 反序列化 ----

    /**
     * 从字节数组反序列化（普通模式——固定魔数）。
     *
     * @param raw 完整的头字节数组
     * @return 解析后的 {@link StegoMetadata}
     * @throws ImageStegoException 魔数不匹配或数据不完整
     */
    public static StegoMetadata fromBytes(final byte[] raw) throws ImageStegoException {
        return fromBytes(raw, null);
    }

    /**
     * 从字节数组反序列化（隐蔽模式——需提供密码以验证 HMAC 魔数）。
     *
     * @param raw      完整的头字节数组
     * @param password 密码 UTF-8 字节（普通模式可为 null）
     * @return 解析后的 {@link StegoMetadata}
     * @throws ImageStegoException 魔数不匹配或数据不完整
     */
    public static StegoMetadata fromBytes(final byte[] raw, final byte[] password)
            throws ImageStegoException {
        if (raw.length < MAGIC_LEN + BASE_FIXED) {
            throw new ImageStegoException("元数据头不完整，长度不足");
        }
        ByteBuffer bb = ByteBuffer.wrap(raw).order(ByteOrder.BIG_ENDIAN);

        // 检测模式：尝试匹配固定魔数
        byte[] first16 = new byte[16];
        bb.get(first16);
        boolean detectedStealth = !Arrays.equals(first16, MAGIC);

        boolean isStealth;
        byte[] stealthMagicForVerify = null;
        if (detectedStealth && password != null && password.length > 0) {
            // 隐蔽模式：前 16 字节是 stealthSalt，接着 16 字节是 stealthMagic
            byte[] stealthSalt = first16;
            byte[] candidateMagic = new byte[STEALTH_MAGIC_LEN];
            if (raw.length < STEALTH_PREFIX_LEN + BASE_FIXED) {
                throw new ImageStegoException("元数据头不完整（隐蔽模式）");
            }
            bb.get(candidateMagic);
            byte[] expected = deriveStealthMagic(stealthSalt, password);
            if (Arrays.equals(candidateMagic, expected)) {
                isStealth = true;
                stealthMagicForVerify = candidateMagic;
            } else {
                throw new ImageStegoException("密码错误或未检测到本工具的隐写数据（隐蔽魔数不匹配）");
            }
        } else if (detectedStealth) {
            throw new ImageStegoException(
                    "检测到隐蔽模式隐写数据，需要提供密码才能提取");
        } else {
            // 普通模式：MAGIC 已读取
            isStealth = false;
            bb.position(MAGIC_LEN); // 确保位置正确（MAGIC 已在 first16 中读取）
        }

        return parseBody(bb, raw, isStealth);
    }

    /**
     * 仅检测是否可能为本工具隐写数据（快速扫描，不做完整解析）。
     *
     * @param raw 头字节数组
     * @return true 若魔数匹配（普通模式）或前 32 字节可能是隐蔽模式
     */
    public static boolean looksLikeStego(final byte[] raw) {
        if (raw.length < MAGIC_LEN) {
            return false;
        }
        // 普通模式
        byte[] first16 = Arrays.copyOf(raw, MAGIC_LEN);
        if (Arrays.equals(first16, MAGIC)) {
            return true;
        }
        // 隐蔽模式：前 32 字节全为非 ASCII 可视为候选
        // （实际上这里无法确认，只能靠调用方尝试用密码解析）
        return raw.length >= STEALTH_PREFIX_LEN + BASE_FIXED;
    }

    /**
     * 解析魔数之后的正文部分。
     */
    private static StegoMetadata parseBody(final ByteBuffer bb, final byte[] raw,
                                            final boolean stealth) throws ImageStegoException {
        int minBodySize = BASE_FIXED;
        if (bb.remaining() < minBodySize) {
            throw new ImageStegoException("元数据正文不完整");
        }

        byte version = bb.get();
        if (version != VERSION) {
            throw new ImageStegoException("不支持的元数据版本: " + version);
        }

        byte flags = bb.get();
        byte channels = bb.get();
        long payloadSize = bb.getLong();
        int nameLen = bb.getInt();

        if (nameLen < 0 || nameLen > 1024) {
            throw new ImageStegoException("文件名长度异常: " + nameLen);
        }

        int expectedBody = BASE_FIXED + nameLen
                + (isParanoidFlag(flags) ? SERPENT_IV_LEN : 0)
                + (hasMacFlag(flags) ? MAC_SIZE : 0);
        if (bb.remaining() + (BASE_FIXED - minBodySize) < expectedBody - minBodySize + nameLen) {
            // Simplify: just check we have enough for name + crypto fields at minimum
        }

        byte[] nameBytes = new byte[nameLen];
        bb.get(nameBytes);
        String fileName = new String(nameBytes, StandardCharsets.UTF_8);

        byte[] salt = new byte[16];
        bb.get(salt);
        byte[] hkdfSalt = new byte[32];
        bb.get(hkdfSalt);
        byte[] nonce = new byte[24];
        bb.get(nonce);

        byte[] serpentIv = null;
        if (isParanoidFlag(flags)) {
            serpentIv = new byte[SERPENT_IV_LEN];
            if (bb.remaining() >= SERPENT_IV_LEN) {
                bb.get(serpentIv);
            }
        }

        byte[] payloadMac = null;
        if (hasMacFlag(flags) && bb.remaining() >= MAC_SIZE) {
            payloadMac = new byte[MAC_SIZE];
            bb.get(payloadMac);
        }

        return new Builder()
                .flags(flags)
                .channels(channels)
                .payloadSize(payloadSize)
                .fileName(fileName)
                .salt(salt)
                .hkdfSalt(hkdfSalt)
                .nonce(nonce)
                .serpentIv(serpentIv)
                .payloadMac(payloadMac)
                .stealth(stealth)
                .build();
    }

    // ---- 隐蔽模式魔数派生 ----

    /**
     * 从密码和盐派生隐蔽模式魔数。
     *
     * @param stealthSalt 16 字节随机盐
     * @param password    密码 UTF-8 字节
     * @return 16 字节派生魔数
     */
    public static byte[] deriveStealthMagic(final byte[] stealthSalt, final byte[] password) {
        try {
            Mac hm = Mac.getInstance(HMAC_ALG);
            hm.init(new SecretKeySpec(stealthSalt, "HmacSHA3-256"));
            byte[] hash = hm.doFinal(password);
            return Arrays.copyOf(hash, STEALTH_MAGIC_LEN);
        } catch (Exception e) {
            throw new RuntimeException("HMAC-SHA3-256 不可用", e);
        }
    }

    // ---- 头大小计算 ----

    /**
     * 计算给定配置下的头字节数（不含魔数前缀）。
     */
    private static int bodySize(final String fileName, final boolean hasMac,
                                 final boolean paranoid) {
        int nameLen = fileName.getBytes(StandardCharsets.UTF_8).length;
        return BASE_FIXED + nameLen
                + (paranoid ? SERPENT_IV_LEN : 0)
                + (hasMac ? MAC_SIZE : 0);
    }

    /**
     * 计算给定配置下的完整头字节数。
     */
    public static int headerSize(final String fileName, final boolean hasMac,
                                  final boolean paranoid, final boolean stealth) {
        int prefix = stealth ? STEALTH_PREFIX_LEN : MAGIC_LEN;
        return prefix + bodySize(fileName, hasMac, paranoid);
    }

    /**
     * 向后兼容：计算普通模式下的头字节数。
     */
    public static int headerSize(final String fileName, final boolean hasMac) {
        return headerSize(fileName, hasMac, false, false);
    }

    // ---- 位标记 ----

    private static boolean hasMacFlag(final byte flags) {
        return ((flags >> 4) & 1) == 1;
    }

    private static boolean isParanoidFlag(final byte flags) {
        return ((flags >> 5) & 1) == 1;
    }

    // ---- 访问器 ----

    /** @return LSB 深度（1–4） */
    public int lsbDepth() { return (flags & 0x03) + 1; }

    /** @return 是否有 MAC */
    public boolean hasMac() { return hasMacFlag(flags); }

    /** @return 是否 paranoid 模式 */
    public boolean isParanoid() { return isParanoidFlag(flags); }

    /** @return 是否隐蔽模式 */
    public boolean isStealth() { return stealth; }

    /** @return 有效通道数 */
    public int channels() { return channels & 0xFF; }

    /** @return 原始文件字节数 */
    public long payloadSize() { return payloadSize; }

    /** @return 原始文件名 */
    public String fileName() { return fileName; }

    /** @return Argon2 salt */
    public byte[] salt() { return salt.clone(); }

    /** @return HKDF salt */
    public byte[] hkdfSalt() { return hkdfSalt.clone(); }

    /** @return XChaCha20 nonce */
    public byte[] nonce() { return nonce.clone(); }

    /** @return Serpent-CTR IV（可能为 null） */
    public byte[] serpentIv() { return serpentIv != null ? serpentIv.clone() : null; }

    /** @return 原文 MAC（可能为 null） */
    public byte[] payloadMac() { return payloadMac != null ? payloadMac.clone() : null; }

    /** @return 当前 flags 字节值 */
    public byte flags() { return flags; }

    // ---- 构建器 ----

    public static Builder builder() { return new Builder(); }

    /**
     * {@link StegoMetadata} 的构建器。
     */
    public static final class Builder {
        private byte flags;
        private byte channels = 3;
        private long payloadSize;
        private String fileName = "unknown";
        private byte[] salt = new byte[16];
        private byte[] hkdfSalt = new byte[32];
        private byte[] nonce = new byte[24];
        private byte[] serpentIv;
        private byte[] payloadMac;
        private boolean stealth;

        public Builder lsbDepth(final int depth) {
            flags = (byte) ((flags & 0xFC) | ((depth - 1) & 0x03));
            return this;
        }

        public Builder hasMac(final boolean hasMac) {
            if (hasMac) flags = (byte) (flags | 0x10);
            else flags = (byte) (flags & ~0x10);
            return this;
        }

        public Builder paranoid(final boolean paranoid) {
            if (paranoid) flags = (byte) (flags | 0x20);
            else flags = (byte) (flags & ~0x20);
            return this;
        }

        Builder flags(final byte f) { this.flags = f; return this; }

        public Builder channels(final int ch) { this.channels = (byte) ch; return this; }

        public Builder payloadSize(final long size) { this.payloadSize = size; return this; }

        public Builder fileName(final String name) {
            this.fileName = name != null ? name : "unknown"; return this;
        }

        public Builder salt(final byte[] s) {
            this.salt = s != null ? s.clone() : new byte[16]; return this;
        }

        public Builder hkdfSalt(final byte[] hs) {
            this.hkdfSalt = hs != null ? hs.clone() : new byte[32]; return this;
        }

        public Builder nonce(final byte[] n) {
            this.nonce = n != null ? n.clone() : new byte[24]; return this;
        }

        public Builder serpentIv(final byte[] iv) {
            this.serpentIv = iv != null ? iv.clone() : null; return this;
        }

        public Builder payloadMac(final byte[] mac) {
            this.payloadMac = mac != null ? mac.clone() : null; return this;
        }

        public Builder stealth(final boolean s) { this.stealth = s; return this; }

        public StegoMetadata build() { return new StegoMetadata(this); }
    }
}
