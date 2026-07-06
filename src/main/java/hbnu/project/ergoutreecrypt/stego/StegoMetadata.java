package hbnu.project.ergoutreecrypt.stego;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * 图像隐写元数据头编解码。
 *
 * <p>在图片像素开头嵌入固定格式的二进制头，供提取时识别与还原。
 * 头结构（Big-Endian）：
 * <pre>
 *   MAGIC        16 B    "EGTC-STEGO-IMG01"
 *   VERSION      1  B    元数据格式版本
 *   FLAGS        1  B    [lsbDepth:2][hasMac:1][paranoid:1][reserved:4]
 *   CHANNELS     1  B    有效通道数（3=RGB, 4=RGBA 仍写 3 因跳过 alpha）
 *   PAYLOAD_SIZE 8  B    原始文件字节数 (long)
 *   FILE_NAME_LEN 4 B    文件名 UTF-8 字节数 (int)
 *   FILE_NAME    var     原始文件名 UTF-8 字节
 *   SALT         16 B    Argon2 salt
 *   HKDF_SALT    32 B    HKDF-SHA3-256 salt
 *   NONCE        24 B    XChaCha20 nonce
 *   PAYLOAD_MAC  64 B    BLAKE2b-512（可选，hasMac=1 时存在）
 * </pre>
 *
 * @author ErgouTree
 */
public final class StegoMetadata {

    /**
     * 固定魔数（ASCII）。
     */
    public static final byte[] MAGIC = "EGTC-STEGO-IMG01".getBytes(StandardCharsets.US_ASCII);

    /**
     * 元数据格式版本。
     */
    public static final byte VERSION = 1;

    /**
     * 无 MAC 时最小头长度 = 16 + 1 + 1 + 1 + 8 + 4 + 16 + 32 + 24 = 103。
     */
    private static final int BASE_HEADER_SIZE = 103;

    /**
     * MAC 长度 = 64。
     */
    private static final int MAC_SIZE = 64;

    // ---- 字段 ----
    private final byte flags;
    private final byte channels;
    private final long payloadSize;
    private final String fileName;
    private final byte[] salt;
    private final byte[] hkdfSalt;
    private final byte[] nonce;
    private final byte[] payloadMac;

    private StegoMetadata(final Builder builder) {
        this.flags = builder.flags;
        this.channels = builder.channels;
        this.payloadSize = builder.payloadSize;
        this.fileName = builder.fileName;
        this.salt = builder.salt;
        this.hkdfSalt = builder.hkdfSalt;
        this.nonce = builder.nonce;
        this.payloadMac = builder.payloadMac;
    }

    /**
     * 将元数据序列化为字节数组（嵌入用）。
     *
     * @return 完整的头字节数组
     */
    public byte[] toBytes() {
        byte[] nameBytes = fileName.getBytes(StandardCharsets.UTF_8);
        int total = BASE_HEADER_SIZE + nameBytes.length + (hasMac() ? MAC_SIZE : 0);
        ByteBuffer bb = ByteBuffer.allocate(total).order(ByteOrder.BIG_ENDIAN);
        bb.put(MAGIC);                                 // 16
        bb.put(VERSION);                               // 1
        bb.put(flags);                                 // 1
        bb.put(channels);                              // 1
        bb.putLong(payloadSize);                       // 8
        bb.putInt(nameBytes.length);                   // 4
        bb.put(nameBytes);                             // var
        bb.put(salt);                                  // 16
        bb.put(hkdfSalt);                              // 32
        bb.put(nonce);                                 // 24
        if (hasMac() && payloadMac != null) {
            bb.put(payloadMac);                        // 64
        }
        return bb.array();
    }

    /**
     * 从字节数组反序列化（提取用）。
     *
     * @param raw 完整的头字节数组
     * @return 解析后的 {@link StegoMetadata}
     * @throws ImageStegoException 魔数不匹配或数据不完整
     */
    public static StegoMetadata fromBytes(final byte[] raw) throws ImageStegoException {
        if (raw.length < BASE_HEADER_SIZE) {
            throw new ImageStegoException("元数据头不完整，长度不足 " + BASE_HEADER_SIZE);
        }
        ByteBuffer bb = ByteBuffer.wrap(raw).order(ByteOrder.BIG_ENDIAN);

        // 魔数
        byte[] magic = new byte[16];
        bb.get(magic);
        if (!Arrays.equals(magic, MAGIC)) {
            throw new ImageStegoException("未检测到本工具的隐写数据（魔数不匹配）");
        }

        // 版本
        byte version = bb.get();
        if (version != VERSION) {
            throw new ImageStegoException("不支持的元数据版本: " + version);
        }

        // flags
        byte flags = bb.get();
        byte channels = bb.get();
        long payloadSize = bb.getLong();
        int nameLen = bb.getInt();

        if (nameLen < 0 || nameLen > 1024) {
            throw new ImageStegoException("文件名长度异常: " + nameLen);
        }
        if (raw.length < BASE_HEADER_SIZE + nameLen + (hasMacFlag(flags) ? MAC_SIZE : 0)) {
            throw new ImageStegoException("元数据头不完整（文件名/可选MAC区域不足）");
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
                .payloadMac(payloadMac)
                .build();
    }

    /**
     * 计算给定配置下的头字节数。
     *
     * @param fileName 原始文件名
     * @param hasMac   是否有 MAC
     * @return 头字节数
     */
    public static int headerSize(final String fileName, final boolean hasMac) {
        int nameLen = fileName.getBytes(StandardCharsets.UTF_8).length;
        return BASE_HEADER_SIZE + nameLen + (hasMac ? MAC_SIZE : 0);
    }

    /**
     * 根据 flags 字节判断是否有 MAC。
     */
    private static boolean hasMacFlag(final byte flags) {
        return ((flags >> 4) & 1) == 1;
    }

    // ---- 访问器 ----

    /** @return LSB 深度（1–4） */
    public int lsbDepth() { return (flags & 0x03) + 1; }

    /** @return 是否有 MAC */
    public boolean hasMac() { return hasMacFlag(flags); }

    /** @return 是否 paranoid 模式 */
    public boolean isParanoid() { return ((flags >> 5) & 1) == 1; }

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

    /** @return 原文 MAC（可能为 null） */
    public byte[] payloadMac() { return payloadMac != null ? payloadMac.clone() : null; }

    /**
     * @return 当前 flags 字节值
     */
    public byte flags() { return flags; }

    // ---- 构建器 ----

    /**
     * @return 新的构建器
     */
    public static Builder builder() {
        return new Builder();
    }

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
        private byte[] payloadMac;

        /**
         * @param depth LSB 深度（1–4）
         * @return 当前构建器
         */
        public Builder lsbDepth(final int depth) {
            flags = (byte) ((flags & 0xFC) | ((depth - 1) & 0x03));
            return this;
        }

        /**
         * @param hasMac 是否有 MAC
         * @return 当前构建器
         */
        public Builder hasMac(final boolean hasMac) {
            if (hasMac) {
                flags = (byte) (flags | 0x10);
            } else {
                flags = (byte) (flags & ~0x10);
            }
            return this;
        }

        /**
         * @param paranoid 是否 paranoid 模式
         * @return 当前构建器
         */
        public Builder paranoid(final boolean paranoid) {
            if (paranoid) {
                flags = (byte) (flags | 0x20);
            } else {
                flags = (byte) (flags & ~0x20);
            }
            return this;
        }

        /**
         * @param f flags 字节值
         * @return 当前构建器
         */
        Builder flags(final byte f) {
            this.flags = f;
            return this;
        }

        /**
         * @param ch 有效通道数
         * @return 当前构建器
         */
        public Builder channels(final int ch) {
            this.channels = (byte) ch;
            return this;
        }

        /**
         * @param size 原始文件字节数
         * @return 当前构建器
         */
        public Builder payloadSize(final long size) {
            this.payloadSize = size;
            return this;
        }

        /**
         * @param name 原始文件名
         * @return 当前构建器
         */
        public Builder fileName(final String name) {
            this.fileName = name != null ? name : "unknown";
            return this;
        }

        /**
         * @param s Argon2 salt（16 字节）
         * @return 当前构建器
         */
        public Builder salt(final byte[] s) {
            this.salt = s != null ? s.clone() : new byte[16];
            return this;
        }

        /**
         * @param hs HKDF-SHA3-256 salt（32 字节）
         * @return 当前构建器
         */
        public Builder hkdfSalt(final byte[] hs) {
            this.hkdfSalt = hs != null ? hs.clone() : new byte[32];
            return this;
        }

        /**
         * @param n XChaCha20 nonce（24 字节）
         * @return 当前构建器
         */
        public Builder nonce(final byte[] n) {
            this.nonce = n != null ? n.clone() : new byte[24];
            return this;
        }

        /**
         * @param mac BLAKE2b-512 MAC（64 字节，可选）
         * @return 当前构建器
         */
        public Builder payloadMac(final byte[] mac) {
            this.payloadMac = mac != null ? mac.clone() : null;
            return this;
        }

        /**
         * @return 构建 {@link StegoMetadata} 实例
         */
        public StegoMetadata build() {
            return new StegoMetadata(this);
        }
    }
}
