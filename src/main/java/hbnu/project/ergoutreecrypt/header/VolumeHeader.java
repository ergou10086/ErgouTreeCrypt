package hbnu.project.ergoutreecrypt.header;

import java.util.Arrays;

/**
 * 卷头字段容器。
 *
 * <p>包含版本、注释、标志位以及所有密码学参数（salt、hkdfSalt、serpentIV、nonce、
 * keyHash、keyfileHash、authTag）。注释以明文存储，不会被加密。
 *
 * @author ErgouTree
 */
public final class VolumeHeader {

    /**
     * 当前协议版本。解密老文件时会被读取值覆盖。
     */
    public static final String CURRENT_VERSION = "v2.14";

    /**
     * 注释最大长度（UTF-8 字节数上限）。
     */
    public static final int MAX_COMMENT_LEN = 99999;

    // ==================== 各字段原始长度（RS 编码前） ====================

    /**
     * Argon2 salt 长度：16 字节。
     */
    public static final int SALT_SIZE = 16;

    /**
     * HKDF-SHA3 salt 长度：32 字节。
     */
    public static final int HKDF_SALT_SIZE = 32;

    /**
     * Serpent IV 长度：16 字节。
     */
    public static final int SERPENT_IV_SIZE = 16;

    /**
     * XChaCha20 nonce 长度：24 字节。
     */
    public static final int NONCE_SIZE = 24;

    /**
     * Key hash 长度：64 字节（v2 HMAC-SHA3-512 / v1 SHA3-512(key)）。
     */
    public static final int KEY_HASH_SIZE = 64;

    /**
     * Keyfile hash 长度：32 字节（SHA3-256）。
     */
    public static final int KEYFILE_HASH_SIZE = 32;

    /**
     * Auth tag 长度：64 字节（BLAKE2b 或 HMAC-SHA3 载荷标签）。
     */
    public static final int AUTH_TAG_SIZE = 64;

    // ==================== 实例字段 ====================

    /**
     * 协议版本字符串（如 "v2.14"）。
     */
    private String version;

    /**
     * 明文注释（UTF-8 编码，最长 99999 字节）。
     */
    private String comments;

    /**
     * 卷头选项标志位。
     */
    private Flags flags;

    /**
     * Argon2id salt（16 字节）。
     */
    private byte[] salt;

    /**
     * HKDF-SHA3 salt（32 字节）。
     */
    private byte[] hkdfSalt;

    /**
     * Serpent-CTR IV（16 字节）。
     */
    private byte[] serpentIV;

    /**
     * XChaCha20 nonce（24 字节）。
     */
    private byte[] nonce;

    /**
     * 密钥验证哈希（64 字节）。
     */
    private byte[] keyHash;

    /**
     * keyfile 哈希（32 字节，SHA3-256）。
     */
    private byte[] keyfileHash;

    /**
     * 载荷认证标签（64 字节）。
     */
    private byte[] authTag;

    /**
     * 创建空 header（字段均为默认值/零长度数组），供 Reader 填充。
     */
    public VolumeHeader() {
        this.version = CURRENT_VERSION;
        this.comments = "";
        this.flags = new Flags();
        this.salt = new byte[0];
        this.hkdfSalt = new byte[0];
        this.serpentIV = new byte[0];
        this.nonce = new byte[0];
        this.keyHash = new byte[KEY_HASH_SIZE];
        this.keyfileHash = new byte[KEYFILE_HASH_SIZE];
        this.authTag = new byte[AUTH_TAG_SIZE];
    }

    /**
     * 创建含密码学参数的新 header（加密时使用）。
     *
     * @param salt      Argon2 salt（16 字节）
     * @param hkdfSalt  HKDF salt（32 字节）
     * @param serpentIV Serpent IV（16 字节）
     * @param nonce     XChaCha20 nonce（24 字节）
     */
    public VolumeHeader(byte[] salt, byte[] hkdfSalt, byte[] serpentIV, byte[] nonce) {
        this();
        this.version = CURRENT_VERSION;
        this.salt = salt.clone();
        this.hkdfSalt = hkdfSalt.clone();
        this.serpentIV = serpentIV.clone();
        this.nonce = nonce.clone();
    }

    /**
     * 是否为 v1.x 旧版本卷。
     *
     * @return 若 version 以 "v1" 开头则返回 true
     */
    public boolean isLegacyV1() {
        return version != null && version.length() >= 2 && version.startsWith("v1");
    }

    // ---- accessors ----

    public String getVersion() { return version; }
    public void setVersion(String version) { this.version = version; }

    public String getComments() { return comments; }
    public void setComments(String comments) { this.comments = comments; }

    public Flags getFlags() { return flags; }
    public void setFlags(Flags flags) { this.flags = flags; }

    public byte[] getSalt() { return salt; }
    public void setSalt(byte[] salt) { this.salt = salt; }

    public byte[] getHkdfSalt() { return hkdfSalt; }
    public void setHkdfSalt(byte[] hkdfSalt) { this.hkdfSalt = hkdfSalt; }

    public byte[] getSerpentIV() { return serpentIV; }
    public void setSerpentIV(byte[] serpentIV) { this.serpentIV = serpentIV; }

    public byte[] getNonce() { return nonce; }
    public void setNonce(byte[] nonce) { this.nonce = nonce; }

    public byte[] getKeyHash() { return keyHash; }
    public void setKeyHash(byte[] keyHash) { this.keyHash = keyHash; }

    public byte[] getKeyfileHash() { return keyfileHash; }
    public void setKeyfileHash(byte[] keyfileHash) { this.keyfileHash = keyfileHash; }

    public byte[] getAuthTag() { return authTag; }
    public void setAuthTag(byte[] authTag) { this.authTag = authTag; }

    @Override
    public String toString() {
        return "VolumeHeader{version=" + version
                + ", comments=" + comments
                + ", flags=" + flags
                + ", salt=" + Arrays.toString(salt)
                + ", hkdfSalt=" + Arrays.toString(hkdfSalt)
                + ", serpentIV=" + Arrays.toString(serpentIV)
                + ", nonce=" + Arrays.toString(nonce)
                + '}';
    }
}
