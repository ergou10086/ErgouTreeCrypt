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
     * v2.15 协议版本（含 Argon2 参数覆写支持）。
     *
     * <p>当加密端使用非默认 Argon2 参数（如 Android LIGHT 模式）时，
     * header 版本升级到 v2.15，新增 Argon2 参数块。
     */
    public static final String VERSION_V215 = "v2.15";

    /**
     * v2.16 协议版本（含加密前压缩标志）。
     *
     * <p>当加密端启用「加密前压缩」时，header 版本升级到 v2.16，新增单字节
     * 压缩标志（RS1 编码）。解密端据此在解密后对载荷做 Zstandard 解压。
     */
    public static final String VERSION_V216 = "v2.16";

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
     * Argon2id 内存参数（KiB）。0 表示未设置，解密时使用 paranoid 标志推断默认值。
     *
     * <p>仅 v2.15+ header 包含此字段。
     */
    private int argon2MemoryKib;

    /**
     * Argon2id 迭代次数。0 表示未设置，解密时使用 paranoid 标志推断默认值。
     *
     * <p>仅 v2.15+ header 包含此字段。
     */
    private int argon2Passes;

    /**
     * Argon2id 并行线程数。0 表示未设置，解密时使用 paranoid 标志推断默认值。
     *
     * <p>仅 v2.15+ header 包含此字段。
     */
    private int argon2Threads;

    /**
     * 载荷是否在加密前经过 Zstandard 压缩。
     *
     * <p>仅 v2.16+ header 包含此字段；解密端据此决定是否解压。
     */
    private boolean compressed;

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

    public int getArgon2MemoryKib() { return argon2MemoryKib; }
    public void setArgon2MemoryKib(int argon2MemoryKib) { this.argon2MemoryKib = argon2MemoryKib; }

    public int getArgon2Passes() { return argon2Passes; }
    public void setArgon2Passes(int argon2Passes) { this.argon2Passes = argon2Passes; }

    public int getArgon2Threads() { return argon2Threads; }
    public void setArgon2Threads(int argon2Threads) { this.argon2Threads = argon2Threads; }

    /**
     * 获取载荷是否在加密前经过 Zstandard 压缩。
     *
     * @return true 表示需要解压
     */
    public boolean isCompressed() { return compressed; }

    /**
     * 设置载荷是否在加密前经过 Zstandard 压缩。
     *
     * @param compressed 是否压缩
     */
    public void setCompressed(boolean compressed) { this.compressed = compressed; }

    /**
     * 是否包含有效的 Argon2 参数覆写。
     *
     * <p>任一字段 &gt; 0 即视为有效覆写。全为 0 表示使用默认参数（由 paranoid 标志决定）。
     *
     * @return 若有非零参数则返回 true
     */
    public boolean hasArgon2Params() {
        return argon2MemoryKib > 0 || argon2Passes > 0 || argon2Threads > 0;
    }

    /**
     * 是否为 v2.15+ 协议版本。
     *
     * @return 若版本为 {@value #VERSION_V215} 或更高则返回 true
     */
    public boolean isV215() {
        return VERSION_V215.compareTo(version) <= 0;
    }

    /**
     * 是否为 v2.16+ 协议版本（含加密前压缩标志）。
     *
     * @return 若版本为 {@value #VERSION_V216} 或更高则返回 true
     */
    public boolean isV216() {
        return VERSION_V216.compareTo(version) <= 0;
    }

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
