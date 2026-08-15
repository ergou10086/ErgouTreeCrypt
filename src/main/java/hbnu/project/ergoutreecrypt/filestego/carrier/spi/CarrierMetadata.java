package hbnu.project.ergoutreecrypt.filestego.carrier.spi;

import hbnu.project.ergoutreecrypt.filestego.api.Argon2Params;
import hbnu.project.ergoutreecrypt.filestego.api.CarrierException;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

/**
 * 载体层元数据——存储密钥派生所需的密码学参数。
 *
 * <p>与 Payload 层的 JSON Metadata（描述原始文件信息）不同，CarrierMetadata
 * 存放的是密码学关键数据（盐、nonce 等），以固定二进制布局存储在各载体格式的
 * "解码器忽略"区域（末尾追加、自定义 chunk/box 等）。
 *
 * <h3>二进制布局</h3>
 * <pre>
 *   MAGIC          4 bytes   "EGFS" (0x45474653)
 *   VERSION        1 byte    uint8 (1)
 *   PAYLOAD_SIZE   8 bytes   uint64 (Payload 总字节数)
 *   FLAGS          1 byte    bitfield
 *                            [paranoid:1][hasIntegrity:1][stealth:1][reserved:5]
 *   SALT          16 bytes   Argon2id salt
 *   HKDF_SALT     32 bytes   HKDF salt
 *   NONCE         24 bytes   XChaCha20 nonce
 *   SERPENT_IV    16 bytes   仅 paranoid 模式时存在
 *   STEALTH_SALT  16 bytes   仅 stealth 模式时存在
 *   ARGON2_MEM    4 bytes   uint32 Argon2 内存参数覆写（KiB），0 = 使用默认
 *   ARGON2_PASS   1 byte    Argon2 迭代次数覆写，0 = 使用默认
 *   ARGON2_THREAD 1 byte    Argon2 并行线程覆写，0 = 使用默认
 *   RESERVED      2 bytes   未来扩展（全 0）
 * </pre>
 *
 * <p>固定部分：4+1+8+1+16+32+24+8 = 94 字节。
 * 含 SERPENT_IV 时加 16 字节，含 STEALTH_SALT 时加 16 字节。
 * 不含两者 = 94 字节，含两者 = 126 字节。
 *
 * <p>ARGON2 三字段全零（旧文件）表示使用默认参数（见
 * {@link hbnu.project.ergoutreecrypt.crypto.CryptoConstants}）；
 * 非零时须构成合法组合，否则视为格式损坏。
 *
 * @author ErgouTree
 * @since 2026/8/5
 */
public final class CarrierMetadata {

    /**
     * 载体元数据魔数 "EGFS"
     */
    static final byte[] MAGIC = {0x45, 0x47, 0x46, 0x53};
    /**
     * 魔数字节长度（公开常量，供各适配器使用）。
     */
    public static final int MAGIC_LEN = 4;

    /**
     * 当前元数据版本
     */
    static final byte VERSION = 1;

    /**
     * 固定部分字节数：MAGIC(4)+VERSION(1)+PAYLOAD_SIZE(8)+FLAGS(1)+SALT(16)+HKDF_SALT(32)+NONCE(24)+RESERVED(8)
     */
    private static final int FIXED_SIZE = 4 + 1 + 8 + 1 + 16 + 32 + 24 + 8;

    /**
     * Serpent IV 长度
     */
    private static final int SERPENT_IV_LEN = 16;
    /**
     * 隐蔽模式盐长度
     */
    private static final int STEALTH_SALT_LEN = 16;

    /**
     * FLAGS bit 定义
     */
    private static final int FLAG_PARANOID = 0x01;
    private static final int FLAG_HAS_INTEGRITY = 0x02;
    private static final int FLAG_STEALTH = 0x04;

    /**
     * Payload 总字节数
     */
    private final long payloadSize;
    /**
     * 标志位
     */
    private final byte flags;
    /**
     * Argon2id 盐（16 字节）
     */
    private final byte[] salt;
    /**
     * HKDF 盐（32 字节）
     */
    private final byte[] hkdfSalt;
    /**
     * XChaCha20 nonce（24 字节）
     */
    private final byte[] nonce;
    /**
     * Serpent-CTR IV（16 字节，仅 paranoid 模式）
     */
    private final byte[] serpentIv;
    /**
     * 隐蔽模式盐（16 字节，仅 stealth 模式）
     */
    private final byte[] stealthSalt;

    /**
     * Argon2 参数覆写（null 表示使用默认参数，见 RESERVED 字段布局）。
     */
    private final Argon2Params argon2Params;

    /**
     * 创建载体元数据实例（Argon2 参数使用默认值）。
     *
     * @param payloadSize Payload 总字节数
     * @param flags       标志位
     * @param salt        Argon2id 盐（必须 16 字节）
     * @param hkdfSalt    HKDF 盐（必须 32 字节）
     * @param nonce       XChaCha20 nonce（必须 24 字节）
     * @param serpentIv   Serpent IV（paranoid 模式时提供，否则为 null）
     * @param stealthSalt 隐蔽模式盐（stealth 模式时提供，否则为 null）
     */
    public CarrierMetadata(final long payloadSize, final byte flags,
                           final byte[] salt, final byte[] hkdfSalt, final byte[] nonce,
                           final byte[] serpentIv, final byte[] stealthSalt) {
        this(payloadSize, flags, salt, hkdfSalt, nonce, serpentIv, stealthSalt, null);
    }

    /**
     * 创建载体元数据实例。
     *
     * @param payloadSize  Payload 总字节数
     * @param flags        标志位
     * @param salt         Argon2id 盐（必须 16 字节）
     * @param hkdfSalt     HKDF 盐（必须 32 字节）
     * @param nonce        XChaCha20 nonce（必须 24 字节）
     * @param serpentIv    Serpent IV（paranoid 模式时提供，否则为 null）
     * @param stealthSalt  隐蔽模式盐（stealth 模式时提供，否则为 null）
     * @param argon2Params Argon2 参数覆写（可为 null 表示使用默认参数）
     */
    public CarrierMetadata(final long payloadSize, final byte flags,
                           final byte[] salt, final byte[] hkdfSalt, final byte[] nonce,
                           final byte[] serpentIv, final byte[] stealthSalt,
                           final Argon2Params argon2Params) {
        this.payloadSize = payloadSize;
        this.flags = flags;
        this.salt = salt.clone();
        this.hkdfSalt = hkdfSalt.clone();
        this.nonce = nonce.clone();
        this.serpentIv = (serpentIv != null) ? serpentIv.clone() : null;
        this.stealthSalt = (stealthSalt != null) ? stealthSalt.clone() : null;
        this.argon2Params = argon2Params;
    }

    /**
     * 计算此元数据序列化后的总字节数。
     *
     * @param paranoid 是否为 paranoid 模式
     * @param stealth  是否为隐蔽模式
     * @return 序列化后的字节数
     */
    public static int totalSize(final boolean paranoid, final boolean stealth) {
        int size = FIXED_SIZE;
        if (paranoid) {
            size += SERPENT_IV_LEN;
        }
        if (stealth) {
            size += STEALTH_SALT_LEN;
        }
        return size;
    }

    /**
     * 从字节数组反序列化载体元数据。
     *
     * @param raw 完整的载体元数据字节数组
     * @return 解析后的 {@link CarrierMetadata} 实例
     * @throws CarrierException 如果数据格式不合法
     */
    public static CarrierMetadata fromBytes(final byte[] raw) throws CarrierException {
        if (raw.length < FIXED_SIZE) {
            throw new CarrierException("载体元数据太短: " + raw.length + " < " + FIXED_SIZE);
        }
        ByteBuffer bb = ByteBuffer.wrap(raw).order(ByteOrder.BIG_ENDIAN);

        // 验证魔数
        byte[] magic = new byte[MAGIC_LEN];
        bb.get(magic);
        if (!Arrays.equals(magic, MAGIC)) {
            throw new CarrierException("载体元数据魔数不匹配");
        }

        // 验证版本
        byte version = bb.get();
        if (version != VERSION) {
            throw new CarrierException("不支持的载体元数据版本: " + version);
        }

        long payloadSize = bb.getLong();
        byte flags = bb.get();

        boolean paranoid = (flags & FLAG_PARANOID) != 0;
        boolean stealth = (flags & FLAG_STEALTH) != 0;

        byte[] salt = new byte[16];
        bb.get(salt);

        byte[] hkdfSalt = new byte[32];
        bb.get(hkdfSalt);

        byte[] nonce = new byte[24];
        bb.get(nonce);

        // 读取可选字段
        byte[] serpentIv = null;
        if (paranoid && bb.remaining() >= SERPENT_IV_LEN) {
            serpentIv = new byte[SERPENT_IV_LEN];
            bb.get(serpentIv);
        }

        byte[] stealthSalt = null;
        if (stealth && bb.remaining() >= STEALTH_SALT_LEN) {
            stealthSalt = new byte[STEALTH_SALT_LEN];
            bb.get(stealthSalt);
        }

        // RESERVED 字段（8 字节）：ARGON2_MEM(4) + ARGON2_PASS(1) + ARGON2_THREAD(1) + RESERVED(2)
        Argon2Params argon2Params = null;
        if (bb.remaining() >= 8) {
            int memoryKiB = bb.getInt();
            int passes = Byte.toUnsignedInt(bb.get());
            int threads = Byte.toUnsignedInt(bb.get());
            bb.getShort();
            if (memoryKiB != 0 || passes != 0 || threads != 0) {
                argon2Params = new Argon2Params(memoryKiB, passes, threads);
                if (!argon2Params.isValid()) {
                    throw new CarrierException("载体元数据 Argon2 参数非法: "
                            + "memoryKiB=" + memoryKiB + ", passes=" + passes
                            + ", threads=" + threads);
                }
            }
        }

        return new CarrierMetadata(payloadSize, flags, salt, hkdfSalt, nonce,
                serpentIv, stealthSalt, argon2Params);
    }

    /**
     * 从给定参数构建 flags 字节。
     *
     * @param paranoid     是否为 paranoid 模式
     * @param hasIntegrity 是否存储完整性校验
     * @param stealth      是否为隐蔽模式
     * @return flags 字节
     */
    public static byte buildFlags(final boolean paranoid, final boolean hasIntegrity,
                                  final boolean stealth) {
        byte f = 0;
        if (paranoid) {
            f |= FLAG_PARANOID;
        }
        if (hasIntegrity) {
            f |= FLAG_HAS_INTEGRITY;
        }
        if (stealth) {
            f |= FLAG_STEALTH;
        }
        return f;
    }

    /**
     * 快速检测字节数组是否以载体元数据魔数 "EGFS" 开头。
     *
     * @param data 待检测的字节数组
     * @return true 如果以 EGFS 魔数开头
     */
    public static boolean startsWithMagic(final byte[] data) {
        if (data.length < MAGIC_LEN) {
            return false;
        }
        for (int i = 0; i < MAGIC_LEN; i++) {
            if (data[i] != MAGIC[i]) {
                return false;
            }
        }
        return true;
    }

    /**
     * @return Payload 总字节数
     */
    public long payloadSize() {
        return payloadSize;
    }

    /**
     * @return Argon2id 盐（16 字节副本）
     */
    public byte[] salt() {
        return salt.clone();
    }

    /**
     * @return HKDF 盐（32 字节副本）
     */
    public byte[] hkdfSalt() {
        return hkdfSalt.clone();
    }

    /**
     * @return XChaCha20 nonce（24 字节副本）
     */
    public byte[] nonce() {
        return nonce.clone();
    }

    /**
     * @return Serpent IV（16 字节副本，非 paranoid 模式返回 null）
     */
    public byte[] serpentIv() {
        return (serpentIv != null) ? serpentIv.clone() : null;
    }

    /**
     * @return 隐蔽模式盐（16 字节副本，非 stealth 模式返回 null）
     */
    public byte[] stealthSalt() {
        return (stealthSalt != null) ? stealthSalt.clone() : null;
    }

    /**
     * @return 是否为 paranoid 模式
     */
    public boolean isParanoid() {
        return (flags & FLAG_PARANOID) != 0;
    }

    /**
     * @return 是否存储完整性校验
     */
    public boolean hasIntegrity() {
        return (flags & FLAG_HAS_INTEGRITY) != 0;
    }

    /**
     * @return 是否为隐蔽模式
     */
    public boolean isStealth() {
        return (flags & FLAG_STEALTH) != 0;
    }

    /**
     * @return 原始 flags 字节
     */
    public byte flags() {
        return flags;
    }

    /**
     * 验证魔数是否匹配。
     *
     * @return true 如果魔数正确
     */
    public boolean isValid() {
        return true;
    }

    /**
     * @return Argon2 参数覆写（null 表示使用默认参数）
     */
    public Argon2Params argon2Params() {
        return argon2Params;
    }

    /**
     * 序列化为字节数组。
     *
     * @return 完整的载体元数据字节数组
     */
    public byte[] toBytes() {
        boolean paranoid = isParanoid();
        boolean stealth = isStealth();
        int total = totalSize(paranoid, stealth);

        ByteBuffer bb = ByteBuffer.allocate(total).order(ByteOrder.BIG_ENDIAN);
        bb.put(MAGIC);
        bb.put(VERSION);
        bb.putLong(payloadSize);
        bb.put(flags);
        bb.put(salt);
        bb.put(hkdfSalt);
        bb.put(nonce);
        if (paranoid && serpentIv != null) {
            bb.put(serpentIv);
        } else if (paranoid) {
            bb.put(new byte[SERPENT_IV_LEN]);
        }
        if (stealth && stealthSalt != null) {
            bb.put(stealthSalt);
        } else if (stealth) {
            bb.put(new byte[STEALTH_SALT_LEN]);
        }
        // ARGON2 参数覆写（无覆写时全零，与旧格式一致）
        bb.putInt(argon2Params != null ? argon2Params.memoryKiB() : 0);
        bb.put((byte) (argon2Params != null ? argon2Params.passes() : 0));
        bb.put((byte) (argon2Params != null ? argon2Params.threads() : 0));
        // 保留字段填零
        bb.put(new byte[2]);

        return bb.array();
    }
}
