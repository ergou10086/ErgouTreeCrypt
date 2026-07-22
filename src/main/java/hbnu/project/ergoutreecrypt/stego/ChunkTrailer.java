package hbnu.project.ergoutreecrypt.stego;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * Chunk 结构隐写的尾部元数据格式（v1.9.6）。
 *
 * <h3>文件布局</h3>
 * <pre>
 *   [加密载荷]
 *   ─────────── trailer 正文 ───────────
 *   encryptedSize 8B  long
 *   fileNameLen   2B  short
 *   fileName     var  UTF-8
 *   salt         16B
 *   hkdfSalt     32B
 *   nonce        24B
 *   flags         1B   bit0=paranoid, bit1=hasMac, bit2=stealth
 *   serpentIv    16B   (仅 paranoid 时)
 *   payloadMac   64B   (仅 hasMac 时)
 *   ─────────── trailer 后缀 ───────────
 *   trailerSize   4B  int    正文字节数
 *   [stealthSalt  16B]       (仅 stealth 时)
 *   magic-or-     16B        普通："EGTC-CHUNK-END01"
 *   stealthMagic             隐蔽：HMAC 派生
 * </pre>
 *
 * @author ErgouTree
 */
final class ChunkTrailer {

    static final byte[] MAGIC = "EGTC-CHUNK-END01".getBytes(StandardCharsets.US_ASCII);
    static final int MAGIC_LEN = 16;
    static final int STEALTH_MAGIC_LEN = 16;
    static final int STEALTH_SALT_LEN = 16;
    static final int FOOTER_SUFFIX_LEN = 4 + MAGIC_LEN;
    static final int STEALTH_FOOTER_SUFFIX_LEN = 4 + STEALTH_SALT_LEN + STEALTH_MAGIC_LEN;

    private static final int SERPENT_IV_LEN = 16;
    private static final int MAC_SIZE = 64;
    /**
     * 定长部分: encryptedSize(8)+nameLen(2)+salt(16)+hkdfSalt(32)+nonce(24)+flags(1) = 83
     */
    private static final int FIXED_SIZE = 8 + 2 + 16 + 32 + 24 + 1;

    private static final String HMAC_ALG = "HmacSHA3-256";

    final long encryptedSize;
    final String fileName;
    final byte[] salt;
    final byte[] hkdfSalt;
    final byte[] nonce;
    final byte[] serpentIv;
    final byte flags;
    final byte[] payloadMac;
    final boolean stealth;

    ChunkTrailer(final long encryptedSize, final String fileName,
                 final byte[] salt, final byte[] hkdfSalt, final byte[] nonce,
                 final byte[] serpentIv, final byte flags, final byte[] payloadMac,
                 final boolean stealth) {
        this.encryptedSize = encryptedSize;
        this.fileName = fileName;
        this.salt = salt;
        this.hkdfSalt = hkdfSalt;
        this.nonce = nonce;
        this.serpentIv = serpentIv;
        this.flags = flags;
        this.payloadMac = payloadMac;
        this.stealth = stealth;
    }

    /**
     * 向后兼容构造器（非 stealth、无 serpentIv）。
     */
    ChunkTrailer(final long encryptedSize, final String fileName,
                 final byte[] salt, final byte[] hkdfSalt, final byte[] nonce,
                 final byte flags, final byte[] payloadMac) {
        this(encryptedSize, fileName, salt, hkdfSalt, nonce, null, flags, payloadMac, false);
    }

    /**
     * 从字节数组反序列化。
     */
    static ChunkTrailer fromBytes(final byte[] raw) throws ImageStegoException {
        return fromBytes(raw, false);
    }

    /**
     * 从字节数组反序列化（可指定 stealth）。
     */
    static ChunkTrailer fromBytes(final byte[] raw, final boolean stealth)
            throws ImageStegoException {
        if (raw.length < FIXED_SIZE) {
            throw new ImageStegoException("Chunk trailer 太短: " + raw.length);
        }
        ByteBuffer bb = ByteBuffer.wrap(raw).order(ByteOrder.BIG_ENDIAN);
        long encryptedSize = bb.getLong();
        int nameLen = Short.toUnsignedInt(bb.getShort());
        if (nameLen < 0 || nameLen > 1024
                || raw.length < FIXED_SIZE + nameLen) {
            throw new ImageStegoException("Chunk trailer 文件名长度异常: " + nameLen);
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
        byte flags = bb.get();

        // 从 flags 判断后续字段
        boolean hasSerpent = isParanoidFlag(flags);
        boolean hasMac = hasMacFlag(flags);

        byte[] serpentIv = null;
        if (hasSerpent && bb.remaining() >= SERPENT_IV_LEN) {
            serpentIv = new byte[SERPENT_IV_LEN];
            bb.get(serpentIv);
        }

        byte[] payloadMac = null;
        if (hasMac && bb.remaining() >= MAC_SIZE) {
            payloadMac = new byte[MAC_SIZE];
            bb.get(payloadMac);
        }

        return new ChunkTrailer(encryptedSize, fileName, salt, hkdfSalt, nonce,
                serpentIv, flags, payloadMac, stealth);
    }

    static boolean hasMacFlag(final byte f) {
        return (f & 2) != 0;
    }

    static boolean isParanoidFlag(final byte f) {
        return (f & 1) != 0;
    }

    static boolean isStealthFlag(final byte f) {
        return (f & 4) != 0;
    }

    /**
     * 计算 trailer 正文所需字节大小。
     */
    static int trailerBodySize(final String fileName, final boolean hasMac,
                               final boolean paranoid) {
        int nameLen = fileName.getBytes(StandardCharsets.UTF_8).length;
        return FIXED_SIZE + nameLen
                + (paranoid ? SERPENT_IV_LEN : 0)
                + (hasMac ? MAC_SIZE : 0);
    }

    /**
     * 向后兼容。
     */
    static int trailerSize(final String fileName, final boolean hasMac) {
        return trailerBodySize(fileName, hasMac, false);
    }

    /**
     * 从密码和盐派生隐蔽模式魔数。
     */
    static byte[] deriveStealthMagic(final byte[] stealthSalt, final byte[] password) {
        try {
            Mac hm = Mac.getInstance(HMAC_ALG);
            hm.init(new SecretKeySpec(stealthSalt, "HmacSHA3-256"));
            byte[] hash = hm.doFinal(password);
            return Arrays.copyOf(hash, STEALTH_MAGIC_LEN);
        } catch (Exception e) {
            throw new RuntimeException("HMAC-SHA3-256 不可用", e);
        }
    }

    static boolean isMagicMatch(final byte[] tail) {
        return Arrays.equals(tail, MAGIC);
    }

    /**
     * 序列化 trailer 正文（不含尾部 trailerSize/magic/stealth 后缀）。
     */
    byte[] toBytes() {
        byte[] nameBytes = fileName.getBytes(StandardCharsets.UTF_8);
        boolean hasSerpentIv = isParanoid();
        int total = FIXED_SIZE + nameBytes.length
                + (hasSerpentIv ? SERPENT_IV_LEN : 0)
                + (hasMac() ? MAC_SIZE : 0);
        ByteBuffer bb = ByteBuffer.allocate(total).order(ByteOrder.BIG_ENDIAN);
        bb.putLong(encryptedSize);
        bb.putShort((short) nameBytes.length);
        bb.put(nameBytes);
        bb.put(salt);
        bb.put(hkdfSalt);
        bb.put(nonce);
        bb.put(flags);
        if (hasSerpentIv) {
            // 始终写入 16 字节（空时填零），保证 fromBytes 可正确解析
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

    boolean hasMac() {
        return hasMacFlag(flags);
    }

    boolean isParanoid() {
        return isParanoidFlag(flags);
    }
}
