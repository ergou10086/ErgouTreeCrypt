package hbnu.project.ergoutreecrypt.stego;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * Chunk 结构隐写的尾部元数据格式。
 *
 * <p>追加在 IEND 块 + 加密载荷之后、文件末尾。自描述格式——从文件尾反向读取即可定位。
 *
 * <pre>
 *   encryptedSize 8B  long   加密载荷字节数
 *   fileNameLen   2B  short  文件名 UTF-8 字节数
 *   fileName     var  UTF-8  原始文件名
 *   salt         16B          Argon2 salt
 *   hkdfSalt     32B          HKDF-SHA3-256 salt
 *   nonce        24B          XChaCha20 nonce
 *   flags         1B          bit0=paranoid, bit1=hasMac
 *   payloadMac   64B  (可选)  BLAKE2b-512 MAC (hasMac=1 时)
 *   ──────────────────────── trailer 结束 ────────────────────────
 *   trailerSize   4B  int    上述 trailer 字节数（不含自身）
 *   magic        16B         固定魔数 "EGTC-CHUNK-END01"
 * </pre>
 *
 * @author ErgouTree
 */
final class ChunkTrailer {

    static final byte[] MAGIC = "EGTC-CHUNK-END01".getBytes(StandardCharsets.US_ASCII);
    static final int MAGIC_LEN = 16;
    static final int SIZE_FIELD_LEN = 4;
    /** trailerSize(4) + MAGIC(16) = 20 bytes after trailer body */
    static final int FOOTER_SUFFIX_LEN = SIZE_FIELD_LEN + MAGIC_LEN;

    private static final int FIXED_SIZE = 8 + 2 + 16 + 32 + 24 + 1; // 83
    private static final int MAC_SIZE = 64;

    final long encryptedSize;
    final String fileName;
    final byte[] salt;
    final byte[] hkdfSalt;
    final byte[] nonce;
    final byte flags;
    final byte[] payloadMac;

    ChunkTrailer(final long encryptedSize, final String fileName,
                 final byte[] salt, final byte[] hkdfSalt, final byte[] nonce,
                 final byte flags, final byte[] payloadMac) {
        this.encryptedSize = encryptedSize;
        this.fileName = fileName;
        this.salt = salt;
        this.hkdfSalt = hkdfSalt;
        this.nonce = nonce;
        this.flags = flags;
        this.payloadMac = payloadMac;
    }

    /** 序列化为字节数组。 */
    byte[] toBytes() {
        byte[] nameBytes = fileName.getBytes(StandardCharsets.UTF_8);
        int total = FIXED_SIZE + nameBytes.length + (hasMac() ? MAC_SIZE : 0);
        ByteBuffer bb = ByteBuffer.allocate(total).order(ByteOrder.BIG_ENDIAN);
        bb.putLong(encryptedSize);
        bb.putShort((short) nameBytes.length);
        bb.put(nameBytes);
        bb.put(salt);
        bb.put(hkdfSalt);
        bb.put(nonce);
        bb.put(flags);
        if (hasMac() && payloadMac != null) {
            bb.put(payloadMac);
        }
        return bb.array();
    }

    /** 从字节数组反序列化。 */
    static ChunkTrailer fromBytes(final byte[] raw) throws ImageStegoException {
        if (raw.length < FIXED_SIZE) {
            throw new ImageStegoException("Chunk trailer 太短: " + raw.length);
        }
        ByteBuffer bb = ByteBuffer.wrap(raw).order(ByteOrder.BIG_ENDIAN);
        long encryptedSize = bb.getLong();
        int nameLen = Short.toUnsignedInt(bb.getShort());
        if (nameLen < 0 || nameLen > 1024 || raw.length < FIXED_SIZE + nameLen) {
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

        byte[] payloadMac = null;
        if (hasMacFlag(flags) && bb.remaining() >= MAC_SIZE) {
            payloadMac = new byte[MAC_SIZE];
            bb.get(payloadMac);
        }
        return new ChunkTrailer(encryptedSize, fileName, salt, hkdfSalt, nonce, flags, payloadMac);
    }

    boolean hasMac() { return hasMacFlag(flags); }
    boolean isParanoid() { return (flags & 1) != 0; }
    static boolean hasMacFlag(final byte f) { return (f & 2) != 0; }

    /** 计算 trailer 所需的字节大小。 */
    static int trailerSize(final String fileName, final boolean hasMac) {
        return FIXED_SIZE + fileName.getBytes(StandardCharsets.UTF_8).length
                + (hasMac ? MAC_SIZE : 0);
    }
}
