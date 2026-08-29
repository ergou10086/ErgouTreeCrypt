package hbnu.project.ergoutreecrypt.filestego.codec;

import hbnu.project.ergoutreecrypt.compress.ZstdCompressor;
import hbnu.project.ergoutreecrypt.crypto.*;
import hbnu.project.ergoutreecrypt.filestego.api.Argon2Params;
import hbnu.project.ergoutreecrypt.filestego.api.PayloadException;
import hbnu.project.ergoutreecrypt.filestego.api.ProgressListener;
import hbnu.project.ergoutreecrypt.filestego.api.StegoEncodeOptions;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

/**
 * STEG-V2 Payload 编解码器——将文件加密为统一的 STEG-V2 格式，或从该格式解密还原。
 *
 * <h3>二进制布局</h3>
 * <pre>
 *   MAGIC         4 bytes   "STG2" (0x53544732)
 *   VERSION       2 bytes   uint16 big-endian (1)
 *   FLAGS         2 bytes   bitfield big-endian
 *   META_LENGTH   2 bytes   uint16 big-endian (N)
 *   METADATA      N bytes   UTF-8 JSON
 *   HEADER_MAC    64 bytes  可选，对 Header 部分的 MAC
 *   CIPHERTEXT    variable  加密后的文件数据
 *   PAYLOAD_MAC   64 bytes  可选，对密文的 MAC
 * </pre>
 *
 * <p>FLAGS 位定义：
 * <ul>
 *   <li>bit 0 — PARANOID：Serpent-CTR + XChaCha20 双层加密</li>
 *   <li>bit 1 — COMPRESSED：加密前进行了压缩</li>
 *   <li>bit 2 — HAS_INTEGRITY：包含 PAYLOAD_MAC</li>
 *   <li>bit 3 — HAS_HEADER_MAC：包含 HEADER_MAC</li>
 *   <li>bits 4–15 — 保留</li>
 * </ul>
 *
 * @author ErgouTree
 * @since 2026/8/5
 */
public final class PayloadCodec {

    /**
     * STEG-V2 魔数 "STG2"
     */
    static final byte[] MAGIC = {0x53, 0x54, 0x47, 0x32};

    /**
     * 魔数字节长度
     */
    static final int MAGIC_LEN = 4;

    /**
     * 当前 Payload 格式版本
     */
    private static final int VERSION = 1;

    /**
     * Header 定长部分：MAGIC(4)+VERSION(2)+FLAGS(2)+META_LENGTH(2) = 10
     */
    private static final int HEADER_FIXED_SIZE = 4 + 2 + 2 + 2;

    /**
     * 密钥长度
     */
    private static final int ENC_KEY_LEN = 32;
    private static final int MAC_KEY_LEN = 32;
    private static final int HEADER_MAC_KEY_LEN = 32;
    private static final int SERPENT_KEY_LEN = 32;
    private static final int SERPENT_IV_LEN = 16;

    /**
     * MAC 输出长度
     */
    private static final int MAC_SIZE = 64;

    /**
     * FLAGS 位定义
     */
    private static final int FLAG_PARANOID = 0x0001;
    private static final int FLAG_COMPRESSED = 0x0002;
    private static final int FLAG_HAS_INTEGRITY = 0x0004;
    private static final int FLAG_HAS_HEADER_MAC = 0x0008;

    /**
     * 内置默认密码
     */
    private static final byte[] DEFAULT_PASSWORD = "ErgouTree-stego-default-passphrase".getBytes(StandardCharsets.UTF_8);

    /**
     * 流式编解码分块大小（1 MiB）：控制内存占用峰值的同时保持 I/O 效率。
     */
    private static final int STREAM_CHUNK_BYTES = 1 << 20;

    private PayloadCodec() {
    }

    // ---- 内部类型 ----

    /**
     * 将原始文件加密为 STEG-V2 Payload。
     *
     * @param plaintext 原始文件字节
     * @param fileName  原始文件名（不含路径）
     * @param password  密码（可为空使用默认密码）
     * @param salt      16 字节 Argon2id 盐
     * @param hkdfSalt  32 字节 HKDF 盐
     * @param nonce     24 字节 XChaCha20 nonce
     * @param serpentIv 16 字节 Serpent IV（paranoid 模式；非 paranoid 为 null）
     * @param options   编码选项
     * @return 完整的 STEG-V2 Payload 字节数组
     */
    public static byte[] encode(final byte[] plaintext, final String fileName,
                                final byte[] password, final byte[] salt,
                                final byte[] hkdfSalt, final byte[] nonce,
                                final byte[] serpentIv,
                                final StegoEncodeOptions options) {
        // 步骤 1：构建 Metadata JSON
        String mimeType = guessMimeType(fileName);
        String metadataJson = buildMetadataJson(fileName, plaintext.length, mimeType);
        byte[] metadataBytes = metadataJson.getBytes(StandardCharsets.UTF_8);

        if (metadataBytes.length > 65535) {
            throw new IllegalArgumentException("Metadata 过大: " + metadataBytes.length);
        }

        // 步骤 2：计算 flags
        int flags = buildFlags(options);

        // 步骤 3：密钥派生
        byte[] effectivePwd = (password != null && password.length > 0)
                ? password : DEFAULT_PASSWORD;
        byte[] masterKey = deriveMasterKeyUnchecked(effectivePwd, salt, options.isParanoid(),
                options.argon2Params());

        byte[] ciphertext;
        byte[] headerMacBytes = null;
        byte[] payloadMacBytes = null;

        try {
            HkdfStream hkdf = new HkdfStream(masterKey, hkdfSalt);
            byte[] encKey = hkdf.read(ENC_KEY_LEN);
            byte[] macKey = hkdf.read(MAC_KEY_LEN);
            byte[] headerMacKey = options.hasHeaderMac()
                    ? hkdf.read(HEADER_MAC_KEY_LEN) : null;
            byte[] serpentKey = options.isParanoid()
                    ? hkdf.read(SERPENT_KEY_LEN) : null;

            // 步骤 4：可选加密前 Zstandard 压缩，再加密
            byte[] work = plaintext;
            if (options.isCompressed()) {
                work = ZstdCompressor.compress(work, options.compressionLevel());
            }

            ciphertext = encryptPayload(encKey, nonce, serpentKey, serpentIv, work);

            // 步骤 5：计算 Header MAC（对 Header 定长部分 + Metadata）
            if (options.hasHeaderMac() && headerMacKey != null) {
                headerMacBytes = computeHeaderMac(headerMacKey, flags, metadataBytes);
            }

            // 步骤 6：计算 Payload MAC（对密文）
            if (options.hasIntegrity()) {
                payloadMacBytes = computePayloadMac(macKey, ciphertext);
            }

            SecureZero.zeroAll(encKey, macKey, headerMacKey, serpentKey);
        } finally {
            SecureZero.zero(masterKey);
        }

        // 步骤 7：组装完整 Payload
        int headerSize = computeHeaderSize(metadataBytes.length, options.hasHeaderMac());
        int totalSize = headerSize + ciphertext.length
                + (options.hasIntegrity() ? MAC_SIZE : 0);

        ByteBuffer buf = ByteBuffer.allocate(totalSize).order(ByteOrder.BIG_ENDIAN);
        // Header 定长部分
        buf.put(MAGIC);
        buf.putShort((short) VERSION);
        buf.putShort((short) flags);
        buf.putShort((short) metadataBytes.length);
        buf.put(metadataBytes);
        // Header MAC
        if (options.hasHeaderMac() && headerMacBytes != null) {
            buf.put(headerMacBytes);
        }
        // 密文
        buf.put(ciphertext);
        // Payload MAC
        if (options.hasIntegrity() && payloadMacBytes != null) {
            buf.put(payloadMacBytes);
        }

        return buf.array();
    }

    /**
     * 从 STEG-V2 Payload 中解密还原原始文件（Argon2 参数使用默认值）。
     *
     * <p>密码学参数（salt、hkdfSalt、nonce 等）需从载体层的
     * {@code CarrierMetadata} 获取。
     *
     * @param payload   完整的 STEG-V2 Payload 字节数组
     * @param password  密码
     * @param salt      16 字节 Argon2id 盐（来自 CarrierMetadata）
     * @param hkdfSalt  32 字节 HKDF 盐（来自 CarrierMetadata）
     * @param nonce     24 字节 XChaCha20 nonce（来自 CarrierMetadata）
     * @param serpentIv 16 字节 Serpent IV（来自 CarrierMetadata；非 paranoid 为 null）
     * @param paranoid  是否 paranoid 模式（来自 CarrierMetadata flags）
     * @return 解密结果（含明文和元数据）
     * @throws PayloadException 密码错误、MAC 失败或格式异常
     */
    public static DecodeResult decode(final byte[] payload, final byte[] password,
                                      final byte[] salt, final byte[] hkdfSalt,
                                      final byte[] nonce, final byte[] serpentIv,
                                      final boolean paranoid) throws PayloadException {
        return decode(payload, password, salt, hkdfSalt, nonce, serpentIv, paranoid, null);
    }

    /**
     * 从 STEG-V2 Payload 中解密还原原始文件。
     *
     * <p>密码学参数（salt、hkdfSalt、nonce 等）需从载体层的
     * {@code CarrierMetadata} 获取；Argon2 参数覆写同样来自
     * {@code CarrierMetadata}（null 表示使用默认参数）。
     *
     * @param payload      完整的 STEG-V2 Payload 字节数组
     * @param password     密码
     * @param salt         16 字节 Argon2id 盐（来自 CarrierMetadata）
     * @param hkdfSalt     32 字节 HKDF 盐（来自 CarrierMetadata）
     * @param nonce        24 字节 XChaCha20 nonce（来自 CarrierMetadata）
     * @param serpentIv    16 字节 Serpent IV（来自 CarrierMetadata；非 paranoid 为 null）
     * @param paranoid     是否 paranoid 模式（来自 CarrierMetadata flags）
     * @param argon2Params Argon2 参数覆写（来自 CarrierMetadata；null 使用默认值）
     * @return 解密结果（含明文和元数据）
     * @throws PayloadException 密码错误、MAC 失败或格式异常
     */
    public static DecodeResult decode(final byte[] payload, final byte[] password,
                                      final byte[] salt, final byte[] hkdfSalt,
                                      final byte[] nonce, final byte[] serpentIv,
                                      final boolean paranoid, final Argon2Params argon2Params)
            throws PayloadException {
        if (payload.length < HEADER_FIXED_SIZE) {
            throw new PayloadException("Payload 太短: " + payload.length);
        }

        ByteBuffer buf = ByteBuffer.wrap(payload).order(ByteOrder.BIG_ENDIAN);

        // 步骤 1：验证魔数
        byte[] magic = new byte[MAGIC_LEN];
        buf.get(magic);
        if (!Arrays.equals(magic, MAGIC)) {
            throw new PayloadException("不是有效的 STEG-V2 Payload（魔数不匹配）");
        }

        // 步骤 2：读取版本
        int version = Short.toUnsignedInt(buf.getShort());
        if (version != VERSION) {
            throw new PayloadException("不支持的 Payload 版本: " + version);
        }

        // 步骤 3：读取 Flags
        int flags = Short.toUnsignedInt(buf.getShort());
        boolean hasHeaderMac = (flags & FLAG_HAS_HEADER_MAC) != 0;
        boolean hasIntegrity = (flags & FLAG_HAS_INTEGRITY) != 0;
        boolean isParanoid = (flags & FLAG_PARANOID) != 0;
        boolean isCompressed = (flags & FLAG_COMPRESSED) != 0;

        // 步骤 4：读取 Metadata
        int metaLength = Short.toUnsignedInt(buf.getShort());
        if (metaLength < 0 || metaLength > payload.length - HEADER_FIXED_SIZE) {
            throw new PayloadException("Metadata 长度异常: " + metaLength);
        }

        byte[] metadataBytes = new byte[metaLength];
        buf.get(metadataBytes);
        String metadataJson = new String(metadataBytes, StandardCharsets.UTF_8);
        PayloadHeader header = parseMetadata(metadataJson, version, flags);

        // 步骤 5：验证 Header MAC（快速密码校验）
        if (hasHeaderMac) {
            if (buf.remaining() < MAC_SIZE) {
                throw new PayloadException("Payload 截断：缺少 Header MAC");
            }
            byte[] storedHeaderMac = new byte[MAC_SIZE];
            buf.get(storedHeaderMac);

            byte[] effectivePwd = (password != null && password.length > 0)
                    ? password : DEFAULT_PASSWORD;
            byte[] masterKey = deriveMasterKey(effectivePwd, salt, paranoid, argon2Params);

            try {
                HkdfStream hkdf = new HkdfStream(masterKey, hkdfSalt);
                hkdf.read(ENC_KEY_LEN);
                hkdf.read(MAC_KEY_LEN);
                byte[] headerMacKey = hkdf.read(HEADER_MAC_KEY_LEN);

                byte[] computed = computeHeaderMac(headerMacKey, flags, metadataBytes);
                if (!constantTimeEquals(computed, storedHeaderMac)) {
                    throw new PayloadException("Header MAC 验证失败——密码错误或数据被篡改");
                }
                SecureZero.zero(headerMacKey);
            } finally {
                SecureZero.zero(masterKey);
            }
        }

        // 步骤 6：计算密文区域
        // 当前 buf 位置是 CIPHERTEXT 起始位置
        int ciphertextStart = buf.position();
        int remaining = buf.remaining();
        int ciphertextLen = remaining - (hasIntegrity ? MAC_SIZE : 0);
        if (ciphertextLen < 0) {
            throw new PayloadException("密文长度异常: " + ciphertextLen);
        }

        byte[] ciphertext = new byte[ciphertextLen];
        buf.get(ciphertext);

        // 步骤 7：读取 Payload MAC
        byte[] storedPayloadMac = null;
        if (hasIntegrity) {
            storedPayloadMac = new byte[MAC_SIZE];
            buf.get(storedPayloadMac);
        }

        // 步骤 8：密钥派生和解密
        byte[] effectivePwd = (password != null && password.length > 0)
                ? password : DEFAULT_PASSWORD;
        // 如果前面没有计算过 Header MAC，这里需要独立派生
        if (!hasHeaderMac) {
            byte[] masterKey = deriveMasterKey(effectivePwd, salt, paranoid, argon2Params);
            byte[] plaintext;
            try {
                HkdfStream hkdf = new HkdfStream(masterKey, hkdfSalt);
                byte[] encKey = hkdf.read(ENC_KEY_LEN);
                byte[] macKey = hkdf.read(MAC_KEY_LEN);
                byte[] serpentKey = isParanoid ? hkdf.read(SERPENT_KEY_LEN) : null;

                plaintext = decryptPayload(encKey, nonce, serpentKey, serpentIv, ciphertext);

                if (hasIntegrity && storedPayloadMac != null) {
                    byte[] computedMac = computePayloadMac(macKey, ciphertext);
                    if (!constantTimeEquals(computedMac, storedPayloadMac)) {
                        SecureZero.zero(plaintext);
                        throw new PayloadException("Payload MAC 验证失败——数据可能被篡改");
                    }
                }
                SecureZero.zeroAll(encKey, macKey, serpentKey);
            } finally {
                SecureZero.zero(masterKey);
            }

            // 步骤：若加密前压缩过，则解压还原
            if (isCompressed) {
                plaintext = ZstdCompressor.decompress(plaintext);
            }

            return new DecodeResult(plaintext, header);
        } else {
            // Header MAC 已验证过密码，重新派生完整密钥
            byte[] masterKey = deriveMasterKey(effectivePwd, salt, paranoid, argon2Params);
            byte[] plaintext;
            try {
                HkdfStream hkdf = new HkdfStream(masterKey, hkdfSalt);
                byte[] encKey = hkdf.read(ENC_KEY_LEN);
                byte[] macKey = hkdf.read(MAC_KEY_LEN);
                hkdf.read(HEADER_MAC_KEY_LEN); // 跳过 headerMacKey
                byte[] serpentKey = isParanoid ? hkdf.read(SERPENT_KEY_LEN) : null;

                plaintext = decryptPayload(encKey, nonce, serpentKey, serpentIv, ciphertext);

                if (hasIntegrity && storedPayloadMac != null) {
                    byte[] computedMac = computePayloadMac(macKey, ciphertext);
                    if (!constantTimeEquals(computedMac, storedPayloadMac)) {
                        SecureZero.zero(plaintext);
                        throw new PayloadException("Payload MAC 验证失败——数据可能被篡改");
                    }
                }
                SecureZero.zeroAll(encKey, macKey, serpentKey);
            } finally {
                SecureZero.zero(masterKey);
            }

            // 步骤：若加密前压缩过，则解压还原
            if (isCompressed) {
                plaintext = ZstdCompressor.decompress(plaintext);
            }

            return new DecodeResult(plaintext, header);
        }
    }

    // ---- 流式编码/解码（大文件与移动端，内存占用恒定） ----

    /**
     * 将原始文件流式加密为 STEG-V2 Payload 并写入文件。
     *
     * <p>与 {@link #encode} 对相同输入产出字节完全一致的 Payload，但内存占用
     * 恒定（1 MiB 分块），适用于大文件与移动端。布局不变：
     * header → headerMAC → ciphertext → payloadMAC（末尾追加）。
     *
     * @param plaintextFile 原始文件路径
     * @param payloadOut    Payload 输出路径
     * @param fileName      原始文件名（不含路径）
     * @param password      密码（可为空使用默认密码）
     * @param salt          16 字节 Argon2id 盐
     * @param hkdfSalt      32 字节 HKDF 盐
     * @param nonce         24 字节 XChaCha20 nonce
     * @param serpentIv     16 字节 Serpent IV（paranoid 模式；非 paranoid 为 null）
     * @param options       编码选项
     * @throws IOException      读写失败
     * @throws PayloadException 密钥派生失败（如内存不足）
     */
    public static void encodeToFile(final Path plaintextFile, final Path payloadOut,
                                    final String fileName, final byte[] password,
                                    final byte[] salt, final byte[] hkdfSalt, final byte[] nonce,
                                    final byte[] serpentIv, final StegoEncodeOptions options)
            throws IOException, PayloadException {
        encodeToFile(plaintextFile, payloadOut, fileName, password, salt, hkdfSalt, nonce,
                serpentIv, options, null);
    }

    /**
     * 将原始文件流式加密为 STEG-V2 Payload 并写入文件（带进度回调）。
     *
     * <p>与 {@link #encodeToFile} 相同，另在流式加密阶段按已加密字节数占
     * 明文总字节数的比例逐块回调 {@link ProgressListener}（密钥派生阶段
     * 不产生回调）。
     *
     * @param plaintextFile 原始文件路径
     * @param payloadOut    Payload 输出路径
     * @param fileName      原始文件名（不含路径）
     * @param password      密码（可为空使用默认密码）
     * @param salt          16 字节 Argon2id 盐
     * @param hkdfSalt      32 字节 HKDF 盐
     * @param nonce         24 字节 XChaCha20 nonce
     * @param serpentIv     16 字节 Serpent IV（paranoid 模式；非 paranoid 为 null）
     * @param options       编码选项
     * @param listener      进度监听器（可为 null）
     * @throws IOException      读写失败
     * @throws PayloadException 密钥派生失败（如内存不足）
     */
    public static void encodeToFile(final Path plaintextFile, final Path payloadOut,
                                    final String fileName, final byte[] password,
                                    final byte[] salt, final byte[] hkdfSalt, final byte[] nonce,
                                    final byte[] serpentIv, final StegoEncodeOptions options,
                                    final ProgressListener listener)
            throws IOException, PayloadException {
        // 步骤 1：构建 Metadata JSON（与 byte[] encode 完全一致）
        String mimeType = guessMimeType(fileName);
        String metadataJson = buildMetadataJson(fileName, Files.size(plaintextFile), mimeType);
        byte[] metadataBytes = metadataJson.getBytes(StandardCharsets.UTF_8);
        if (metadataBytes.length > 65535) {
            throw new IllegalArgumentException("Metadata 过大: " + metadataBytes.length);
        }

        // 步骤 2：计算 flags
        int flags = buildFlags(options);

        // 步骤 3：密钥派生（带 Argon2 覆写与 OOM 守卫）
        byte[] effectivePwd = (password != null && password.length > 0)
                ? password : DEFAULT_PASSWORD;
        byte[] masterKey = deriveMasterKey(effectivePwd, salt, options.isParanoid(),
                options.argon2Params());

        try {
            HkdfStream hkdf = new HkdfStream(masterKey, hkdfSalt);
            byte[] encKey = hkdf.read(ENC_KEY_LEN);
            byte[] macKey = hkdf.read(MAC_KEY_LEN);
            byte[] headerMacKey = options.hasHeaderMac()
                    ? hkdf.read(HEADER_MAC_KEY_LEN) : null;
            byte[] serpentKey = options.isParanoid()
                    ? hkdf.read(SERPENT_KEY_LEN) : null;

            try (OutputStream fos = Files.newOutputStream(payloadOut)) {
                // 步骤 4：Header 定长部分 + Metadata
                ByteBuffer fixed = ByteBuffer.allocate(HEADER_FIXED_SIZE)
                        .order(ByteOrder.BIG_ENDIAN);
                fixed.put(MAGIC);
                fixed.putShort((short) VERSION);
                fixed.putShort((short) flags);
                fixed.putShort((short) metadataBytes.length);
                fos.write(fixed.array());
                fos.write(metadataBytes);

                // 步骤 5：Header MAC
                if (options.hasHeaderMac() && headerMacKey != null) {
                    fos.write(computeHeaderMac(headerMacKey, flags, metadataBytes));
                }

                // 步骤 6：流式加密密文 + 增量 Payload MAC（MAC 在密文后，末尾追加）
                Mac payloadMac = options.hasIntegrity()
                        ? MacFactory.create(macKey, false) : null;
                // 加密前压缩：先把明文流式压缩到临时文件，再对压缩后的临时文件加密
                Path encryptSource = plaintextFile;
                Path compressedTemp = null;
                try {
                    if (options.isCompressed()) {
                        compressedTemp = Files.createTempFile("ergou-stego", ".zst");
                        ZstdCompressor.compress(Files.newInputStream(plaintextFile),
                                Files.newOutputStream(compressedTemp), options.compressionLevel());
                        encryptSource = compressedTemp;
                    }
                    streamEncrypt(encryptSource, fos, encKey, nonce, serpentKey, serpentIv,
                            payloadMac, Files.size(encryptSource), listener);
                    if (payloadMac != null) {
                        fos.write(payloadMac.doFinal());
                    }
                } finally {
                    if (compressedTemp != null) {
                        Files.deleteIfExists(compressedTemp);
                    }
                    if (payloadMac != null) {
                        payloadMac.close();
                    }
                }
            }
            SecureZero.zeroAll(encKey, macKey, headerMacKey, serpentKey);
        } finally {
            SecureZero.zero(masterKey);
        }
    }

    /**
     * 从 STEG-V2 Payload 文件流式解密还原原始文件。
     *
     * <p>与 {@link #decode} 对相同输入产出完全一致的明文，内存占用恒定。
     * Header MAC 校验在读取密文前完成（密码错误快速失败、不产生输出文件）；
     * Payload MAC 校验失败时删除已写入的明文输出并抛出异常。
     *
     * @param payloadFile   Payload 文件路径
     * @param plaintextOut  明文输出路径
     * @param password      密码
     * @param salt          16 字节 Argon2id 盐
     * @param hkdfSalt      32 字节 HKDF 盐
     * @param nonce         24 字节 XChaCha20 nonce
     * @param serpentIv     16 字节 Serpent IV（非 paranoid 为 null）
     * @param paranoid      是否 paranoid 模式（来自 CarrierMetadata flags）
     * @param argon2Params  Argon2 参数覆写（来自 CarrierMetadata；null 使用默认值）
     * @return 解析后的 Payload Header（含原始文件名，供调用方命名输出）
     * @throws IOException      读写失败
     * @throws PayloadException 密码错误、MAC 失败或格式异常
     */
    public static PayloadHeader decodeToFile(final Path payloadFile, final Path plaintextOut,
                                             final byte[] password, final byte[] salt,
                                             final byte[] hkdfSalt, final byte[] nonce,
                                             final byte[] serpentIv, final boolean paranoid,
                                             final Argon2Params argon2Params)
            throws IOException, PayloadException {
        return decodeToFile(payloadFile, plaintextOut, password, salt, hkdfSalt, nonce,
                serpentIv, paranoid, argon2Params, null);
    }

    /**
     * 从 STEG-V2 Payload 文件流式解密还原原始文件（带进度回调）。
     *
     * <p>与 {@link #decodeToFile} 相同，另在流式解密阶段按已解密字节数占
     * 密文总字节数的比例逐块回调 {@link ProgressListener}（密钥派生与
     * Header MAC 校验阶段不产生回调）。
     *
     * @param payloadFile   Payload 文件路径
     * @param plaintextOut  明文输出路径
     * @param password      密码
     * @param salt          16 字节 Argon2id 盐
     * @param hkdfSalt      32 字节 HKDF 盐
     * @param nonce         24 字节 XChaCha20 nonce
     * @param serpentIv     16 字节 Serpent IV（非 paranoid 为 null）
     * @param paranoid      是否 paranoid 模式（来自 CarrierMetadata flags）
     * @param argon2Params  Argon2 参数覆写（来自 CarrierMetadata；null 使用默认值）
     * @param listener      进度监听器（可为 null）
     * @return 解析后的 Payload Header（含原始文件名，供调用方命名输出）
     * @throws IOException      读写失败
     * @throws PayloadException 密码错误、MAC 失败或格式异常
     */
    public static PayloadHeader decodeToFile(final Path payloadFile, final Path plaintextOut,
                                             final byte[] password, final byte[] salt,
                                             final byte[] hkdfSalt, final byte[] nonce,
                                             final byte[] serpentIv, final boolean paranoid,
                                             final Argon2Params argon2Params,
                                             final ProgressListener listener)
            throws IOException, PayloadException {
        long fileSize = Files.size(payloadFile);
        if (fileSize < HEADER_FIXED_SIZE) {
            throw new PayloadException("Payload 太短: " + fileSize);
        }
        try (InputStream fin = Files.newInputStream(payloadFile)) {
            // 步骤 1-4：读 Header 定长部分、校验魔数/版本、读 Metadata
            ByteBuffer fixed = ByteBuffer.allocate(HEADER_FIXED_SIZE)
                    .order(ByteOrder.BIG_ENDIAN);
            readFully(fin, fixed.array());
            byte[] magic = new byte[MAGIC_LEN];
            fixed.get(magic);
            if (!Arrays.equals(magic, MAGIC)) {
                throw new PayloadException("不是有效的 STEG-V2 Payload（魔数不匹配）");
            }
            int version = Short.toUnsignedInt(fixed.getShort());
            if (version != VERSION) {
                throw new PayloadException("不支持的 Payload 版本: " + version);
            }
            int flags = Short.toUnsignedInt(fixed.getShort());
            boolean hasHeaderMac = (flags & FLAG_HAS_HEADER_MAC) != 0;
            boolean hasIntegrity = (flags & FLAG_HAS_INTEGRITY) != 0;
            boolean isCompressed = (flags & FLAG_COMPRESSED) != 0;
            int metaLength = Short.toUnsignedInt(fixed.getShort());
            if (metaLength < 0 || metaLength > fileSize - HEADER_FIXED_SIZE) {
                throw new PayloadException("Metadata 长度异常: " + metaLength);
            }
            byte[] metadataBytes = new byte[metaLength];
            readFully(fin, metadataBytes);
            String metadataJson = new String(metadataBytes, StandardCharsets.UTF_8);
            PayloadHeader header = parseMetadata(metadataJson, version, flags);

            // 步骤 5：密钥派生 + Header MAC 快速校验（密码错误在此失败，不产生输出）
            byte[] effectivePwd = (password != null && password.length > 0)
                    ? password : DEFAULT_PASSWORD;
            byte[] masterKey = deriveMasterKey(effectivePwd, salt, paranoid, argon2Params);
            try {
                HkdfStream hkdf = new HkdfStream(masterKey, hkdfSalt);
                byte[] encKey = hkdf.read(ENC_KEY_LEN);
                byte[] macKey = hkdf.read(MAC_KEY_LEN);
                byte[] headerMacKey = hasHeaderMac ? hkdf.read(HEADER_MAC_KEY_LEN) : null;
                byte[] serpentKey = paranoid ? hkdf.read(SERPENT_KEY_LEN) : null;

                if (hasHeaderMac && headerMacKey != null) {
                    byte[] storedHeaderMac = new byte[MAC_SIZE];
                    readFully(fin, storedHeaderMac);
                    byte[] computed = computeHeaderMac(headerMacKey, flags, metadataBytes);
                    if (!constantTimeEquals(computed, storedHeaderMac)) {
                        throw new PayloadException("Header MAC 验证失败——密码错误或数据被篡改");
                    }
                }

                // 步骤 6：计算密文区间，读取末尾存储的 Payload MAC
                long headerEnd = HEADER_FIXED_SIZE + metaLength
                        + (hasHeaderMac ? MAC_SIZE : 0);
                long ciphertextLen = fileSize - headerEnd - (hasIntegrity ? MAC_SIZE : 0);
                if (ciphertextLen < 0) {
                    throw new PayloadException("密文长度异常: " + ciphertextLen);
                }
                byte[] storedPayloadMac = null;
                if (hasIntegrity) {
                    storedPayloadMac = new byte[MAC_SIZE];
                    try (RandomAccessFile raf = new RandomAccessFile(payloadFile.toFile(), "r")) {
                        raf.seek(headerEnd + ciphertextLen);
                        raf.readFully(storedPayloadMac);
                    }
                }

                // 步骤 7：流式解密 + 增量 Payload MAC 校验
                Mac payloadMac = hasIntegrity ? MacFactory.create(macKey, false) : null;
                // 加密前压缩时：先解密到临时文件，再解压到最终输出
                Path decryptTarget = isCompressed
                        ? Files.createTempFile("ergou-stego", ".zst") : plaintextOut;
                try {
                    try {
                        streamDecrypt(fin, ciphertextLen, decryptTarget, encKey, nonce,
                                serpentKey, serpentIv, payloadMac, listener);
                    } catch (PayloadException | IOException e) {
                        // 解密中途失败：删除未完成的明文输出
                        Files.deleteIfExists(decryptTarget);
                        Files.deleteIfExists(plaintextOut);
                        throw e;
                    }
                    if (payloadMac != null) {
                        byte[] computedMac = payloadMac.doFinal();
                        if (!constantTimeEquals(computedMac, storedPayloadMac)) {
                            Files.deleteIfExists(decryptTarget);
                            Files.deleteIfExists(plaintextOut);
                            throw new PayloadException("Payload MAC 验证失败——数据可能被篡改");
                        }
                    }
                    if (isCompressed) {
                        ZstdCompressor.decompress(Files.newInputStream(decryptTarget),
                                Files.newOutputStream(plaintextOut));
                    }
                } finally {
                    if (isCompressed) {
                        Files.deleteIfExists(decryptTarget);
                    }
                    if (payloadMac != null) {
                        payloadMac.close();
                    }
                }
                SecureZero.zeroAll(encKey, macKey, headerMacKey, serpentKey);
            } finally {
                SecureZero.zero(masterKey);
            }
            return header;
        }
    }

    // ---- 编码 ----

    /**
     * 仅读取 Payload Header（不解密密文），用于快速格式识别和元数据查看。
     *
     * @param payload 完整的 STEG-V2 Payload 字节数组
     * @return 解析后的 Header 信息
     * @throws PayloadException 格式不合法
     */
    public static PayloadHeader readHeader(final byte[] payload) throws PayloadException {
        if (payload.length < HEADER_FIXED_SIZE) {
            throw new PayloadException("Payload 太短: " + payload.length);
        }

        ByteBuffer buf = ByteBuffer.wrap(payload).order(ByteOrder.BIG_ENDIAN);

        byte[] magic = new byte[MAGIC_LEN];
        buf.get(magic);
        if (!Arrays.equals(magic, MAGIC)) {
            throw new PayloadException("不是有效的 STEG-V2 Payload（魔数不匹配）");
        }

        int version = Short.toUnsignedInt(buf.getShort());
        if (version != VERSION) {
            throw new PayloadException("不支持的 Payload 版本: " + version);
        }

        int flags = Short.toUnsignedInt(buf.getShort());
        int metaLength = Short.toUnsignedInt(buf.getShort());

        if (metaLength < 0 || metaLength > payload.length - HEADER_FIXED_SIZE) {
            throw new PayloadException("Metadata 长度异常: " + metaLength);
        }

        byte[] metadataBytes = new byte[metaLength];
        buf.get(metadataBytes);
        String metadataJson = new String(metadataBytes, StandardCharsets.UTF_8);

        return parseMetadata(metadataJson, version, flags);
    }

    // ---- 解码 ----

    /**
     * 快速检测字节数组是否以 STEG-V2 MAGIC 开头。
     *
     * @param data 待检测的字节数组
     * @return true 如果以 "STG2" 魔数开头
     */
    public static boolean isStegV2(final byte[] data) {
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

    // ---- 只读 Header ----

    /**
     * 返回 Header 定长部分字节数（不含 Metadata）。
     *
     * @return 固定 10 字节
     */
    public static int headerFixedSize() {
        return HEADER_FIXED_SIZE;
    }

    // ---- 检测 ----

    /**
     * 从选项构建 FLAGS 位掩码。
     */
    private static int buildFlags(final StegoEncodeOptions options) {
        int flags = 0;
        if (options.isParanoid()) {
            flags |= FLAG_PARANOID;
        }
        if (options.isCompressed()) {
            flags |= FLAG_COMPRESSED;
        }
        if (options.hasIntegrity()) {
            flags |= FLAG_HAS_INTEGRITY;
        }
        if (options.hasHeaderMac()) {
            flags |= FLAG_HAS_HEADER_MAC;
        }
        return flags;
    }

    /**
     * 计算 Header 总大小（含 Metadata 和可选的 HEADER_MAC）。
     */
    static int computeHeaderSize(final int metadataLen, final boolean hasHeaderMac) {
        return HEADER_FIXED_SIZE + metadataLen + (hasHeaderMac ? MAC_SIZE : 0);
    }

    // ---- 内部辅助方法 ----

    /**
     * 派生 Argon2id 主密钥，并将内存不足等致命失败包装为 {@link PayloadException}。
     *
     * <p>{@link Argon2Kdf#deriveKey} 会先按设备可用堆预检：堆内放不下时自动
     * 回退到离堆（native 内存）实现，因此 1 GiB 参数的桌面端文件也能在移动
     * 端派生；只有堆与离堆内存均不足时才抛 {@link OutOfMemoryError}。解码侧
     * 的 Argon2 参数来自载体元数据（编码时烘焙进文件），与当前设备的内存档位
     * 设置无关。
     *
     * @param password     密码
     * @param salt         Argon2id 盐
     * @param paranoid     是否偏执模式参数
     * @param argon2Params 参数覆写（可为 null 使用默认值）
     * @return 32 字节主密钥
     * @throws PayloadException 密钥派生失败（如堆与离堆内存均不足）
     */
    private static byte[] deriveMasterKey(final byte[] password, final byte[] salt,
                                          final boolean paranoid,
                                          final Argon2Params argon2Params)
            throws PayloadException {
        try {
            if (argon2Params != null) {
                return Argon2Kdf.deriveKey(password, salt, paranoid,
                        argon2Params.memoryKiB(), argon2Params.passes(),
                        argon2Params.threads());
            }
            return Argon2Kdf.deriveKey(password, salt, paranoid);
        } catch (OutOfMemoryError oom) {
            String mem = argon2Params != null ? argon2Params.memoryKiB() + " KiB" : "默认 1 GiB";
            throw new PayloadException("内存不足：该文件使用 " + mem
                    + " 的 Argon2 参数，且设备堆与离堆内存均无法满足密钥派生，请改用桌面端处理", oom);
        }
    }

    /**
     * 派生 Argon2id 主密钥（无受检异常路径，供 byte[] 编码路径使用）。
     *
     * @param password     密码
     * @param salt         Argon2id 盐
     * @param paranoid     是否偏执模式参数
     * @param argon2Params 参数覆写（可为 null 使用默认值）
     * @return 32 字节主密钥
     */
    private static byte[] deriveMasterKeyUnchecked(final byte[] password, final byte[] salt,
                                                   final boolean paranoid,
                                                   final Argon2Params argon2Params) {
        if (argon2Params != null) {
            return Argon2Kdf.deriveKey(password, salt, paranoid,
                    argon2Params.memoryKiB(), argon2Params.passes(),
                    argon2Params.threads());
        }
        return Argon2Kdf.deriveKey(password, salt, paranoid);
    }

    /**
     * 从输入流读取指定字节数到缓冲区（不足则抛出 IOException）。
     *
     * @param in  输入流
     * @param buf 目标缓冲区
     * @throws IOException 读取失败或流提前结束
     */
    private static void readFully(final InputStream in, final byte[] buf) throws IOException {
        int off = 0;
        while (off < buf.length) {
            int n = in.read(buf, off, buf.length - off);
            if (n < 0) {
                throw new IOException("Unexpected end of stream");
            }
            off += n;
        }
    }

    /**
     * 构建 Metadata JSON 字符串。
     */
    private static String buildMetadataJson(final String fileName, final long fileSize,
                                            final String mimeType) {
        StringBuilder sb = new StringBuilder(128);
        sb.append("{\"origName\":\"");
        sb.append(escapeJson(fileName));
        sb.append("\",\"origSize\":");
        sb.append(fileSize);
        if (mimeType != null) {
            sb.append(",\"mimeType\":\"");
            sb.append(escapeJson(mimeType));
            sb.append("\"");
        }
        sb.append("}");
        return sb.toString();
    }

    /**
     * 解析 Metadata JSON 为 PayloadHeader。
     */
    private static PayloadHeader parseMetadata(final String json, final int version,
                                               final int flags) throws PayloadException {
        try {
            String origName = extractJsonString(json, "origName");
            long origSize = extractJsonNumber(json, "origSize");
            String mimeType = extractJsonStringOpt(json, "mimeType");

            if (origName == null || origName.isEmpty()) {
                throw new PayloadException("Metadata 缺少 origName 字段");
            }

            return new PayloadHeader(version, flags, origName, origSize, mimeType);
        } catch (PayloadException e) {
            throw e;
        } catch (Exception e) {
            throw new PayloadException("Metadata JSON 解析失败", e);
        }
    }

    /**
     * 从简单 JSON 中提取字符串字段值。
     */
    private static String extractJsonString(final String json, final String key) {
        String searchKey = "\"" + key + "\":\"";
        int idx = json.indexOf(searchKey);
        if (idx < 0) {
            return null;
        }
        int start = idx + searchKey.length();
        int end = json.indexOf("\"", start);
        if (end < 0) {
            return null;
        }
        return unescapeJson(json.substring(start, end));
    }

    /**
     * 从简单 JSON 中提取可选字符串字段值。
     */
    private static String extractJsonStringOpt(final String json, final String key) {
        return extractJsonString(json, key);
    }

    /**
     * 从简单 JSON 中提取数字字段值。
     */
    private static long extractJsonNumber(final String json, final String key) {
        String searchKey = "\"" + key + "\":";
        int idx = json.indexOf(searchKey);
        if (idx < 0) {
            return 0;
        }
        int start = idx + searchKey.length();
        int end = start;
        while (end < json.length()
                && (Character.isDigit(json.charAt(end)) || json.charAt(end) == '-')) {
            end++;
        }
        if (end == start) {
            return 0;
        }
        return Long.parseLong(json.substring(start, end));
    }

    /**
     * JSON 字符串转义。
     */
    private static String escapeJson(final String s) {
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    /**
     * JSON 字符串反转义。
     */
    private static String unescapeJson(final String s) {
        return s.replace("\\\"", "\"")
                .replace("\\\\", "\\")
                .replace("\\n", "\n")
                .replace("\\r", "\r")
                .replace("\\t", "\t");
    }

    /**
     * 根据扩展名推测 MIME 类型。
     */
    private static String guessMimeType(final String fileName) {
        if (fileName == null) {
            return null;
        }
        String lower = fileName.toLowerCase();
        if (lower.endsWith(".zip")) {
            return "application/zip";
        }
        if (lower.endsWith(".pdf")) {
            return "application/pdf";
        }
        if (lower.endsWith(".png")) {
            return "image/png";
        }
        if (lower.endsWith(".jpg") || lower.endsWith(".jpeg")) {
            return "image/jpeg";
        }
        if (lower.endsWith(".wav")) {
            return "audio/wav";
        }
        if (lower.endsWith(".flac")) {
            return "audio/flac";
        }
        if (lower.endsWith(".mp4")) {
            return "video/mp4";
        }
        if (lower.endsWith(".mp3")) {
            return "audio/mpeg";
        }
        if (lower.endsWith(".txt")) {
            return "text/plain";
        }
        if (lower.endsWith(".json")) {
            return "application/json";
        }
        if (lower.endsWith(".xml")) {
            return "application/xml";
        }
        return null;
    }

    /**
     * 加密载荷数据。
     */
    private static byte[] encryptPayload(final byte[] encKey, final byte[] nonce,
                                         final byte[] serpentKey, final byte[] serpentIv,
                                         final byte[] plaintext) {
        byte[] work = plaintext;
        if (serpentKey != null && serpentIv != null) {
            SerpentCtr sc = new SerpentCtr(serpentKey, serpentIv);
            work = new byte[plaintext.length];
            sc.process(work, plaintext, plaintext.length);
        }
        XChaCha20 chacha = new XChaCha20(encKey, nonce);
        byte[] out = new byte[work.length];
        chacha.process(out, work, work.length);
        return out;
    }

    /**
     * 解密载荷数据。
     */
    private static byte[] decryptPayload(final byte[] encKey, final byte[] nonce,
                                         final byte[] serpentKey, final byte[] serpentIv,
                                         final byte[] ciphertext) {
        XChaCha20 chacha = new XChaCha20(encKey, nonce);
        byte[] work = new byte[ciphertext.length];
        chacha.process(work, ciphertext, ciphertext.length);
        if (serpentKey != null && serpentIv != null) {
            SerpentCtr sc = new SerpentCtr(serpentKey, serpentIv);
            byte[] out = new byte[work.length];
            sc.process(out, work, work.length);
            return out;
        }
        return work;
    }

    // ---- 流式加密/解密原语 ----

    /**
     * 流式加密：明文 → [Serpent-CTR（paranoid）] → XChaCha20 → 输出，同时增量累积密文 MAC。
     *
     * <p>两个密码均为 BouncyCastle 有状态流密码，逐块调用与一次性调用产出
     * 字节完全一致（与 {@link #encryptPayload} 等价）。
     *
     * @param plaintextFile 明文文件
     * @param out           密文输出流
     * @param encKey        XChaCha20 密钥
     * @param nonce         XChaCha20 nonce
     * @param serpentKey    Serpent 密钥（非 paranoid 为 null）
     * @param serpentIv     Serpent IV（非 paranoid 为 null）
     * @param payloadMac    密文 MAC 累积器（可为 null）
     * @param totalBytes    明文总字节数（进度分母）
     * @param listener      进度监听器（可为 null），按已加密字节数回调
     * @throws IOException 读写失败
     */
    private static void streamEncrypt(final Path plaintextFile, final OutputStream out,
                                      final byte[] encKey, final byte[] nonce,
                                      final byte[] serpentKey, final byte[] serpentIv,
                                      final Mac payloadMac, final long totalBytes,
                                      final ProgressListener listener) throws IOException {
        boolean paranoid = serpentKey != null && serpentIv != null;
        SerpentCtr serpent = paranoid ? new SerpentCtr(serpentKey, serpentIv) : null;
        XChaCha20 chacha = new XChaCha20(encKey, nonce);
        byte[] readBuf = new byte[STREAM_CHUNK_BYTES];
        byte[] workBuf = new byte[STREAM_CHUNK_BYTES];
        byte[] outBuf = new byte[STREAM_CHUNK_BYTES];
        try (InputStream fin = Files.newInputStream(plaintextFile)) {
            long processed = 0;
            int n;
            while ((n = fin.read(readBuf)) > 0) {
                if (paranoid) {
                    serpent.process(workBuf, readBuf, n);
                } else {
                    System.arraycopy(readBuf, 0, workBuf, 0, n);
                }
                chacha.process(outBuf, workBuf, n);
                out.write(outBuf, 0, n);
                if (payloadMac != null) {
                    payloadMac.update(outBuf, n);
                }
                processed += n;
                if (listener != null) {
                    listener.onProgress((double) processed / Math.max(totalBytes, 1L));
                }
            }
            if (listener != null && totalBytes <= 0) {
                listener.onProgress(1.0);
            }
        }
    }

    /**
     * 流式解密：密文 → XChaCha20 → [Serpent-CTR（paranoid）] → 明文文件，
     * 同时增量累积密文 MAC。
     *
     * @param in           密文输入流（已定位到密文起点）
     * @param length       密文字节数
     * @param plaintextOut 明文输出路径
     * @param encKey       XChaCha20 密钥
     * @param nonce        XChaCha20 nonce
     * @param serpentKey   Serpent 密钥（非 paranoid 为 null）
     * @param serpentIv    Serpent IV（非 paranoid 为 null）
     * @param payloadMac   密文 MAC 累积器（可为 null）
     * @param listener     进度监听器（可为 null），按已解密字节数回调
     * @throws IOException      读写失败
     * @throws PayloadException 密文提前结束
     */
    private static void streamDecrypt(final InputStream in, final long length,
                                      final Path plaintextOut, final byte[] encKey,
                                      final byte[] nonce, final byte[] serpentKey,
                                      final byte[] serpentIv, final Mac payloadMac,
                                      final ProgressListener listener)
            throws IOException, PayloadException {
        boolean paranoid = serpentKey != null && serpentIv != null;
        XChaCha20 chacha = new XChaCha20(encKey, nonce);
        SerpentCtr serpent = paranoid ? new SerpentCtr(serpentKey, serpentIv) : null;
        byte[] readBuf = new byte[STREAM_CHUNK_BYTES];
        byte[] workBuf = new byte[STREAM_CHUNK_BYTES];
        byte[] outBuf = new byte[STREAM_CHUNK_BYTES];
        try (OutputStream fos = Files.newOutputStream(plaintextOut)) {
            long remaining = length;
            while (remaining > 0) {
                int want = (int) Math.min(remaining, STREAM_CHUNK_BYTES);
                int n = in.read(readBuf, 0, want);
                if (n < 0) {
                    throw new PayloadException("Payload 截断：密文提前结束");
                }
                chacha.process(workBuf, readBuf, n);
                if (paranoid) {
                    serpent.process(outBuf, workBuf, n);
                } else {
                    System.arraycopy(workBuf, 0, outBuf, 0, n);
                }
                fos.write(outBuf, 0, n);
                if (payloadMac != null) {
                    payloadMac.update(readBuf, n);
                }
                remaining -= n;
                if (listener != null) {
                    listener.onProgress((double) (length - remaining) / Math.max(length, 1L));
                }
            }
            if (listener != null && length <= 0) {
                listener.onProgress(1.0);
            }
        }
    }

    // ---- 加密/解密原语 ----

    /**
     * 计算 Header MAC。
     *
     * <p>对 VERSION(2B) \|\| FLAGS(2B) \|\| META_LENGTH(2B) \|\| METADATA(NB) 进行 MAC。
     */
    private static byte[] computeHeaderMac(final byte[] headerMacKey, final int flags,
                                           final byte[] metadataBytes) {
        ByteBuffer headerData = ByteBuffer.allocate(2 + 2 + 2 + metadataBytes.length)
                .order(ByteOrder.BIG_ENDIAN);
        headerData.putShort((short) VERSION);
        headerData.putShort((short) flags);
        headerData.putShort((short) metadataBytes.length);
        headerData.put(metadataBytes);

        Mac mac = MacFactory.create(headerMacKey, false);
        byte[] data = headerData.array();
        mac.update(data, data.length);
        return mac.doFinal();
    }

    /**
     * 计算 Payload MAC。
     */
    private static byte[] computePayloadMac(final byte[] macKey, final byte[] ciphertext) {
        Mac mac = MacFactory.create(macKey, false);
        mac.update(ciphertext, ciphertext.length);
        return mac.doFinal();
    }

    /**
     * 常量时间字节数组比较。
     */
    private static boolean constantTimeEquals(final byte[] a, final byte[] b) {
        if (a.length != b.length) {
            return false;
        }
        int diff = 0;
        for (int i = 0; i < a.length; i++) {
            diff |= a[i] ^ b[i];
        }
        return diff == 0;
    }

    /**
     * 解析后的 Payload Header 信息。
     *
     * @param version  格式版本
     * @param flags    标志位
     * @param origName 原始文件名
     * @param origSize 原始文件大小（字节）
     * @param mimeType MIME 类型（可为 null）
     */
    public record PayloadHeader(int version, int flags, String origName,
                                long origSize, String mimeType) {
    }

    /**
     * Payload 解码结果——包含解密后的明文和 Header 信息。
     *
     * @param plaintext 解密后的原始文件字节
     * @param header    解析后的 Header 信息
     */
    public record DecodeResult(byte[] plaintext, PayloadHeader header) {
    }
}
