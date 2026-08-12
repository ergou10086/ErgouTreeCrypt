package hbnu.project.ergoutreecrypt.filestego;

import hbnu.project.ergoutreecrypt.crypto.BruteForceGuard;
import hbnu.project.ergoutreecrypt.crypto.RandomBytes;
import hbnu.project.ergoutreecrypt.crypto.SecureZero;
import hbnu.project.ergoutreecrypt.filestego.api.CarrierException;
import hbnu.project.ergoutreecrypt.filestego.api.EmbedOptions;
import hbnu.project.ergoutreecrypt.filestego.api.FileStegoException;
import hbnu.project.ergoutreecrypt.filestego.api.FileStegoOptions;
import hbnu.project.ergoutreecrypt.filestego.api.PayloadException;
import hbnu.project.ergoutreecrypt.filestego.api.StegoEncodeOptions;
import hbnu.project.ergoutreecrypt.filestego.carrier.spi.AbstractCarrierAdapter;
import hbnu.project.ergoutreecrypt.filestego.carrier.spi.CarrierAdapter;
import hbnu.project.ergoutreecrypt.filestego.carrier.spi.CarrierMetadata;
import hbnu.project.ergoutreecrypt.filestego.carrier.spi.CarrierRegistry;
import hbnu.project.ergoutreecrypt.filestego.carrier.spi.CarrierResult;
import hbnu.project.ergoutreecrypt.filestego.codec.PayloadCodec;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.SecureRandom;
import java.util.Optional;

/**
 * 文件隐写统一入口——协调 {@link PayloadCodec} 与 {@link CarrierAdapter} 完成嵌入/提取。
 *
 * <p>这是调用方（UI 层）唯一需要接触的类。典型的隐藏流程：
 * <ol>
 *   <li>读取待隐藏文件</li>
 *   <li>检测载体格式，匹配对应的 {@link CarrierAdapter}</li>
 *   <li>生成密码学参数（salt、nonce 等）</li>
 *   <li>调用 {@link PayloadCodec#encode} 加密为 STEG-V2 Payload</li>
 *   <li>构建 {@link CarrierMetadata} 并序列化</li>
 *   <li>调用 {@link CarrierAdapter#embed} 写入载体文件</li>
 * </ol>
 *
 * <p>提取流程：
 * <ol>
 *   <li>检测载体格式，匹配对应的 {@link CarrierAdapter}</li>
 *   <li>调用适配器提取 {@link CarrierResult}（含元数据和 Payload）</li>
 *   <li>使用元数据中的密码学参数调用 {@link PayloadCodec#decode} 解密</li>
 *   <li>将还原的明文写入输出目录</li>
 * </ol>
 *
 * @author ErgouTree
 * @since 2026/8/5
 */
public final class FileStegoCodec {

    static {
        // 确保内置载体适配器（PNG/ZIP/...）在首次使用前完成注册
        CarrierBootstrap.ensureRegistered();
    }

    /** 密钥长度常量 */
    private static final int SALT_LEN = 16;
    private static final int HKDF_SALT_LEN = 32;
    private static final int NONCE_LEN = 24;
    private static final int SERPENT_IV_LEN = 16;
    private static final int STEALTH_SALT_LEN = 16;

    /** 内置默认密码（无密码模式使用） */
    private static final byte[] DEFAULT_PASSWORD =
            "ErgouTree-stego-default-passphrase".getBytes(java.nio.charset.StandardCharsets.UTF_8);

    /**
     * 将文件加密后嵌入到载体文件中。
     *
     * @param carrierFile 载体文件（PNG/ZIP/PDF/WAV/FLAC/MP4...）
     * @param secretFile  待隐藏的文件
     * @param output      输出路径
     * @param password    密码（可为空，使用默认密码）
     * @param options     文件隐写选项
     * @throws IOException        文件读写失败
     * @throws FileStegoException 不支持的格式、容量不足等
     */
    public void hide(final Path carrierFile, final Path secretFile, final Path output,
                      final byte[] password, final FileStegoOptions options)
            throws IOException, FileStegoException {
        // 步骤 1：查找匹配的适配器
        CarrierAdapter adapter = findAdapterForEmbed(carrierFile);

        // 步骤 2：读取待隐藏文件
        byte[] plaintext = Files.readAllBytes(secretFile);
        String fileName = secretFile.getFileName().toString();

        // 步骤 2.5：容量检查——若载体有容量限制且待隐藏文件过大，提前失败
        long capacity = adapter.capacity(carrierFile);
        if (capacity != Long.MAX_VALUE && plaintext.length > capacity) {
            throw new FileStegoException(String.format(
                    "载体容量不足：待隐藏文件 %s (%s) 过大，"
                            + "%s 载体最多可嵌入约 %s 数据。"
                            + " 建议：切换为 ZIP 或 PNG 等无容量限制的载体格式。",
                    fileName, formatSize(plaintext.length),
                    adapter.displayName(), formatSize(capacity)));
        }

        // 步骤 3：生成密码学参数
        byte[] salt = RandomBytes.generate(SALT_LEN);
        byte[] hkdfSalt = RandomBytes.generate(HKDF_SALT_LEN);
        byte[] nonce = RandomBytes.generate(NONCE_LEN);
        byte[] serpentIv = options.isParanoid() ? RandomBytes.generate(SERPENT_IV_LEN) : null;
        byte[] stealthSalt = options.isStealth() ? RandomBytes.generate(STEALTH_SALT_LEN) : null;

        byte[] effectivePwd = (password != null && password.length > 0) ? password : DEFAULT_PASSWORD;

        // 步骤 4：加密为 STEG-V2 Payload
        StegoEncodeOptions encodeOpts = options.toEncodeOptions();
        byte[] payload = PayloadCodec.encode(plaintext, fileName, effectivePwd,
                salt, hkdfSalt, nonce, serpentIv, encodeOpts);

        try {
            // 步骤 5：构建 CarrierMetadata
            byte flags = CarrierMetadata.buildFlags(
                    options.isParanoid(), options.isStoreIntegrity(), options.isStealth());
            CarrierMetadata meta = new CarrierMetadata(payload.length, flags,
                    salt, hkdfSalt, nonce, serpentIv, stealthSalt);
            byte[] metaBytes = meta.toBytes();

            // 步骤 6：组装 meta + payload 一起传给适配器
            byte[] combined = new byte[metaBytes.length + payload.length];
            System.arraycopy(metaBytes, 0, combined, 0, metaBytes.length);
            System.arraycopy(payload, 0, combined, metaBytes.length, payload.length);

            // 确保组合后的数据不超过载体容量限制
            if (capacity != Long.MAX_VALUE && combined.length > capacity) {
                throw new FileStegoException(String.format(
                        "载体容量不足：加密后数据 (%s) 超过 %s 载体最大容量 (%s)。"
                                + " 建议：切换为 ZIP 等无容量限制的载体格式。",
                        formatSize(combined.length),
                        adapter.displayName(), formatSize(capacity)));
            }

            // 步骤 7：委托适配器嵌入
            EmbedOptions embedOpts = options.toEmbedOptions();
            adapter.embed(carrierFile, combined, output, effectivePwd, embedOpts);
        } catch (CarrierException e) {
            throw new FileStegoException("载体嵌入失败: " + e.getMessage(), e);
        } finally {
            SecureZero.zero(payload);
        }

        // 步骤 8：文件大小混淆（可选）
        if (options.isObfuscateSize() && options.targetSizeBytes() > 0) {
            padToSize(output, options.targetSizeBytes());
        }
    }

    /**
     * 从载体文件中提取并解密隐藏的文件。
     *
     * @param stegoFile 隐写载体文件
     * @param outputDir 输出目录
     * @param password  密码（可为空）
     * @return 提取后的文件路径
     * @throws IOException        文件读写失败
     * @throws FileStegoException 格式不匹配、密码错误、MAC 失败等
     */
    public Path extract(final Path stegoFile, final Path outputDir, final byte[] password)
            throws IOException, FileStegoException {
        byte[] effectivePwd = (password != null && password.length > 0) ? password : DEFAULT_PASSWORD;

        // 步骤 1：防暴力破解检查
        BruteForceGuard guard = BruteForceGuard.getInstance();
        String filePath = stegoFile.toAbsolutePath().toString();
        if (!guard.allowAttempt(filePath)) {
            throw new FileStegoException(
                    "解密尝试次数过多（" + guard.getMaxAttempts()
                    + " 次），请稍后再试或确认密码是否正确");
        }

        // 步骤 2：查找匹配的适配器
        CarrierAdapter adapter = findAdapterForExtract(stegoFile);

        try {
            // 步骤 3：提取完整结果（元数据 + Payload）
            CarrierResult result;
            if (adapter instanceof AbstractCarrierAdapter abstractAdapter) {
                result = abstractAdapter.extractFull(stegoFile, effectivePwd);
            } else {
                // 非标准适配器：先提取 Payload，再从 Payload 中读取 Header（有限信息）
                byte[] payload = adapter.extract(stegoFile, effectivePwd);
                PayloadCodec.PayloadHeader header = PayloadCodec.readHeader(payload);
                // 这种情况下加密参数未知，无法解密——抛出异常
                throw new FileStegoException(
                        "适配器 " + adapter.id() + " 不支持返回密码学参数，无法解密");
            }

            CarrierMetadata meta = result.metadata();
            byte[] payload = result.payload();

            // 步骤 4：调用 PayloadCodec 解密
            PayloadCodec.DecodeResult decoded = PayloadCodec.decode(
                    payload, effectivePwd,
                    meta.salt(), meta.hkdfSalt(), meta.nonce(),
                    meta.serpentIv(), meta.isParanoid());

            // 步骤 5：写入输出文件
            Path outputFile = outputDir.resolve(decoded.header().origName());
            Files.createDirectories(outputDir);
            Files.write(outputFile, decoded.plaintext());

            guard.recordSuccess(filePath);
            return outputFile;
        } catch (CarrierException e) {
            guard.recordFailure(filePath);
            throw new FileStegoException("载体提取失败: " + e.getMessage(), e);
        } catch (PayloadException e) {
            guard.recordFailure(filePath);
            throw new FileStegoException("Payload 解密失败: " + e.getMessage(), e);
        }
    }

    /**
     * 检测文件是否包含隐写数据。
     *
     * <p>仅依据各适配器的 {@link CarrierAdapter#detect} 魔数检测，不做扩展名回退，
     * 避免把普通的 PNG/ZIP 等误判为隐写文件。
     *
     * @param file 待检测文件
     * @return true 如果检测到隐写数据
     */
    public boolean isStegoFile(final Path file) {
        return CarrierRegistry.detectByMagic(file).isPresent();
    }

    /**
     * 估算载体文件的最大隐写容量（字节；容量无关方案下为理论无限）。
     *
     * @param carrierFile 载体文件
     * @return 最大可嵌入字节数，{@link Long#MAX_VALUE} 表示理论无限
     * @throws IOException 文件读取失败
     */
    public long availableCapacity(final Path carrierFile) throws IOException {
        Optional<CarrierAdapter> adapter = CarrierRegistry.findByExtension(
                getExtension(carrierFile));
        if (adapter.isPresent()) {
            return adapter.get().capacity(carrierFile);
        }
        // 未知格式假设末尾追加，容量无限
        return Long.MAX_VALUE;
    }

    /**
     * 获取当前已注册的适配器数量。
     *
     * @return 适配器数量
     */
    public int registeredAdapterCount() {
        return CarrierRegistry.count();
    }

    // ---- 内部辅助方法 ----

    /**
     * 为嵌入操作查找适配器（按载体文件扩展名匹配）。
     */
    private CarrierAdapter findAdapterForEmbed(final Path carrierFile)
            throws FileStegoException {
        String ext = getExtension(carrierFile);
        Optional<CarrierAdapter> adapter = CarrierRegistry.findByExtension(ext);
        if (adapter.isEmpty()) {
            throw new FileStegoException("不支持的载体格式: " + ext
                    + "。支持的格式: " + supportedExtensionsString());
        }
        return adapter.get();
    }

    /**
     * 为提取操作查找适配器（先魔数检测，再扩展名回退）。
     */
    private CarrierAdapter findAdapterForExtract(final Path stegoFile)
            throws FileStegoException {
        Optional<CarrierAdapter> adapter = CarrierRegistry.detectAdapter(stegoFile);
        if (adapter.isEmpty()) {
            throw new FileStegoException(
                    "未检测到可识别的隐写数据。请确认文件来源。");
        }
        return adapter.get();
    }

    /**
     * 获取文件扩展名（小写，含 "." 前缀）。
     */
    private static String getExtension(final Path file) {
        String name = file.getFileName().toString().toLowerCase();
        int dot = name.lastIndexOf('.');
        return (dot >= 0) ? name.substring(dot) : "";
    }

    /**
     * 已注册适配器支持的所有扩展名（用于错误提示）。
     */
    private static String supportedExtensionsString() {
        StringBuilder sb = new StringBuilder();
        for (CarrierAdapter a : CarrierRegistry.all()) {
            if (sb.length() > 0) {
                sb.append(", ");
            }
            sb.append(String.join("/", a.supportedExtensions()));
        }
        return sb.toString();
    }

    /**
     * 在文件末尾追加密码学随机字节，直到达到目标大小。
     */
    private static void padToSize(final Path file, final long targetBytes)
            throws IOException, FileStegoException {
        long current = Files.size(file);
        if (current >= targetBytes) {
            throw new FileStegoException(String.format(
                    "目标大小(%s)小于或等于实际文件大小(%s)，无法混淆",
                    formatSize(targetBytes), formatSize(current)));
        }
        long toAdd = targetBytes - current;
        SecureRandom sr = new SecureRandom();
        byte[] buf = new byte[8192];
        try (java.io.OutputStream out = Files.newOutputStream(file,
                StandardOpenOption.APPEND)) {
            long remaining = toAdd;
            while (remaining > 0) {
                int chunk = (int) Math.min(remaining, buf.length);
                sr.nextBytes(buf);
                out.write(buf, 0, chunk);
                remaining -= chunk;
            }
        }
    }

    /**
     * 格式化文件大小。
     */
    private static String formatSize(final long bytes) {
        if (bytes < 1024) {
            return bytes + " B";
        } else if (bytes < 1024 * 1024) {
            return String.format("%.1f KB", bytes / 1024.0);
        }
        return String.format("%.1f MB", bytes / (1024.0 * 1024.0));
    }
}
