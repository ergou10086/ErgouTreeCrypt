package hbnu.project.ergoutreecrypt.filestego;

import hbnu.project.ergoutreecrypt.crypto.BruteForceGuard;
import hbnu.project.ergoutreecrypt.crypto.RandomBytes;
import hbnu.project.ergoutreecrypt.filestego.api.CarrierException;
import hbnu.project.ergoutreecrypt.filestego.api.EmbedOptions;
import hbnu.project.ergoutreecrypt.filestego.api.FileStegoException;
import hbnu.project.ergoutreecrypt.filestego.api.FileStegoOptions;
import hbnu.project.ergoutreecrypt.filestego.api.PayloadException;
import hbnu.project.ergoutreecrypt.filestego.api.ProgressListener;
import hbnu.project.ergoutreecrypt.filestego.api.StegoEncodeOptions;
import hbnu.project.ergoutreecrypt.filestego.api.StegoPreflight;
import hbnu.project.ergoutreecrypt.filestego.carrier.spi.CarrierResult;
import hbnu.project.ergoutreecrypt.filestego.carrier.spi.AbstractCarrierAdapter;
import hbnu.project.ergoutreecrypt.filestego.carrier.spi.CarrierAdapter;
import hbnu.project.ergoutreecrypt.filestego.carrier.spi.CarrierMetadata;
import hbnu.project.ergoutreecrypt.filestego.carrier.spi.CarrierRegistry;
import hbnu.project.ergoutreecrypt.filestego.codec.PayloadCodec;
import hbnu.project.ergoutreecrypt.log.LogService;

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
     * 低内存模式下大文件护栏阈值（64 MiB）：超过此大小的载荷仅在
     * 适配器支持流式嵌入/提取时才允许处理。
     */
    private static final long LARGE_PAYLOAD_THRESHOLD_BYTES = 64L << 20;

    /**
     * 只读预检的载体大小上限（64 MiB）：非流式适配器（PDF/WAV/FLAC）读取元数据
     * 会整读文件，超过此大小的文件跳过预检，避免移动端在「选择文件」阶段 OOM。
     */
    private static final long PREFLIGHT_MAX_BYTES = 64L << 20;

    /**
     * 将文件加密后嵌入到载体文件中。
     *
     * <p>载荷以流式（1 MiB 分块）加密到临时文件，再经
     * {@link CarrierAdapter#embedFromFile} 嵌入，全程内存占用恒定，
     * 支持 1GB 级大文件。低内存模式下，载荷超过
     * {@link #LARGE_PAYLOAD_THRESHOLD_BYTES} 且适配器不支持流式嵌入时，
     * 提前抛出友好错误而非 OOM。
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
        hide(carrierFile, secretFile, output, password, options, null);
    }

    /**
     * 将文件加密后嵌入到载体文件中（带进度回调）。
     *
     * <p>与 {@link #hide} 相同，另按阶段加权回调总体进度：
     * <ul>
     *   <li>0.00~0.02：前置检查完成（让进度条在密钥派生前即离开 0）</li>
     *   <li>0.02~0.60：Payload 流式加密（按已加密字节数）</li>
     *   <li>0.60~0.95：载体流式嵌入（按已写入字节数；非流式适配器在完成时跳变）</li>
     *   <li>0.95~1.00：文件大小混淆（可选）</li>
     * </ul>
     * 处理成功结束前必定回调 1.0。
     *
     * @param carrierFile 载体文件（PNG/ZIP/PDF/WAV/FLAC/MP4...）
     * @param secretFile  待隐藏的文件
     * @param output      输出路径
     * @param password    密码（可为空，使用默认密码）
     * @param options     文件隐写选项
     * @param listener    进度监听器（可为 null）
     * @throws IOException        文件读写失败
     * @throws FileStegoException 不支持的格式、容量不足等
     */
    public void hide(final Path carrierFile, final Path secretFile, final Path output,
                      final byte[] password, final FileStegoOptions options,
                      final ProgressListener listener)
            throws IOException, FileStegoException {
        // 步骤 1：查找匹配的适配器
        CarrierAdapter adapter = findAdapterForEmbed(carrierFile);

        LogService.info("FileStego", "开始嵌入 " + secretFile.getFileName()
                + " → " + carrierFile.getFileName());
        if (LogService.isTraceEnabled()) {
            LogService.trace("FileStego", "载体=" + adapter.displayName()
                    + ", 载荷=" + LogService.humanSize(Files.size(secretFile))
                    + ", paranoid=" + options.isParanoid()
                    + ", stealth=" + options.isStealth());
        }

        // 步骤 2：容量检查——在读取文件之前用文件大小判断，避免大文件 OOM
        String fileName = secretFile.getFileName().toString();
        long plaintextSize = Files.size(secretFile);
        long capacity = adapter.capacity(carrierFile);
        if (capacity != Long.MAX_VALUE && plaintextSize > capacity) {
            throw new FileStegoException(String.format(
                    "载体容量不足：待隐藏文件 %s (%s) 过大，"
                            + "%s 载体最多可嵌入约 %s 数据。"
                            + " 建议：切换为 ZIP 或 PNG 等无容量限制的载体格式。",
                    fileName, formatSize(plaintextSize),
                    adapter.displayName(), formatSize(capacity)));
        }
        // 低内存模式护栏：大载荷且适配器未实现流式嵌入 → 提前友好失败
        long threshold = lowMemoryThreshold(options);
        if (options.isLowMemoryMode()
                && plaintextSize > threshold
                && !adapter.supportsStreamingEmbed()) {
            throw new FileStegoException(String.format(
                    "该载体格式暂不支持大文件（>%s）流式嵌入，请改用 ZIP、PNG 或 MP4 载体。",
                    formatSize(threshold)));
        }

        // 前置检查完成，推进到 0.02（密钥派生可能耗时数秒，进度条先离开 0）
        if (listener != null) {
            listener.onProgress(0.02);
        }

        // 步骤 3：生成密码学参数
        byte[] salt = RandomBytes.generate(SALT_LEN);
        byte[] hkdfSalt = RandomBytes.generate(HKDF_SALT_LEN);
        byte[] nonce = RandomBytes.generate(NONCE_LEN);
        byte[] serpentIv = options.isParanoid() ? RandomBytes.generate(SERPENT_IV_LEN) : null;
        byte[] stealthSalt = options.isStealth() ? RandomBytes.generate(STEALTH_SALT_LEN) : null;

        byte[] effectivePwd = (password != null && password.length > 0) ? password : DEFAULT_PASSWORD;

        // 步骤 4：流式加密为 STEG-V2 Payload（临时文件，恒定内存），阶段 0.02~0.60
        Path payloadFile = Files.createTempFile("ergou-stego-payload-", ".tmp");
        try {
            StegoEncodeOptions encodeOpts = options.toEncodeOptions();
            ProgressListener encodeListener = listener == null ? null
                    : f -> listener.onProgress(0.02 + 0.58 * f);
            PayloadCodec.encodeToFile(secretFile, payloadFile, fileName, effectivePwd,
                    salt, hkdfSalt, nonce, serpentIv, encodeOpts, encodeListener);
            long payloadSize = Files.size(payloadFile);

            // 步骤 5：构建 CarrierMetadata（含 Argon2 参数覆写）
            byte flags = CarrierMetadata.buildFlags(
                    options.isParanoid(), options.isStoreIntegrity(), options.isStealth());
            CarrierMetadata meta = new CarrierMetadata(payloadSize, flags,
                    salt, hkdfSalt, nonce, serpentIv, stealthSalt, options.argon2Params());
            byte[] metaBytes = meta.toBytes();

            // 步骤 6：确保组合后的数据不超过载体容量限制
            long combinedLen = metaBytes.length + payloadSize;
            if (capacity != Long.MAX_VALUE && combinedLen > capacity) {
                throw new FileStegoException(String.format(
                        "载体容量不足：加密后数据 (%s) 超过 %s 载体最大容量 (%s)。"
                                + " 建议：切换为 ZIP 等无容量限制的载体格式。",
                        formatSize(combinedLen),
                        adapter.displayName(), formatSize(capacity)));
            }

            // 步骤 7：委托适配器嵌入（meta 与 payload 分离传递），阶段 0.60~0.95
            EmbedOptions embedOpts = options.toEmbedOptions();
            ProgressListener embedListener = listener == null ? null
                    : f -> listener.onProgress(0.60 + 0.35 * f);
            adapter.embedFromFile(carrierFile, metaBytes, payloadFile, output,
                    effectivePwd, embedOpts, embedListener);
        } catch (CarrierException e) {
            throw new FileStegoException("载体嵌入失败: " + e.getMessage(), e);
        } catch (PayloadException e) {
            throw new FileStegoException("Payload 加密失败: " + e.getMessage(), e);
        } finally {
            Files.deleteIfExists(payloadFile);
        }

        // 步骤 8：文件大小混淆（可选），阶段 0.95~1.00
        if (options.isObfuscateSize() && options.targetSizeBytes() > 0) {
            ProgressListener padListener = listener == null ? null
                    : f -> listener.onProgress(0.95 + 0.05 * f);
            padToSize(output, options.targetSizeBytes(), padListener);
        }
        if (listener != null) {
            listener.onProgress(1.0);
        }
        LogService.info("FileStego", "嵌入完成 → " + output.getFileName());
    }

    /**
     * 从载体文件中提取并解密隐藏的文件（默认选项，非低内存模式）。
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
        return extract(stegoFile, outputDir, password, FileStegoOptions.defaults());
    }

    /**
     * 从载体文件中提取并解密隐藏的文件。
     *
     * <p>提取与解密全程流式（恒定内存）：Payload 提取到临时文件后经
     * {@code PayloadCodec.decodeToFile} 解密写出。低内存模式下，载体文件超过
     * {@link #LARGE_PAYLOAD_THRESHOLD_BYTES} 且适配器不支持流式提取时，
     * 提前抛出友好错误而非 OOM。
     *
     * @param stegoFile 隐写载体文件
     * @param outputDir 输出目录
     * @param password  密码（可为空）
     * @param options   文件隐写选项（低内存模式与大文件护栏）
     * @return 提取后的文件路径
     * @throws IOException        文件读写失败
     * @throws FileStegoException 格式不匹配、密码错误、MAC 失败等
     */
    public Path extract(final Path stegoFile, final Path outputDir, final byte[] password,
                        final FileStegoOptions options)
            throws IOException, FileStegoException {
        return extract(stegoFile, outputDir, password, options, null);
    }

    /**
     * 从载体文件中提取并解密隐藏的文件（带进度回调）。
     *
     * <p>与 {@link #extract} 相同，另按阶段加权回调总体进度：
     * <ul>
     *   <li>0.00~0.02：适配器定位与前置检查完成</li>
     *   <li>0.02~0.50：Payload 从载体流式提取（按已提取字节数）</li>
     *   <li>0.50~1.00：Payload 流式解密（按已解密字节数；密钥派生可能
     *       使进度短暂停留在 0.50）</li>
     * </ul>
     * 处理成功结束前必定回调 1.0。
     *
     * @param stegoFile 隐写载体文件
     * @param outputDir 输出目录
     * @param password  密码（可为空）
     * @param options   文件隐写选项（低内存模式与大文件护栏）
     * @param listener  进度监听器（可为 null）
     * @return 提取后的文件路径
     * @throws IOException        文件读写失败
     * @throws FileStegoException 格式不匹配、密码错误、MAC 失败等
     */
    public Path extract(final Path stegoFile, final Path outputDir, final byte[] password,
                        final FileStegoOptions options, final ProgressListener listener)
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
        LogService.info("FileStego", "开始提取 " + stegoFile.getFileName());
        if (LogService.isTraceEnabled()) {
            LogService.trace("FileStego", "载体=" + adapter.displayName());
        }

        try {
            // 低内存模式护栏：大载体且适配器未实现流式提取 → 提前友好失败
            long threshold = lowMemoryThreshold(options);
            if (options.isLowMemoryMode()
                    && Files.size(stegoFile) > threshold
                    && !adapter.supportsStreamingExtract()) {
                throw new FileStegoException(String.format(
                        "该载体格式暂不支持大文件（>%s）流式提取，请使用桌面端提取。",
                        formatSize(threshold)));
            }

            // 前置检查完成，推进到 0.02
            if (listener != null) {
                listener.onProgress(0.02);
            }

            // 步骤 3：提取元数据与 Payload 到临时文件（恒定内存）
            if (!(adapter instanceof AbstractCarrierAdapter abstractAdapter)) {
                // 非标准适配器：先提取 Payload，再从 Payload 中读取 Header（有限信息）
                byte[] payload = adapter.extract(stegoFile, effectivePwd);
                PayloadCodec.PayloadHeader header = PayloadCodec.readHeader(payload);
                // 这种情况下加密参数未知，无法解密——抛出异常
                throw new FileStegoException(
                        "适配器 " + adapter.id() + " 不支持返回密码学参数，无法解密");
            }

            Path payloadFile = Files.createTempFile("ergou-stego-extract-", ".tmp");
            Path plaintextTmp = Files.createTempFile("ergou-stego-plain-", ".tmp");
            try {
                // 阶段 0.02~0.50：Payload 从载体流式提取
                ProgressListener carrierListener = listener == null ? null
                        : f -> listener.onProgress(0.02 + 0.48 * f);
                CarrierMetadata meta = abstractAdapter.extractFullToFile(
                        stegoFile, effectivePwd, payloadFile, carrierListener);

                // 步骤 4：流式解密（Argon2 参数从载体元数据读取），阶段 0.50~1.00
                ProgressListener decodeListener = listener == null ? null
                        : f -> listener.onProgress(0.50 + 0.50 * f);
                PayloadCodec.PayloadHeader header = PayloadCodec.decodeToFile(
                        payloadFile, plaintextTmp, effectivePwd,
                        meta.salt(), meta.hkdfSalt(), meta.nonce(),
                        meta.serpentIv(), meta.isParanoid(), meta.argon2Params(),
                        decodeListener);

                // 步骤 5：移动明文到最终输出路径
                Files.createDirectories(outputDir);
                Path outputFile = outputDir.resolve(header.origName());
                Files.move(plaintextTmp, outputFile, java.nio.file.StandardCopyOption.REPLACE_EXISTING);

                if (listener != null) {
                    listener.onProgress(1.0);
                }
                guard.recordSuccess(filePath);
                return outputFile;
            } finally {
                Files.deleteIfExists(payloadFile);
                Files.deleteIfExists(plaintextTmp);
            }
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
     * 只读预检隐写载体：读取元数据中的 Argon2 档位与 Payload 头的压缩标志。
     *
     * <p>供移动端在提取前调用（对齐卷路径的「加密前压缩」防护策略）：无需完整
     * 提取 Payload，只读元数据（判定 KDF 档位）与 Payload 头前 10 字节（判定
     * 「加密前压缩」标志）。非隐写文件或读取失败返回 {@link StegoPreflight#UNKNOWN}。
     *
     * @param stegoFile 隐写载体文件
     * @param password  密码（可为 null；文件隐写载体定位不依赖密码）
     * @return 预检结果；无法判定时返回 {@link StegoPreflight#UNKNOWN}
     */
    public StegoPreflight preflight(final Path stegoFile, final byte[] password) {
        try {
            CarrierAdapter adapter = findAdapterForExtract(stegoFile);
            if (!(adapter instanceof AbstractCarrierAdapter abstractAdapter)) {
                return StegoPreflight.UNKNOWN;
            }
            // 非流式适配器（PDF/WAV/FLAC）读元数据会整读文件，大文件预检可能 OOM；
            // 跳过预检，交由提取路径的 lowMemoryMode 护栏拒绝（与 extract 口径一致）
            if (Files.size(stegoFile) > PREFLIGHT_MAX_BYTES
                    && !adapter.supportsStreamingExtract()) {
                return StegoPreflight.UNKNOWN;
            }
            CarrierMetadata meta = abstractAdapter.readMetadataOnly(stegoFile, password);
            Integer memoryKib = meta.argon2Params() != null
                    ? meta.argon2Params().memoryKiB() : null;
            Boolean compressed = null;
            try {
                byte[] prefix = abstractAdapter.readPayloadPrefix(stegoFile, meta, 10);
                compressed = PayloadCodec.isCompressedFlag(prefix);
            } catch (CarrierException ignored) {
                // 压缩标志读取失败不影响档位判定，compressed 保持 null
            }
            return new StegoPreflight(memoryKib, compressed);
        } catch (Exception e) {
            return StegoPreflight.UNKNOWN;
        }
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
     * 在文件末尾追加密码学随机字节，直到达到目标大小，并按已追加字节数回调进度。
     *
     * @param file        待混淆的文件
     * @param targetBytes 目标文件大小（字节）
     * @param listener    进度监听器（可为 null）
     * @throws IOException        文件读写失败
     * @throws FileStegoException 目标大小不大于当前文件大小
     */
    private static void padToSize(final Path file, final long targetBytes,
                                  final ProgressListener listener)
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
                if (listener != null) {
                    listener.onProgress((double) (toAdd - remaining) / Math.max(toAdd, 1L));
                }
            }
            if (listener != null && toAdd <= 0) {
                listener.onProgress(1.0);
            }
        }
    }

    /**
     * 解析低内存模式的大文件护栏阈值。
     *
     * <p>优先使用选项中的显式阈值（移动端按设备实际可用堆计算）；未设置时
     * 回退到内置默认值 {@link #LARGE_PAYLOAD_THRESHOLD_BYTES}。
     *
     * @param options 文件隐写选项
     * @return 生效的护栏阈值（字节）
     */
    private static long lowMemoryThreshold(final FileStegoOptions options) {
        long custom = options.lowMemoryThresholdBytes();
        return custom > 0 ? custom : LARGE_PAYLOAD_THRESHOLD_BYTES;
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
