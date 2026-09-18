package hbnu.project.ergoutreecrypt.imagecrypt;

import hbnu.project.ergoutreecrypt.crypto.KdfProgress;
import hbnu.project.ergoutreecrypt.crypto.Mac;
import hbnu.project.ergoutreecrypt.crypto.RandomBytes;
import hbnu.project.ergoutreecrypt.crypto.SecureZero;
import hbnu.project.ergoutreecrypt.crypto.XChaCha20;
import hbnu.project.ergoutreecrypt.exception.CancelledException;
import hbnu.project.ergoutreecrypt.exception.CryptoException;
import hbnu.project.ergoutreecrypt.exception.ErrorKind;
import hbnu.project.ergoutreecrypt.filetypes.OutputNaming;
import hbnu.project.ergoutreecrypt.imagecrypt.png.PixelPngReader;
import hbnu.project.ergoutreecrypt.imagecrypt.png.PixelPngWriter;
import hbnu.project.ergoutreecrypt.imagecrypt.png.RobustPngWriter;
import hbnu.project.ergoutreecrypt.imagecrypt.robust.RobustCarrier;
import hbnu.project.ergoutreecrypt.log.LogService;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.SequenceInputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.FileStore;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;
import java.util.Objects;

/**
 * EGTC-IMG 图片加密子系统门面：加密、还原、只读探测与完整性校验。
 *
 * <h3>数据流</h3>
 * <pre>
 *   加密  [原文件] → ImageProbe → InnerManifest ┐
 *                                              ├→ XChaCha20 → BLAKE2b → RGB 扫描行 → PNG
 *    还原  [PNG] → 反滤波取 RGB → OuterHeader ──┘
 * </pre>
 * 加解密共用同一条流式管线：加密侧 {@link FrameSource} 把 {@code 头 || 密文 || 认证标签}
 * 当作逻辑字节流交给 {@link PixelPngWriter}；解密侧 {@link DecryptingFrameSink} 把 RGB 样本
 * 当作写入口，边收边解密。两侧的工作内存都固定（1 MiB 缓冲 + 单行 RGB），
 * 与图片分辨率、载荷长度无关，因此移动端不需要解码原图 Bitmap。
 *
 * <h3>阶段上报的语义</h3>
 * <p>加密路径的"读原文件 → 加密 → 累积 MAC → 写 PNG 扫描行"由同一条拉取式管线完成，
 * 无法拆成互不重叠的两段，因此只上报 {@link ImageCryptPhase#ENCRYPTING}。
 * 解密路径同理，由 {@link ImageCryptPhase#PNG_READING} 覆盖"解析 PNG → 解密 → 写临时文件"，
 * 其后依次是 {@link ImageCryptPhase#MAC_VERIFY} 与 {@link ImageCryptPhase#COMMITTING}。
 * KDF 阶段的 pass 进度走 {@link ImageCryptProgress#onKdfPass(int, int)}，不与字节进度混用。
 *
 * <h3>临时文件与提交</h3>
 * <p>还原产物一律先写目标同目录下的随机 {@code .part} 文件，只有 64 字节认证标签通过后才原子移动到目标名。
 * 任何失败路径（密码错误、标签不符、取消、I/O 异常）都会删除临时文件，因此<b>绝不会有未经认证的内容出现在目标位置</b>，目标位置也不会留下半成品。
 *
 * <h3>安全语义</h3>
 * <p>{@link ImageCryptMode#PUBLIC_RECOVERY} 把每文件随机主密钥明文写入协议头，只阻止直接查看，<b>不提供保密性</b>；其 MAC 校验只能称为"完整性通过"，不能称为"认证通过"。
 * 密码模式的 protectionMode、KDF 参数、cipherId 与 macId 全部落在认证范围内，篡改后无法把密码文件降级为公开文件。
 *
 * <h3>生命周期</h3>
 * <p>密码字节由<b>调用方</b>负责清零；核心在使用前克隆一份并在 finally 中清零自己的副本，
 * 因此不会意外改写调用方的数组，也不会把密码留到垃圾回收。日志只记录文件名，不记录完整路径、密码、密钥或 nonce。
 *
 * @author ErgouTree
 * @since 2026/9/16
 */
public final class ImageCryptCodec {

    /**
     * I/O 缓冲与流式分块大小（1 MiB）。取消检查按该粒度进行，满足协议要求的
     * "I/O 循环取消检查间隔不超过 1 MiB"。
     */
    private static final int IO_BUFFER_BYTES = 1 << 20;

    /**
     * 临时文件前缀，便于崩溃后按前缀回收陈旧残留。
     */
    private static final String TEMP_FILE_PREFIX = "egtcimg-";

    /**
     * 临时文件后缀。
     */
    private static final String TEMP_FILE_SUFFIX = ".part";

    /**
     * 临时文件随机段字节数。
     */
    private static final int TEMP_FILE_RANDOM_BYTES = 8;

    /**
     * 临时文件名冲突时的重试次数。
     */
    private static final int TEMP_FILE_ATTEMPTS = 8;

    /**
     * 磁盘空间预检的固定余量（字节），覆盖 PNG 块头与 zlib 封装开销。
     */
    private static final long DISK_OVERHEAD_BYTES = 4096L;

    /**
     * 日志分类名。
     */
    private static final String LOG_CATEGORY = "ImageCrypt";

    /**
     * 内层清单中 {@code manifestLength} 字段的结束偏移，用于判断描述区头部是否已足够解析。
     */
    private static final int MANIFEST_LENGTH_FIELD_END = 16;

    /**
     * 纠错模式中保留原文件字节的安全上限。
     *
     * <p>为协议头、认证标签、清单与交织组取整预留约 128 KiB；超过后生成 JPEG 恢复副本。
     */
    private static final long ROBUST_SOURCE_BYTES = 800_000L;

    /** 桌面大图 JPEG 转码桥。 */
    private static final String ROBUST_TRANSCODER =
            "hbnu.project.ergoutreecrypt.imagecrypt.robust.DesktopRobustPayloadTranscoder";

    /**
     * 生产随机源。
     */
    private final ImageCryptRandomSource randomSource;

    /**
     * 创建使用密码学安全随机源的生产门面。
     */
    public ImageCryptCodec() {
        this(ImageCryptRandomSource.secure());
    }

    /**
     * 创建可注入随机源的门面。
     *
     * <p>仅供同包测试构造可复现的黄金向量；包内可见，因此 UI 无法替换随机源。
     *
     * @param randomSource 随机字节来源
     */
    ImageCryptCodec(final ImageCryptRandomSource randomSource) {
        this.randomSource = Objects.requireNonNull(randomSource, "randomSource");
    }

    // ==================== 加密 ====================

    /**
     * 按选项指定的保护模式加密一张图片，不接收进度回调。
     *
     * @param input    输入图片路径
     * @param output   产物 PNG 路径
     * @param password 规范化密码字节；公开恢复模式必须为 {@code null} 或空
     * @param options  保护模式与覆盖策略
     * @throws ImageCryptException 输入不是受支持的图片、载荷超过画布上限、磁盘不足或输出已存在
     * @throws CancelledException  调用方在流程中请求取消
     * @throws IOException         读写失败
     */
    public void encrypt(final Path input, final Path output, final byte[] password,
                        final ImageCryptOptions options)
            throws ImageCryptException, CancelledException, IOException {
        encrypt(input, output, password, options, ImageCryptProgress.NONE);
    }

    /**
     * 按选项指定的保护模式加密一张图片。
     *
     * <p>输入按"完整原文件字节"处理：不解码、不重编码，因此 JPEG 量化表、EXIF、ICC、
     * 动画帧与调色板都随原始字节完整往返。产物是标准 8-bit RGB PNG，在普通看图软件中
     * 显示为无意义的噪声图。
     *
     * @param input    输入图片路径
     * @param output   产物 PNG 路径
     * @param password 已由 {@link ImageCryptPassword#encodeForV1(String)} 规范化的密码字节；
     *                 公开恢复模式必须为 {@code null} 或空
     * @param options  保护模式与覆盖策略；为 {@code null} 时使用 {@link ImageCryptOptions#DEFAULT}
     * @param progress 进度与取消回调，可为 {@code null}
     * @throws ImageCryptException 输入不是受支持的图片、载荷超过画布上限、磁盘不足或输出已存在
     * @throws CancelledException  调用方在流程中请求取消
     * @throws IOException         读写失败
     */
    public void encrypt(final Path input, final Path output, final byte[] password,
                        final ImageCryptOptions options, final ImageCryptProgress progress)
            throws ImageCryptException, CancelledException, IOException {
        Objects.requireNonNull(input, "input");
        Objects.requireNonNull(output, "output");
        ImageCryptOptions effectiveOptions = options == null ? ImageCryptOptions.DEFAULT : options;
        ImageCryptProgress listener = progress == null ? ImageCryptProgress.NONE : progress;
        effectiveOptions.validatePassword(password);

        Path source = normalized(input);
        Path target = normalized(output);
        requireRegularFile(source, "输入图片");
        prepareEncryptTarget(source, target, effectiveOptions);

        byte[] passwordCopy = password == null ? null : password.clone();
        ImageKeySchedule keys = null;
        Path tempFile = null;
        Path payloadTempFile = null;
        boolean committed = false;
        try {
            listener.onPhase(ImageCryptPhase.PROBE);
            ImageProbe.Result probe = ImageProbe.probe(source);
            if (!probe.recognized()) {
                throw new ImageCryptException(ErrorKind.UNSUPPORTED_FORMAT,
                        "输入不是受支持的图片格式: " + source.getFileName());
            }
            long sourceLength = Files.size(source);
            if (sourceLength <= 0) {
                throw new ImageCryptException(ErrorKind.UNSUPPORTED_FORMAT,
                        "输入图片为空文件: " + source.getFileName());
            }
            if (probe.extensionConflict()) {
                LogService.warn(LOG_CATEGORY, "扩展名与实际格式不一致，按魔数判定为 "
                        + probe.format() + "：" + source.getFileName());
            }

            Path payloadSource = source;
            ImageProbe.Result payloadProbe = probe;
            String payloadName = source.getFileName().toString();
            if (effectiveOptions.errorCorrection() && sourceLength > ROBUST_SOURCE_BYTES) {
                payloadTempFile = createTempFile(target.getParent());
                transcodeRobustPayload(source, payloadTempFile, ROBUST_SOURCE_BYTES);
                payloadSource = payloadTempFile;
                payloadProbe = ImageProbe.probe(payloadSource);
                if (!payloadProbe.recognized() || payloadProbe.format() != ImageFormat.JPEG) {
                    throw new ImageCryptException(ErrorKind.INTERNAL_ERROR,
                            "纠错模式 JPEG 恢复副本生成失败");
                }
                sourceLength = Files.size(payloadSource);
                payloadName = replaceExtension(payloadName, "jpg");
                LogService.warn(LOG_CATEGORY, "原图超过抗重编码容量，已生成有损 JPEG 恢复副本："
                        + source.getFileName());
            }

            ImageFormat format = payloadProbe.format();
            InnerManifest manifest = InnerManifest.create(format, sourceLength,
                    payloadName, format.defaultMimeType(),
                    effectiveOptions.errorCorrection() && payloadTempFile != null
                            ? "jpg" : resolveExtension(source, format), false);
            byte[] descriptor = manifest.toBytes();
            long innerPlainLength = manifest.totalLength();
            long logicalLength;
            try {
                logicalLength = Math.addExact((long) ImageCryptProtocol.OUTER_HEADER_LENGTH,
                        innerPlainLength);
                logicalLength = Math.addExact(logicalLength,
                        (long) ImageCryptProtocol.AUTH_TAG_LENGTH);
            } catch (ArithmeticException e) {
                throw new ImageCryptException(ErrorKind.CAPACITY_INSUFFICIENT,
                        "协议帧长度溢出", e);
            }
            int[] canvas;
            if (effectiveOptions.errorCorrection()) {
                canvas = RobustCarrier.chooseCanvas(logicalLength);
            } else {
                long requiredPixels = ImageCryptProtocol.requiredPixels(innerPlainLength);
                if (requiredPixels <= 0) {
                    throw new ImageCryptException(ErrorKind.CAPACITY_INSUFFICIENT,
                            "载荷长度超出画布可承载上限");
                }
                canvas = ImageCryptProtocol.chooseCanvasSize(requiredPixels,
                        payloadProbe.width(), payloadProbe.height());
            }
            long outputEstimate = Math.multiplyExact(
                    Math.multiplyExact((long) canvas[0], (long) canvas[1]),
                    (long) ImageCryptProtocol.PNG_BYTES_PER_PIXEL);
            checkDiskSpace(target.getParent(), outputEstimate + DISK_OVERHEAD_BYTES);

            byte[] hkdfSalt = randomSource.nextBytes(ImageCryptProtocol.HKDF_SALT_LENGTH);
            byte[] nonce = randomSource.nextBytes(ImageCryptProtocol.NONCE_LENGTH);
            ImageCryptFrame frame;
            if (effectiveOptions.requiresPassword()) {
                byte[] argon2Salt = randomSource.nextBytes(ImageCryptProtocol.ARGON2_SALT_LENGTH);
                listener.onPhase(ImageCryptPhase.KDF);
                keys = ImageKeySchedule.fromPassword(passwordCopy, argon2Salt, hkdfSalt,
                        passListener(listener));
                frame = ImageCryptFrame.newPasswordFrame(canvas[0], canvas[1], innerPlainLength,
                        payloadProbe.width(), payloadProbe.height(), argon2Salt, hkdfSalt, nonce);
            } else {
                byte[] masterKey = randomSource.nextBytes(ImageCryptProtocol.MASTER_KEY_LENGTH);
                keys = ImageKeySchedule.fromPublicMasterKey(masterKey, hkdfSalt);
                frame = ImageCryptFrame.newPublicFrame(canvas[0], canvas[1], innerPlainLength,
                        payloadProbe.width(), payloadProbe.height(), hkdfSalt, nonce, masterKey);
                SecureZero.zero(masterKey);
            }

            byte[] keyConfirm = keys.computeKeyConfirm(frame.keyConfirmPrefixBytes());
            try {
                frame = frame.withKeyConfirm(keyConfirm);
            } finally {
                SecureZero.zero(keyConfirm);
            }
            byte[] headerBytes = frame.toBytes();
            listener.onPhase(ImageCryptPhase.ENCRYPTING);
            tempFile = createTempFile(target.getParent());
            XChaCha20 cipher = new XChaCha20(keys.encKey(), frame.nonce());
            Mac mac = keys.beginAuthTag(frame.authenticationPrefixBytes(), innerPlainLength);
            commitLogicalFrame(payloadSource, tempFile, descriptor, headerBytes, innerPlainLength,
                    canvas, cipher, mac, listener, logicalLength,
                    effectiveOptions.errorCorrection());
            commit(tempFile, target, effectiveOptions.overwriteExisting());
            committed = true;
            listener.onPhase(ImageCryptPhase.DONE);
            LogService.info(LOG_CATEGORY, "图片加密完成 → " + target.getFileName());
        } finally {
            SecureZero.zero(passwordCopy);
            if (keys != null) {
                keys.close();
            }
            if (!committed) {
                deleteQuietly(tempFile, "图片加密未完成，已清理临时文件");
            }
            deleteQuietly(payloadTempFile, "已清理纠错模式 JPEG 临时副本");
        }
    }

    /**
     * 把逻辑协议帧流式写成 PNG。
     *
     * <p>临时文件的写入被隔离在这里，是为了让 {@link ImageCryptException} 与
     * {@link CancelledException} 能在 {@link IOException} 边界上原样穿过 PNG 编解码层：
     * 流回调把它们包装为 {@link LogicalStreamException}，本方法在边界处还原。
     *
     * @param source          输入图片
     * @param tempFile        产物临时文件
     * @param descriptor      清单描述区字节
     * @param headerBytes     184 字节协议头（已含 headerCrc32）
     * @param innerPlainLength 加密封装区长度
     * @param canvas          画布尺寸二元数组
     * @param cipher          XChaCha20 实例
     * @param mac             已喂入认证前缀的 MAC
     * @param listener        进度与取消回调
     * @param logicalLength   逻辑帧总长度
     * @param errorCorrection 是否写为抗重编码纠错载体
     * @throws ImageCryptException 载体格式、长度或认证标签构造失败
     * @throws CancelledException  用户取消
     * @throws IOException         读写失败
     */
    private static void commitLogicalFrame(final Path source, final Path tempFile,
                                           final byte[] descriptor, final byte[] headerBytes,
                                           final long innerPlainLength, final int[] canvas,
                                           final XChaCha20 cipher, final Mac mac,
                                           final ImageCryptProgress listener,
                                           final long logicalLength,
                                           final boolean errorCorrection)
            throws ImageCryptException, CancelledException, IOException {
        try (InputStream plaintext = new SequenceInputStream(
                new ByteArrayInputStream(descriptor), Files.newInputStream(source));
             InputStream logical = new FrameSource(headerBytes, plaintext, cipher, mac,
                     innerPlainLength, listener);
             OutputStream rawOutput = Files.newOutputStream(tempFile,
                     StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING)) {
            if (errorCorrection) {
                new RobustPngWriter().write(rawOutput, canvas[0], canvas[1], logical,
                        logicalLength);
            } else {
                new PixelPngWriter().write(rawOutput, canvas[0], canvas[1], logical,
                        logicalLength);
            }
        } catch (LogicalStreamException e) {
            rethrow(e);
        }
    }

    /**
     * 校验加密的输出路径。
     *
     * @param source  输入图片
     * @param target  产物路径
     * @param options 覆盖策略
     * @throws ImageCryptException 源与目标同路径、目标是目录或已存在且不允许覆盖
     * @throws IOException         创建父目录失败
     */
    private static void prepareEncryptTarget(final Path source, final Path target,
                                             final ImageCryptOptions options)
            throws ImageCryptException, IOException {
        if (target.equals(source)) {
            throw new ImageCryptException(ErrorKind.INTERNAL_ERROR, "输出路径不得与输入图片相同");
        }
        Path parent = target.getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
        if (Files.isDirectory(target)) {
            throw new ImageCryptException(ErrorKind.FILE_EXISTS, "输出路径是一个目录");
        }
        if (!options.overwriteExisting() && Files.exists(target)) {
            throw new ImageCryptException(ErrorKind.FILE_EXISTS,
                    "目标文件已存在: " + target.getFileName());
        }
    }

    // ==================== 还原 ====================

    /**
     * 还原 EGTC-IMG 产物，输出到给定目录，不覆盖同名文件。
     *
     * @param input           待还原的 PNG 路径
     * @param outputDirectory 输出目录，不存在时创建
     * @param password        规范化密码字节；公开恢复模式可传 {@code null}
     * @param progress        进度与取消回调，可为 {@code null}
     * @return 实际写入的恢复文件路径
     * @throws ImageCryptException 输入不是 EGTC-IMG、密码错误、载荷损坏或目标已存在
     * @throws CancelledException  调用方在流程中请求取消
     * @throws IOException         读写失败
     */
    public Path decrypt(final Path input, final Path outputDirectory, final byte[] password,
                        final ImageCryptProgress progress)
            throws ImageCryptException, CancelledException, IOException {
        return decrypt(input, outputDirectory, password, false, progress);
    }

    /**
     * 还原 EGTC-IMG 产物，输出到给定目录，不覆盖同名文件、不接收进度回调。
     *
     * @param input           待还原的 PNG 路径
     * @param outputDirectory 输出目录，不存在时创建
     * @param password        规范化密码字节；公开恢复模式可传 {@code null}
     * @return 实际写入的恢复文件路径
     * @throws ImageCryptException 输入不是 EGTC-IMG、密码错误、载荷损坏或目标已存在
     * @throws CancelledException  调用方在流程中请求取消
     * @throws IOException         读写失败
     */
    public Path decrypt(final Path input, final Path outputDirectory, final byte[] password)
            throws ImageCryptException, CancelledException, IOException {
        return decrypt(input, outputDirectory, password, false, ImageCryptProgress.NONE);
    }

    /**
     * 还原 EGTC-IMG 产物，输出到给定目录。
     *
     * <p>恢复文件名由加密区内的 InnerManifest 决定：清单中的 basename 经
     * {@link InnerManifest#safeBasename()} 清洗后作为基名并插入 {@code .restored} 标记；
     * 名称缺失或非法时退化为 {@code restored.<扩展名>}。目录成分、盘符与路径分隔符一律被
     * 剥离，因此恶意构造的文件名无法把产物写出到目标目录之外。
     *
     * <p>目标已存在时默认拒绝覆盖，而不是静默替换；过期判定发生在解出清单之后、
     * 开始写原文件字节之前，因此冲突会在极短时间内报告，不会白等一次完整解密。
     *
     * @param input             待还原的 PNG 路径
     * @param outputDirectory   输出目录，不存在时创建
     * @param password          规范化密码字节；公开恢复模式可传 {@code null}
     * @param overwriteExisting true 表示允许覆盖同名恢复产物
     * @param progress          进度与取消回调，可为 {@code null}
     * @return 实际写入的恢复文件路径
     * @throws ImageCryptException 输入不是 EGTC-IMG、密码错误、载荷损坏或目标已存在
     * @throws CancelledException  调用方在流程中请求取消
     * @throws IOException         读写失败
     */
    public Path decrypt(final Path input, final Path outputDirectory, final byte[] password,
                        final boolean overwriteExisting, final ImageCryptProgress progress)
            throws ImageCryptException, CancelledException, IOException {
        return decrypt(input, outputDirectory, password, overwriteExisting, false, progress);
    }

    /**
     * 还原 EGTC-IMG 产物，并可在显式授权时保留认证失败的尽力恢复结果。
     *
     * <p>尽力恢复不会绕过密码确认，也不会猜测损坏的协议头；它只在纠错层已尽可能恢复
     * 密文字节后，允许认证标签不一致的明文临时文件被提交。输出可能是局部损坏的图片。
     *
     * @param input 待还原图片
     * @param outputDirectory 输出目录
     * @param password 规范化密码字节
     * @param overwriteExisting 是否覆盖同名文件
     * @param bestEffort 是否允许提交未通过最终认证的有损恢复结果
     * @param progress 进度回调
     * @return 实际恢复文件路径
     * @throws ImageCryptException 协议头、密码、输出或严格认证失败
     * @throws CancelledException 用户取消
     * @throws IOException 文件读写失败
     */
    public Path decrypt(final Path input, final Path outputDirectory, final byte[] password,
                        final boolean overwriteExisting, final boolean bestEffort,
                        final ImageCryptProgress progress)
            throws ImageCryptException, CancelledException, IOException {
        Objects.requireNonNull(input, "input");
        Objects.requireNonNull(outputDirectory, "outputDirectory");
        ImageCryptProgress listener = progress == null ? ImageCryptProgress.NONE : progress;

        Path source = normalized(input);
        Path directory = normalized(outputDirectory);
        requireRegularFile(source, "待还原文件");
        Files.createDirectories(directory);

        byte[] passwordCopy = password == null ? null : password.clone();
        DecryptingFrameSink sink = null;
        try {
            listener.onPhase(ImageCryptPhase.PROBE);
            ImageCryptFrame header = peek(source);
            requirePassword(header, passwordCopy);
            checkDiskSpace(directory, header.innerPlainLength() + DISK_OVERHEAD_BYTES);

            Path tempFile = createTempFile(directory);
            sink = new DecryptingFrameSink(passwordCopy, directory, tempFile, overwriteExisting,
                    true, bestEffort, listener);
            decodeFrame(source, sink);

            listener.onPhase(ImageCryptPhase.COMMITTING);
            Path target = sink.targetPath();
            if (target.equals(source)) {
                throw new ImageCryptException(ErrorKind.FILE_EXISTS,
                        "恢复目标与输入文件相同: " + target.getFileName());
            }
            commit(tempFile, target, overwriteExisting);
            sink.markCommitted();
            listener.onPhase(ImageCryptPhase.DONE);
            LogService.info(LOG_CATEGORY, "图片还原完成 → " + target.getFileName());
            return target;
        } finally {
            SecureZero.zero(passwordCopy);
            if (sink != null) {
                sink.closeQuietly();
            }
        }
    }

    // ==================== 只读探测与校验 ====================

    /**
     * 轻量判断文件是否为 EGTC-IMG 产物。
     *
     * <p>只解压到足以读出外层协议头为止，不解密任何载荷，也不做认证。因此该方法是给功能路由
     * 使用的<b>提示性</b>判断：返回 true 只说明外层结构声明了 EGTC-IMG 帧，不说明文件完整、
     * 密码正确或未被篡改。文件不存在、不是普通文件、不是 PNG 或结构不是 EGTC-IMG 时一律
     * 返回 false，使调用方能把普通 PNG 与图片密文分流。
     *
     * @param input 待探测文件
     * @return true 表示外层结构为 EGTC-IMG PNG
     * @throws IOException 读取失败（例如无权限）
     */
    public boolean isEncrypted(final Path input) throws IOException {
        Path source = normalized(input);
        if (!Files.isRegularFile(source)) {
            return false;
        }
        try {
            peek(source);
            return true;
        } catch (ImageCryptException e) {
            LogService.trace(LOG_CATEGORY, "EGTC-IMG 轻探测未通过: " + e.getMessage());
            return false;
        }
    }

    /**
     * 只读探测 EGTC-IMG 元数据。
     *
     * <p>只读取并校验 184 字节外层协议头，<b>不派生任何密码密钥</b>，也不读取加密区。
     * 因此原始文件名、MIME 与真实扩展名不可得，内容长度只能给出区间。
     *
     * @param input 待探测文件
     * @return 外层协议头解析出的元数据
     * @throws ImageCryptException 不是 EGTC-IMG、协议版本不支持或外层结构损坏
     * @throws IOException         读取失败
     */
    public ImageCryptMetadata peekMetadata(final Path input)
            throws ImageCryptException, IOException {
        Objects.requireNonNull(input, "input");
        return ImageCryptMetadata.from(peek(normalized(input)));
    }

    /**
     * 校验产物的完整性与认证标签，不产生任何恢复文件、不接收进度回调。
     *
     * @param input    待校验的 PNG 路径
     * @param password 规范化密码字节；公开恢复模式可传 {@code null}
     * @throws ImageCryptException 不是 EGTC-IMG、密码模式未提供密码、密码错误或载荷被修改
     * @throws CancelledException  调用方在流程中请求取消
     * @throws IOException         读取失败
     */
    public void verify(final Path input, final byte[] password)
            throws ImageCryptException, CancelledException, IOException {
        verify(input, password, ImageCryptProgress.NONE);
    }

    /**
     * 校验产物的完整性与认证标签，不产生任何恢复文件。
     *
     * <h3>为什么以异常而不是布尔值表达失败</h3>
     * <p>协议要求把"密码错误"与"载荷损坏"明确区分开：前者应提示用户重新输入密码，后者应提示
     * 文件已损坏或被修改，两者对用户的下一步动作完全不同。布尔返回值无法承载这一区分，
     * 因此本方法在认证不通过时抛出带 {@link ErrorKind} 的分类异常，成功时正常返回。
     *
     * <p>密码模式下每次调用都会完整执行一遍 Argon2id，因此无法绕过 KDF 快速试探密码；
     * 校验过程不写出任何恢复文件，只把解密结果丢弃。
     *
     * @param input    待校验的 PNG 路径
     * @param password 规范化密码字节；公开恢复模式可传 {@code null}
     * @param progress 进度与取消回调，可为 {@code null}
     * @throws ImageCryptException 不是 EGTC-IMG、密码模式未提供密码、密码错误（{@link ErrorKind#WRONG_PASSWORD}）
     *                             或载荷被修改（{@link ErrorKind#TAMPERED_DATA}）
     * @throws CancelledException  调用方在流程中请求取消
     * @throws IOException         读取失败
     */
    public void verify(final Path input, final byte[] password, final ImageCryptProgress progress)
            throws ImageCryptException, CancelledException, IOException {
        Objects.requireNonNull(input, "input");
        ImageCryptProgress listener = progress == null ? ImageCryptProgress.NONE : progress;

        Path source = normalized(input);
        requireRegularFile(source, "待校验文件");

        byte[] passwordCopy = password == null ? null : password.clone();
        DecryptingFrameSink sink = null;
        try {
            listener.onPhase(ImageCryptPhase.PROBE);
            ImageCryptFrame header = peek(source);
            requirePassword(header, passwordCopy);

            sink = new DecryptingFrameSink(passwordCopy, source.getParent(), null, false,
                    false, false, listener);
            decodeFrame(source, sink);
            listener.onPhase(ImageCryptPhase.DONE);
        } finally {
            SecureZero.zero(passwordCopy);
            if (sink != null) {
                sink.closeQuietly();
            }
        }
    }

    /**
     * 以给定接收器完整解析并认证一份产物。
     *
     * @param source 输入路径
     * @param sink   解密接收器
     * @throws ImageCryptException 结构、密码或认证失败
     * @throws CancelledException  用户取消
     * @throws IOException         读写失败
     */
    private static void decodeFrame(final Path source, final DecryptingFrameSink sink)
            throws ImageCryptException, CancelledException, IOException {
        if (isDirectCarrier(source)) {
            try (InputStream rawInput = new BufferedInputStream(
                    Files.newInputStream(source), IO_BUFFER_BYTES)) {
                new PixelPngReader().readFrame(rawInput, sink);
            } catch (LogicalStreamException e) {
                rethrow(e);
            }
            return;
        }
        try {
            boolean corrupted = RobustCarrier.readFrame(source, sink);
            if (corrupted) {
                LogService.warn(LOG_CATEGORY,
                        "纠错载体存在超过 Reed-Solomon 能力的码字，已使用尽力恢复数据");
            }
        } catch (LogicalStreamException e) {
            rethrow(e);
        }
    }

    /**
     * 轻量读取外层协议头。
     *
     * @param source 已经规范化的输入路径
     * @return 外层协议头
     * @throws ImageCryptException 结构非法或版本不支持
     * @throws IOException         读取失败
     */
    private static ImageCryptFrame peek(final Path source) throws ImageCryptException, IOException {
        try {
            return peekDirect(source);
        } catch (ImageCryptException directFailure) {
            if (directFailure.kind() != ErrorKind.NOT_IMAGE_CRYPT) {
                throw directFailure;
            }
            try {
                return RobustCarrier.peekFrame(source);
            } catch (ImageCryptException robustFailure) {
                robustFailure.addSuppressed(directFailure);
                throw robustFailure;
            }
        }
    }

    /**
     * 判断输入是否为原始逐 RGB 字节载体。
     *
     * @param source 输入路径
     * @return true 表示原始载体头可解析
     * @throws IOException 读取失败
     */
    private static boolean isDirectCarrier(final Path source) throws IOException {
        try {
            peekDirect(source);
            return true;
        } catch (ImageCryptException e) {
            return false;
        }
    }

    /**
     * 只按原始 PNG RGB 字节布局读取协议头。
     *
     * @param source 输入路径
     * @return 外层协议头
     * @throws ImageCryptException 不是原始载体
     * @throws IOException 读取失败
     */
    private static ImageCryptFrame peekDirect(final Path source)
            throws ImageCryptException, IOException {
        try (InputStream rawInput = new BufferedInputStream(
                Files.newInputStream(source), IO_BUFFER_BYTES)) {
            byte[] signature = readFully(rawInput, ImageCryptProtocol.PNG_SIGNATURE.length);
            if (signature == null || !Arrays.equals(signature, ImageCryptProtocol.PNG_SIGNATURE)) {
                throw new ImageCryptException(ErrorKind.NOT_IMAGE_CRYPT,
                        "输入不是 PNG 容器，未检测到 EGTC-IMG 图片密文: " + source.getFileName());
            }
            // 签名已经在手上，重新拼回流的头部再交给 PNG reader，避免依赖 mark/reset 支持
            return new PixelPngReader().peekFrame(new SequenceInputStream(
                    new ByteArrayInputStream(signature), rawInput));
        }
    }

    /**
     * 从流中读满指定字节数。
     *
     * <p>刻意不用 {@code InputStream#readNBytes(int)}：它自 Android 13（API 33）才存在，而本项目
     * minSdk 为 26，依赖它会让共享核心在旧设备上崩溃——这类问题在宿主 JVM 测试中完全不可见。
     * 这里只使用 JDK 8 就已具备的 {@code read(byte[], int, int)}。
     *
     * @param input 输入流；本方法不会关闭
     * @param length 期望读取的字节数
     * @return 读满的字节数组；流在读满前结束时返回 {@code null}
     * @throws IOException 底层读取失败
     */
    private static byte[] readFully(final InputStream input, final int length) throws IOException {
        byte[] buffer = new byte[length];
        int read = 0;
        while (read < length) {
            int count = input.read(buffer, read, length - read);
            if (count < 0) {
                return null;
            }
            read += count;
        }
        return buffer;
    }

    /**
     * 校验密码模式文件确实拿到了密码。
     *
     * @param header   外层协议头
     * @param password 密码字节
     * @throws ImageCryptException 密码模式但未提供密码
     */
    private static void requirePassword(final ImageCryptFrame header, final byte[] password)
            throws ImageCryptException {
        if (header.protectionMode() == ImageCryptMode.PASSWORD
                && (password == null || password.length == 0)) {
            throw new ImageCryptException(ErrorKind.INTERNAL_ERROR,
                    "该文件受密码保护，必须提供密码后才能还原");
        }
    }

    // ==================== 路径与磁盘工具 ====================

    /**
     * 规范化为绝对路径并消除 {@code .} 与 {@code ..}，避免同一文件因写法不同被判为不同目标。
     *
     * @param path 原始路径
     * @return 规范化路径
     */
    private static Path normalized(final Path path) {
        return path.toAbsolutePath().normalize();
    }

    /**
     * 要求路径指向一个存在的普通文件。
     *
     * @param path 路径
     * @param role 角色描述（用于诊断消息）
     * @throws ImageCryptException 路径不存在或是目录
     */
    private static void requireRegularFile(final Path path, final String role)
            throws ImageCryptException {
        if (!Files.exists(path)) {
            throw new ImageCryptException(ErrorKind.INPUT_NOT_FOUND,
                    role + "不存在: " + path.getFileName());
        }
        if (!Files.isRegularFile(path)) {
            throw new ImageCryptException(ErrorKind.UNSUPPORTED_FORMAT,
                    role + "不是普通文件: " + path.getFileName());
        }
    }

    /**
     * 在写入前预检磁盘可用空间。
     *
     * <p>空间不足必须尽早发现：等写满磁盘才失败会让用户在目标目录留下半个文件，而写入已经
     * 消耗了等待时间。无法查询可用空间时不做阻断，交由实际写入阶段报错。
     *
     * <p>这是一次<b>尽力而为</b>的预检，因此必须容忍各平台查询文件系统信息时的差异。
     * Android 的 ART 会在 {@code Files.getFileStore} 上抛出 {@link SecurityException}
     * ——平台的 {@code statvfs} 实现受 SELinux 策略约束，宿主 JVM 上完全看不到这个问题。
     * 若只捕获 {@code IOException}，一次成功的加密就会因为一个纯提示性的预检而在设备上崩溃。
     *
     * @param directory     目标目录
     * @param requiredBytes 预计需要的字节数
     * @throws ImageCryptException 可用空间不足
     */
    private static void checkDiskSpace(final Path directory, final long requiredBytes)
            throws ImageCryptException {
        if (directory == null || requiredBytes <= 0) {
            return;
        }
        try {
            FileStore store = Files.getFileStore(directory);
            long usable = store.getUsableSpace();
            if (usable > 0 && usable < requiredBytes) {
                throw new ImageCryptException(ErrorKind.DISK_FULL,
                        "磁盘空间不足: 需要约 " + requiredBytes + " 字节，可用 " + usable + " 字节");
            }
        } catch (IOException | SecurityException | UnsupportedOperationException e) {
            LogService.trace(LOG_CATEGORY, "无法查询磁盘可用空间，跳过预检: "
                    + e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    /**
     * 通过桌面桥把超大源图转换为限定大小的 JPEG 恢复副本。
     *
     * @param source 输入图片
     * @param target JPEG 临时文件
     * @param maximumBytes 最大字节数
     * @throws ImageCryptException 当前平台不支持转码或图片无法压缩到目标大小
     * @throws IOException 文件读写失败
     */
    private static void transcodeRobustPayload(final Path source, final Path target,
                                               final long maximumBytes)
            throws ImageCryptException, IOException {
        try {
            Class<?> type = Class.forName(ROBUST_TRANSCODER);
            Method method = type.getMethod("transcode", Path.class, Path.class, long.class);
            method.invoke(null, source, target, maximumBytes);
        } catch (ClassNotFoundException | NoSuchMethodException | IllegalAccessException e) {
            throw new ImageCryptException(ErrorKind.CAPACITY_INSUFFICIENT,
                    "当前平台无法为超大图片生成纠错模式 JPEG 恢复副本", e);
        } catch (InvocationTargetException e) {
            Throwable cause = e.getCause();
            if (cause instanceof ImageCryptException imageCrypt) {
                throw imageCrypt;
            }
            if (cause instanceof IOException io) {
                throw io;
            }
            throw new ImageCryptException(ErrorKind.INTERNAL_ERROR,
                    "生成纠错模式 JPEG 恢复副本失败", cause);
        }
    }

    /**
     * 把文件名的最后一个扩展名替换为指定扩展名。
     *
     * @param fileName 原文件名
     * @param extension 新扩展名，不含点
     * @return 替换后的文件名
     */
    private static String replaceExtension(final String fileName, final String extension) {
        int dot = fileName.lastIndexOf('.');
        String base = dot > 0 ? fileName.substring(0, dot) : fileName;
        return base + "." + extension;
    }

    /**
     * 在目标目录下创建一个空的随机命名临时文件。
     *
     * <p>先用随机名占位再写入，既避免与并发任务撞名，也让崩溃残留带有可识别前缀。
     *
     * @param directory 目标目录
     * @return 新建的临时文件路径
     * @throws IOException 连续多次命名冲突或创建失败
     */
    private static Path createTempFile(final Path directory) throws IOException {
        Path parent = directory == null ? Path.of(".").toAbsolutePath() : directory;
        for (int attempt = 0; attempt < TEMP_FILE_ATTEMPTS; attempt++) {
            String name = TEMP_FILE_PREFIX + toHex(RandomBytes.generate(TEMP_FILE_RANDOM_BYTES))
                    + TEMP_FILE_SUFFIX;
            try {
                return Files.createFile(parent.resolve(name));
            } catch (FileAlreadyExistsException e) {
                // 随机名冲突，换一个继续
                LogService.trace(LOG_CATEGORY, "临时文件名冲突，重试");
            }
        }
        throw new IOException("无法在目标目录创建图片加密临时文件");
    }

    /**
     * 把认证通过的临时文件提交到最终位置。
     *
     * <p>优先使用原子移动，使目标位置要么不存在要么已完整；文件系统不支持原子移动时退化为
     * 受控替换。不允许覆盖时，目标在提交瞬间出现会转为 {@link ErrorKind#FILE_EXISTS}，
     * 不会静默替换用户文件。
     *
     * @param tempFile  临时文件
     * @param target    目标路径
     * @param overwrite 是否允许覆盖
     * @throws ImageCryptException 目标已存在且不允许覆盖
     * @throws IOException         移动失败
     */
    private static void commit(final Path tempFile, final Path target, final boolean overwrite)
            throws ImageCryptException, IOException {
        if (!overwrite && Files.exists(target)) {
            throw new ImageCryptException(ErrorKind.FILE_EXISTS,
                    "目标文件已存在: " + target.getFileName());
        }
        try {
            if (overwrite) {
                Files.move(tempFile, target, StandardCopyOption.ATOMIC_MOVE,
                        StandardCopyOption.REPLACE_EXISTING);
            } else {
                Files.move(tempFile, target, StandardCopyOption.ATOMIC_MOVE);
            }
        } catch (AtomicMoveNotSupportedException e) {
            LogService.trace(LOG_CATEGORY, "文件系统不支持原子移动，退化为受控替换");
            try {
                if (overwrite) {
                    Files.move(tempFile, target, StandardCopyOption.REPLACE_EXISTING);
                } else {
                    Files.move(tempFile, target);
                }
            } catch (FileAlreadyExistsException conflict) {
                throw new ImageCryptException(ErrorKind.FILE_EXISTS,
                        "目标文件已存在: " + target.getFileName(), conflict);
            }
        }
    }

    /**
     * 尽力删除临时文件，失败只记录日志。
     *
     * @param tempFile 临时文件；为 {@code null} 时无操作
     * @param reason   删除原因（用于日志）
     */
    private static void deleteQuietly(final Path tempFile, final String reason) {
        if (tempFile == null) {
            return;
        }
        try {
            if (Files.deleteIfExists(tempFile)) {
                LogService.trace(LOG_CATEGORY, reason);
            }
        } catch (IOException e) {
            LogService.warn(LOG_CATEGORY,
                    "临时文件清理失败，将在下次启动时按前缀回收: " + e.getMessage());
        }
    }

    /**
     * 选择写入清单的规范化扩展名。
     *
     * <p>魔数是格式身份的权威来源，扩展名只用于命名。因此规则是：
     * <ul>
     *   <li>文件名扩展名<b>指向同一种格式</b>时沿用它，使 {@code photo.JPEG} 恢复成
     *       {@code photo.restored.jpeg} 而不是被规整成 {@code .jpg}；</li>
     *   <li>扩展名缺失、非法或指向另一种格式时退回格式默认值。后者很常见：用户把 PNG
     *       改名成 {@code .jp2} 再加密，若沿用该扩展名，恢复产物会是一个名叫
     *       {@code .jp2} 的 PNG 文件，用户与看图软件都会被误导。</li>
     * </ul>
     *
     * @param source 输入图片路径
     * @param format 探测出的格式
     * @return 小写扩展名（不含点）
     */
    private static String resolveExtension(final Path source, final ImageFormat format) {
        String fileName = source.getFileName().toString();
        String extension = ImageFormat.extensionOf(fileName);
        if (extension.isEmpty() || extension.length() > ImageCryptProtocol.LIMIT_EXTENSION_BYTES) {
            return format.defaultExtension();
        }
        for (int i = 0; i < extension.length(); i++) {
            char c = extension.charAt(i);
            if (!(c >= 'a' && c <= 'z') && !(c >= '0' && c <= '9')) {
                return format.defaultExtension();
            }
        }
        return ImageFormat.fromExtension(fileName) == format ? extension : format.defaultExtension();
    }

    /**
     * 把 {@link ImageCryptProgress} 适配为 Argon2 的 pass 粒度回调。
     *
     * @param listener 图片加密进度回调
     * @return KDF 进度回调
     */
    private static KdfProgress passListener(final ImageCryptProgress listener) {
        return new KdfProgress() {

            @Override
            public void onProgress(final int pass, final int totalPasses) {
                listener.onKdfPass(pass, totalPasses);
            }

            @Override
            public boolean isCancelled() {
                return listener.isCancelled();
            }
        };
    }

    /**
     * 把流回调里包装的受检异常在门面边界原样抛出。
     *
     * <p>取消与协议错误在 UI 层有不同处理，因此不能把它们降级为通用 I/O 错误；流回调内只会
     * 抛出 {@link CancelledException} 与 {@link ImageCryptException}，其它类型属于编程错误，
     * 归类为内部错误而不是误报成"文件损坏"。
     *
     * @param e 流回调包装异常
     * @throws ImageCryptException 原始协议错误或内部错误
     * @throws CancelledException  原始取消信号
     */
    private static void rethrow(final LogicalStreamException e)
            throws ImageCryptException, CancelledException {
        Throwable cause = e.getCause();
        if (cause instanceof CancelledException cancelled) {
            throw cancelled;
        }
        if (cause instanceof ImageCryptException imageCrypt) {
            throw imageCrypt;
        }
        throw new ImageCryptException(ErrorKind.INTERNAL_ERROR,
                "图片加解密流内部错误: " + e.getMessage(), cause);
    }

    /**
     * 把字节数组渲染为小写十六进制文本。
     *
     * @param data 字节数组
     * @return 十六进制文本
     */
    private static String toHex(final byte[] data) {
        StringBuilder builder = new StringBuilder(data.length * 2);
        for (byte b : data) {
            builder.append(Character.forDigit((b >> 4) & 0xf, 16));
            builder.append(Character.forDigit(b & 0xf, 16));
        }
        return builder.toString();
    }

    /**
     * 把受检的图片协议异常与取消信号穿过 {@link InputStream}/{@link OutputStream} 接口。
     *
     * <p>PNG 编解码层只认识 {@link IOException}，而取消与协议错误是受检异常。该包装在流
     * 回调内层抛出、在门面边界由 {@link #rethrow(LogicalStreamException)} 还原，
     * 使两个方向都不必把受检异常降级成通用 I/O 错误。
     *
     * @author ErgouTree
     * @since 2026/9/16
     */
    private static final class LogicalStreamException extends IOException {

        /**
         * 创建包装异常。
         *
         * @param cause 原始受检异常
         */
        private LogicalStreamException(final Throwable cause) {
            super(cause.getMessage(), cause);
        }
    }

    /**
     * 加密侧的逻辑帧输入流：{@code OuterHeader || Ciphertext || AuthTag}。
     *
     * <p>数据由 {@link PixelPngWriter} 拉取。每填满一块就加密一次并累积 MAC，因此认证标签
     * 只在整个密文产生完毕后才计算，而 PNG 扫描行已经在同步写出——原图与全部密文都不需要
     * 同时驻留内存。
     *
     * @author ErgouTree
     * @since 2026/9/16
     */
    private static final class FrameSource extends InputStream {

        /**
         * 已写出的 184 字节协议头。
         */
        private final byte[] headerBytes;

        /**
         * 明文来源：清单描述区 + 原文件字节。
         */
        private final InputStream plaintext;

        /**
         * XChaCha20 实例。
         */
        private final XChaCha20 cipher;

        /**
         * 认证标签累积器。
         */
        private final Mac mac;

        /**
         * 进度与取消回调。
         */
        private final ImageCryptProgress listener;

        /**
         * 封装区明文总长度。
         */
        private final long totalPlainLength;

        /**
         * 尚未加密的明文字节数。
         */
        private long remainingPlain;

        /**
         * 明文分块缓冲。
         */
        private final byte[] plainBuffer = new byte[IO_BUFFER_BYTES];

        /**
         * 密文分块缓冲。
         */
        private final byte[] cipherBuffer = new byte[IO_BUFFER_BYTES];

        /**
         * 协议头写出位置。
         */
        private int headerCursor;

        /**
         * 密文缓冲读取位置。
         */
        private int bufferCursor;

        /**
         * 密文缓冲有效长度。
         */
        private int bufferCount;

        /**
         * 已解出的认证标签；{@code null} 表示尚未完成。
         */
        private byte[] tag;

        /**
         * 认证标签写出位置。
         */
        private int tagCursor;

        /**
         * 已加密的明文字节数，用于进度上报。
         */
        private long processed;

        /**
         * 创建加密侧逻辑帧流。
         *
         * @param headerBytes      184 字节协议头
         * @param plaintext        清单描述区与原文件字节的拼接流
         * @param cipher           XChaCha20 实例
         * @param mac              已喂入认证前缀的 MAC
         * @param totalPlainLength 封装区明文总长度
         * @param listener         进度与取消回调
         */
        private FrameSource(final byte[] headerBytes, final InputStream plaintext,
                            final XChaCha20 cipher, final Mac mac,
                            final long totalPlainLength, final ImageCryptProgress listener) {
            this.headerBytes = headerBytes;
            this.plaintext = plaintext;
            this.cipher = cipher;
            this.mac = mac;
            this.totalPlainLength = totalPlainLength;
            this.remainingPlain = totalPlainLength;
            this.listener = listener;
        }

        /**
         * 读取一个逻辑帧字节。
         *
         * @return 字节值；逻辑帧结束时为 {@code -1}
         * @throws IOException 底层读写失败、协议错误或用户取消
         */
        @Override
        public int read() throws IOException {
            byte[] single = new byte[1];
            int count = read(single, 0, 1);
            return count < 0 ? -1 : single[0] & 0xff;
        }

        /**
         * 读取一段逻辑帧字节。
         *
         * @param target 目标缓冲
         * @param offset 起始偏移
         * @param length 最大读取长度
         * @return 实际读取数；逻辑帧结束时为 {@code -1}
         * @throws IOException 底层读写失败、协议错误或用户取消
         */
        @Override
        public int read(final byte[] target, final int offset, final int length) throws IOException {
            Objects.requireNonNull(target, "target");
            if (offset < 0 || length < 0 || offset > target.length - length) {
                throw new IndexOutOfBoundsException("逻辑帧读取缓冲区段越界");
            }
            if (length == 0) {
                return 0;
            }
            try {
                if (listener.isCancelled()) {
                    throw new CancelledException("图片加密已取消");
                }
                if (headerCursor < headerBytes.length) {
                    int count = Math.min(length, headerBytes.length - headerCursor);
                    System.arraycopy(headerBytes, headerCursor, target, offset, count);
                    headerCursor += count;
                    return count;
                }
                if (bufferCursor == bufferCount) {
                    if (remainingPlain == 0) {
                        return readTag(target, offset, length);
                    }
                    fillCipherBuffer();
                }
                int count = Math.min(length, bufferCount - bufferCursor);
                System.arraycopy(cipherBuffer, bufferCursor, target, offset, count);
                bufferCursor += count;
                return count;
            } catch (CryptoException e) {
                throw new LogicalStreamException(e);
            }
        }

        /**
         * 从认证标签区读取字节，必要时先完成标签计算。
         *
         * @param target 目标缓冲
         * @param offset 起始偏移
         * @param length 最大读取长度
         * @return 实际读取数；标签读完后为 {@code -1}
         * @throws IOException         底层读写失败
         * @throws ImageCryptException 明文长度与实际不符
         */
        private int readTag(final byte[] target, final int offset, final int length)
                throws IOException, ImageCryptException {
            if (tag == null) {
                tag = completeAuthTag();
            }
            if (tagCursor >= tag.length) {
                return -1;
            }
            int count = Math.min(length, tag.length - tagCursor);
            System.arraycopy(tag, tagCursor, target, offset, count);
            tagCursor += count;
            return count;
        }

        /**
         * 加密下一块明文并累积 MAC。
         *
         * @throws IOException         底层读取失败
         * @throws ImageCryptException 明文短于声明长度
         */
        private void fillCipherBuffer() throws IOException, ImageCryptException {
            int want = (int) Math.min((long) IO_BUFFER_BYTES, remainingPlain);
            int cursor = 0;
            while (cursor < want) {
                int count = plaintext.read(plainBuffer, cursor, want - cursor);
                if (count < 0) {
                    throw new ImageCryptException(ErrorKind.INVALID_HEADER,
                            "输入图片短于声明长度，可能正在被其它程序改写");
                }
                cursor += count;
            }
            cipher.process(cipherBuffer, plainBuffer, want);
            mac.update(cipherBuffer, want);
            remainingPlain -= want;
            bufferCursor = 0;
            bufferCount = want;
            processed += want;
            listener.onBytes(processed, totalPlainLength);
        }

        /**
         * 完成认证标签计算。
         *
         * @return 64 字节认证标签
         * @throws IOException         底层读取失败
         * @throws ImageCryptException 明文来源包含超出声明长度的额外字节
         */
        private byte[] completeAuthTag() throws IOException, ImageCryptException {
            if (plaintext.read() >= 0) {
                throw new ImageCryptException(ErrorKind.INVALID_HEADER,
                        "输入图片在加密过程中长度发生变化，已中止以避免产出无法恢复的产物");
            }
            return mac.doFinal();
        }

        /**
         * 释放 MAC 的密钥材料并清零明文缓冲。
         *
         * @throws IOException 恒不抛出
         */
        @Override
        public void close() throws IOException {
            mac.close();
            SecureZero.zeroAll(plainBuffer, cipherBuffer);
            if (tag != null) {
                SecureZero.zero(tag);
            }
        }
    }

    /**
     * 解密侧的协议帧接收器：把 PNG 逻辑帧的字节流当作写入口。
     *
     * <p>状态机按外层协议头 → 密文 → 认证标签推进，因此允许上游以任意粒度切分（PNG 扫描线
     * 可能窄到几个字节，把协议头拦腰截断）。只有完整标签通过后，临时文件才被视为可用；
     * 在此之前所有明文都停留在临时文件里，不会出现在目标位置。
     *
     * @author ErgouTree
     * @since 2026/9/16
     */
    private static final class DecryptingFrameSink extends OutputStream {

        /**
         * 规范化密码字节；公开恢复模式为 {@code null}。
         */
        private final byte[] password;

        /**
         * 恢复目录。
         */
        private final Path outputDirectory;

        /**
         * 明文临时文件；校验模式为 {@code null}。
         */
        private final Path tempFile;

        /**
         * 是否允许覆盖同名恢复产物。
         */
        private final boolean overwriteExisting;

        /**
         * 是否产出恢复文件；false 表示只做认证校验。
         */
        private final boolean produceOutput;

        /** 是否允许提交认证失败的尽力恢复结果。 */
        private final boolean bestEffort;

        /**
         * 进度与取消回调。
         */
        private final ImageCryptProgress listener;

        /**
         * OuterHeader 缓冲。
         */
        private final byte[] headerBuffer = new byte[ImageCryptProtocol.OUTER_HEADER_LENGTH];

        /**
         * 已收到的协议头字节数。
         */
        private int headerCount;

        /**
         * 解析出的外层协议头。
         */
        private ImageCryptFrame frame;

        /**
         * 密钥编排。
         */
        private ImageKeySchedule keys;

        /**
         * XChaCha20 实例。
         */
        private XChaCha20 cipher;

        /**
         * 认证标签累积器。
         */
        private Mac mac;

        /**
         * 尚未消费的密文字节数。
         */
        private long payloadRemaining;

        /**
         * 认证标签缓冲。
         */
        private final byte[] tagBuffer = new byte[ImageCryptProtocol.AUTH_TAG_LENGTH];

        /**
         * 已收到的认证标签字节数。
         */
        private int tagCount;

        /**
         * 明文分块缓冲。
         */
        private final byte[] plainScratch = new byte[IO_BUFFER_BYTES];

        /**
         * 密文分块缓冲。
         */
        private final byte[] cipherScratch = new byte[IO_BUFFER_BYTES];

        /**
         * 清单描述区缓冲。按协议上限一次性分配，避免依赖文件内声明的长度分配内存。
         */
        private final byte[] descriptorBuffer = new byte[ImageCryptProtocol.LIMIT_MANIFEST_BYTES];

        /**
         * 已累积的描述区字节数。
         */
        private int descriptorCount;

        /**
         * 清单声明的描述区长度；{@code -1} 表示尚未读到该字段。
         */
        private int descriptorLength = -1;

        /**
         * 解析出的内层清单。
         */
        private InnerManifest manifest;

        /**
         * 恢复文件输出流；校验模式为 {@code null}。
         */
        private OutputStream payloadOutput;

        /**
         * 已写出的原文件字节数。
         */
        private long payloadBytes;

        /**
         * 恢复目标路径，解析出清单后确定。
         */
        private Path targetPath;

        /**
         * 是否已经提交到目标位置。
         */
        private boolean committed;

        /**
         * 是否已经释放。
         */
        private boolean closed;

        /**
         * 单字节写缓冲。
         */
        private final byte[] singleByte = new byte[1];

        /**
         * 创建解密侧接收器。
         *
         * @param password          规范化密码字节
         * @param outputDirectory   恢复目录
         * @param tempFile          明文临时文件；校验模式传 {@code null}
         * @param overwriteExisting 是否允许覆盖同名恢复产物
         * @param produceOutput     是否产出恢复文件
         * @param bestEffort       是否允许有损尽力恢复
         * @param listener          进度与取消回调
         */
        private DecryptingFrameSink(final byte[] password, final Path outputDirectory,
                                    final Path tempFile, final boolean overwriteExisting,
                                    final boolean produceOutput, final boolean bestEffort,
                                    final ImageCryptProgress listener) {
            this.password = password;
            this.outputDirectory = outputDirectory;
            this.tempFile = tempFile;
            this.overwriteExisting = overwriteExisting;
            this.produceOutput = produceOutput;
            this.bestEffort = bestEffort;
            this.listener = listener;
        }

        /**
         * 写入一个协议帧字节。
         *
         * @param value 字节值
         * @throws IOException 底层写入失败、协议错误或用户取消
         */
        @Override
        public void write(final int value) throws IOException {
            singleByte[0] = (byte) value;
            write(singleByte, 0, 1);
        }

        /**
         * 写入一段协议帧字节。
         *
         * @param data   数据
         * @param offset 起始偏移
         * @param length 长度
         * @throws IOException 底层写入失败、协议错误或用户取消
         */
        @Override
        public void write(final byte[] data, final int offset, final int length)
                throws IOException {
            Objects.requireNonNull(data, "data");
            if (offset < 0 || length < 0 || offset > data.length - length) {
                throw new IndexOutOfBoundsException("协议帧写入缓冲区段越界");
            }
            if (length == 0) {
                return;
            }
            try {
                int cursor = offset;
                int end = offset + length;
                while (cursor < end) {
                    if (listener.isCancelled()) {
                        throw new CancelledException("图片还原已取消");
                    }
                    if (headerCount < headerBuffer.length) {
                        int count = Math.min(end - cursor, headerBuffer.length - headerCount);
                        System.arraycopy(data, cursor, headerBuffer, headerCount, count);
                        headerCount += count;
                        cursor += count;
                        if (headerCount == headerBuffer.length) {
                            initializeFrame();
                        }
                        continue;
                    }
                    if (payloadRemaining > 0) {
                        int count = (int) Math.min((long) (end - cursor), payloadRemaining);
                        consumeCiphertext(data, cursor, count);
                        cursor += count;
                        continue;
                    }
                    if (tagCount < tagBuffer.length) {
                        int count = Math.min(end - cursor, tagBuffer.length - tagCount);
                        System.arraycopy(data, cursor, tagBuffer, tagCount, count);
                        tagCount += count;
                        cursor += count;
                        if (tagCount == tagBuffer.length) {
                            finishAuthentication();
                        }
                        continue;
                    }
                    throw new ImageCryptException(ErrorKind.INVALID_HEADER,
                            "PNG 逻辑帧包含超出协议帧长度的额外字节");
                }
            } catch (CryptoException e) {
                throw new LogicalStreamException(e);
            }
        }

        /**
         * 在协议头收齐后建立密钥编排并校验 keyConfirm。
         *
         * <p>keyConfirm 覆盖除 headerCrc32 外的全部头字段，因此篡改 protectionMode、KDF 参数
         * 或算法 ID 都无法伪造通过；同时它让密码模式在读取大载荷前就能区分"密码错误"与
         * "载荷损坏"。最终判定仍以完整认证标签为准。
         *
         * @throws IOException         底层读取失败
         * @throws ImageCryptException 头字段非法、缺少密码、密码错误或头部被篡改
         */
        private void initializeFrame() throws IOException, ImageCryptException {
            frame = ImageCryptFrame.fromBytes(headerBuffer);
            boolean passwordMode = frame.protectionMode() == ImageCryptMode.PASSWORD;
            if (passwordMode && (password == null || password.length == 0)) {
                throw new ImageCryptException(ErrorKind.INTERNAL_ERROR,
                        "该文件受密码保护，必须提供密码后才能还原");
            }
            listener.onPhase(ImageCryptPhase.KDF);
            keys = passwordMode
                    ? ImageKeySchedule.fromPassword(password, frame.argon2Salt(), frame.hkdfSalt(),
                    passListener(listener))
                    : ImageKeySchedule.fromPublicMasterKey(frame.embeddedMasterKey(),
                    frame.hkdfSalt());
            if (!keys.verifyKeyConfirm(frame.keyConfirmPrefixBytes(), frame.keyConfirm())) {
                throw new ImageCryptException(
                        passwordMode ? ErrorKind.WRONG_PASSWORD : ErrorKind.TAMPERED_DATA,
                        passwordMode ? "密码错误或协议头已被修改"
                                : "公开恢复模式的协议头完整性校验失败");
            }
            cipher = new XChaCha20(keys.encKey(), frame.nonce());
            mac = keys.beginAuthTag(frame.authenticationPrefixBytes(), frame.ciphertextLength());
            payloadRemaining = frame.ciphertextLength();
            listener.onPhase(ImageCryptPhase.PNG_READING);
        }

        /**
         * 解密一段密文并转发明文。
         *
         * @param data   密文数据
         * @param offset 起始偏移
         * @param length 长度
         * @throws IOException         底层写入失败
         * @throws ImageCryptException 内层清单非法
         */
        private void consumeCiphertext(final byte[] data, final int offset, final int length)
                throws IOException, ImageCryptException {
            int cursor = offset;
            int remaining = length;
            while (remaining > 0) {
                int count = Math.min(remaining, cipherScratch.length);
                System.arraycopy(data, cursor, cipherScratch, 0, count);
                cipher.process(plainScratch, cipherScratch, count);
                mac.update(cipherScratch, count);
                routePlaintext(plainScratch, 0, count);
                cursor += count;
                remaining -= count;
                payloadRemaining -= count;
                listener.onBytes(frame.ciphertextLength() - payloadRemaining,
                        frame.ciphertextLength());
            }
        }

        /**
         * 把明文分流到清单描述区与原文件临时文件。
         *
         * <p>描述区长度由清单自身在偏移 12 处声明，因此先按协议上限收够 16 字节读出该字段，
         * 再按声明长度收齐描述区并解析；解析成功后，同一块里越界的尾部字节属于原文件载荷，
         * 必须补写到临时文件而不能丢弃。
         *
         * @param data   明文数据
         * @param offset 起始偏移
         * @param length 长度
         * @throws IOException         底层写入失败
         * @throws ImageCryptException 清单长度越界、清单非法或载荷超长
         */
        private void routePlaintext(final byte[] data, final int offset, final int length)
                throws IOException, ImageCryptException {
            int cursor = offset;
            int end = offset + length;

            if (manifest == null) {
                int allowed = descriptorLength > 0 ? descriptorLength : descriptorBuffer.length;
                int count = Math.min(end - cursor, allowed - descriptorCount);
                if (count > 0) {
                    System.arraycopy(data, cursor, descriptorBuffer, descriptorCount, count);
                    descriptorCount += count;
                    cursor += count;
                }
                if (descriptorLength < 0 && descriptorCount >= MANIFEST_LENGTH_FIELD_END) {
                    descriptorLength = readDeclaredDescriptorLength();
                }
                if (descriptorLength > 0 && descriptorCount >= descriptorLength) {
                    adoptManifest();
                }
            }

            if (manifest != null && cursor < end) {
                int count = end - cursor;
                if (payloadOutput != null) {
                    payloadOutput.write(data, cursor, count);
                }
                payloadBytes += count;
                if (payloadBytes > manifest.originalFileLength()) {
                    throw new ImageCryptException(ErrorKind.INVALID_HEADER,
                            "封装区中的原文件字节数超过清单声明的长度");
                }
            }
        }

        /**
         * 读取清单声明的描述区长度并做范围校验。
         *
         * @return 描述区长度
         * @throws ImageCryptException 长度低于固定描述区或超过 64 KiB 上限
         */
        private int readDeclaredDescriptorLength() throws ImageCryptException {
            long declared = ((long) (descriptorBuffer[12] & 0xff) << 24)
                    | ((long) (descriptorBuffer[13] & 0xff) << 16)
                    | ((long) (descriptorBuffer[14] & 0xff) << 8)
                    | (long) (descriptorBuffer[15] & 0xff);
            if (declared < ImageCryptProtocol.INNER_MANIFEST_FIXED_LENGTH
                    || declared > ImageCryptProtocol.LIMIT_MANIFEST_BYTES) {
                throw new ImageCryptException(ErrorKind.INVALID_HEADER,
                        "内层清单声明的描述区长度非法: " + declared);
            }
            return (int) declared;
        }

        /**
         * 解析清单描述区并据此确定恢复目标。
         *
         * @throws IOException         打开临时文件失败
         * @throws ImageCryptException 清单非法、长度与协议头矛盾或目标已存在
         */
        private void adoptManifest() throws IOException, ImageCryptException {
            int overflow = descriptorCount - descriptorLength;
            manifest = InnerManifest.fromBytes(
                    Arrays.copyOf(descriptorBuffer, descriptorLength));
            descriptorCount = descriptorLength;
            if (manifest.totalLength() != frame.innerPlainLength()) {
                throw new ImageCryptException(ErrorKind.INVALID_HEADER,
                        "内层清单长度与协议头声明的封装区长度不一致");
            }
            if (produceOutput) {
                resolveTarget();
                payloadOutput = Files.newOutputStream(tempFile, StandardOpenOption.WRITE,
                        StandardOpenOption.TRUNCATE_EXISTING);
            }
            if (overflow > 0) {
                if (payloadOutput != null) {
                    payloadOutput.write(descriptorBuffer, descriptorLength, overflow);
                }
                payloadBytes += overflow;
            }
        }

        /**
         * 依清单确定恢复目标名并做覆盖判定。
         *
         * @throws ImageCryptException 目标名非法、目标是目录或已存在且不允许覆盖
         */
        private void resolveTarget() throws ImageCryptException {
            String extension = manifest.extension().isEmpty()
                    ? manifest.format().defaultExtension() : manifest.extension();
            String name = OutputNaming.imageRestoredOutputName(manifest.safeBasename(), extension);
            Path candidate = outputDirectory.resolve(name).toAbsolutePath().normalize();
            if (!candidate.getParent().equals(outputDirectory)) {
                throw new ImageCryptException(ErrorKind.INVALID_HEADER,
                        "清单文件名试图写出目标目录，已拒绝");
            }
            if (Files.isDirectory(candidate)) {
                throw new ImageCryptException(ErrorKind.FILE_EXISTS, "恢复目标是一个目录: " + name);
            }
            if (!overwriteExisting && Files.exists(candidate)) {
                throw new ImageCryptException(ErrorKind.FILE_EXISTS, "目标文件已存在: " + name);
            }
            targetPath = candidate;
        }

        /**
         * 收齐认证标签后完成最终校验。
         *
         * @throws IOException         刷新临时文件失败
         * @throws ImageCryptException 载荷长度不自洽或认证失败
         */
        private void finishAuthentication() throws IOException, ImageCryptException {
            listener.onPhase(ImageCryptPhase.MAC_VERIFY);
            if (payloadRemaining != 0) {
                throw new ImageCryptException(ErrorKind.INVALID_HEADER,
                        "PNG 逻辑帧在密文结束前进入认证标签区");
            }
            if (manifest == null) {
                throw new ImageCryptException(ErrorKind.INVALID_HEADER,
                        "封装区过短，未包含完整的内层清单");
            }
            if (payloadBytes != manifest.originalFileLength()) {
                throw new ImageCryptException(ErrorKind.INVALID_HEADER,
                        "封装区中的原文件字节数与清单声明不一致");
            }
            byte[] computed = mac.doFinal();
            boolean verified;
            try {
                verified = ImageKeySchedule.verifyAuthTag(computed, tagBuffer);
            } finally {
                SecureZero.zero(computed);
            }
            if (!verified) {
                if (!bestEffort || !produceOutput) {
                    throw new ImageCryptException(ErrorKind.TAMPERED_DATA,
                            "认证标签校验失败: 文件已损坏、被修改或不是原始产物");
                }
                LogService.warn(LOG_CATEGORY,
                        "尽力恢复已忽略认证失败，输出图片可能包含局部损坏");
            }
            if (payloadOutput != null) {
                payloadOutput.flush();
                payloadOutput.close();
                payloadOutput = null;
            }
        }

        /**
         * 返回恢复目标路径。
         *
         * @return 目标路径
         * @throws ImageCryptException 尚未解析出清单
         */
        private Path targetPath() throws ImageCryptException {
            if (targetPath == null) {
                throw new ImageCryptException(ErrorKind.INTERNAL_ERROR, "尚未解析出恢复目标路径");
            }
            return targetPath;
        }

        /**
         * 标记临时文件已经提交，使其不再被清理。
         */
        private void markCommitted() {
            committed = true;
        }

        /**
         * 释放密钥材料并清理未提交的临时文件，失败只记录日志。
         */
        private void closeQuietly() {
            if (closed) {
                return;
            }
            closed = true;
            if (payloadOutput != null) {
                try {
                    payloadOutput.close();
                } catch (IOException e) {
                    LogService.trace(LOG_CATEGORY, "临时文件关闭失败: " + e.getMessage());
                }
                payloadOutput = null;
            }
            if (keys != null) {
                keys.close();
            }
            SecureZero.zeroAll(headerBuffer, tagBuffer, plainScratch, cipherScratch,
                    descriptorBuffer);
            if (!committed) {
                deleteQuietly(tempFile, "图片还原未通过校验或已取消，已清理临时文件");
            }
        }
    }
}
