package hbnu.project.ergoutreecrypt.filetypes;

import hbnu.project.ergoutreecrypt.encoding.RsCodecs;
import hbnu.project.ergoutreecrypt.exception.ErrorKind;
import hbnu.project.ergoutreecrypt.filestego.CarrierBootstrap;
import hbnu.project.ergoutreecrypt.filestego.carrier.spi.CarrierAdapter;
import hbnu.project.ergoutreecrypt.filestego.carrier.spi.CarrierRegistry;
import hbnu.project.ergoutreecrypt.fileops.ArchiveExtractor;
import hbnu.project.ergoutreecrypt.fileops.Splitter;
import hbnu.project.ergoutreecrypt.header.HeaderReader;
import hbnu.project.ergoutreecrypt.i18n.Messages;
import hbnu.project.ergoutreecrypt.log.LogService;
import hbnu.project.ergoutreecrypt.mediacrypt.MediaCryptCodec;
import hbnu.project.ergoutreecrypt.mediacrypt.MediaCryptProfile;
import hbnu.project.ergoutreecrypt.mediacrypt.MediaFormat;
import hbnu.project.ergoutreecrypt.mediacrypt.MediaMetadata;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Locale;
import java.util.Optional;

/**
 * 「启动前拦截 + 提示引导」的文件类型护栏。
 *
 * <p>在用户点击「加密 / 解密 / 隐藏 / 提取 / 校验」的那一刻，按「当前功能 + 当前选项」
 * 对所选输入做一次<b>只读探测</b>，判断这份文件是否该由当前功能处理；不合规则立即拒绝，
 * 并给出「该去哪个功能 / 勾选哪个选项」的指引文案，而不是让核心跑到一半再抛出泛化失败。
 *
 * <p>设计要点：
 * <ul>
 *   <li><b>只读</b>：仅按扩展名、魔数、卷头 version 等轻量探测，绝不修改、不派生密钥；</li>
 *   <li><b>不抛异常</b>：任何探测失败都回退为「保守拒绝 + 兜底文案」，避免预检自身崩掉 UI；</li>
 *   <li><b>两端共用</b>：位于共享核心，桌面端与移动端（含 {@code mediaMode} /
 *       {@code mediaDecryptMode} 开关）调用同一套判定，保证行为一致。</li>
 * </ul>
 *
 * <p>拒绝结果里的 {@link GuardResult#guardKey()} 是 i18n key，界面直接
 * {@code Messages.format(key, args)} 即可得到面向用户的引导文案；{@link GuardResult#kind()}
 * 则给出对应的 {@link ErrorKind}，供需要按类型分支的调用方使用。
 *
 * <p>本类<b>不</b>负责 {@code IMAGE_STEGO_*} 的容量探测：图像隐写依赖 {@code java.awt}，
 * 该子系统在移动端被构建脚本排除，故此处只做扩展名护栏，容量与魔数判定仍由桌面端
 * 控制器与 {@code stego} 子系统自行完成。
 *
 * @author ErgouTree
 * @since 2026/9/14
 */
public final class FileInputGuard {

    /**
     * 引导文案：不是本工具加密的文件（可能是压缩包，需勾选解压后解密）。
     */
    public static final String GUARD_NOT_ENCRYPTED = "guard.redirect.notEncrypted";

    /**
     * 引导文案：这是格式保持加密的媒体文件，应到音视频页解密还原。
     */
    public static final String GUARD_FPE_DECRYPT = "guard.redirect.fpeDecrypt";

    /**
     * 引导文案：这是格式保持加密的媒体文件，应到音视频页校验完整性。
     */
    public static final String GUARD_FPE_VERIFY = "guard.redirect.fpeVerify";

    /**
     * 引导文案：这是隐写载体，应到隐写页提取。
     */
    public static final String GUARD_STEGO_EXTRACT = "guard.redirect.stegoExtract";

    /**
     * 引导文案：该媒体文件需切换到格式保持解密开关。
     */
    public static final String GUARD_MEDIA_DECRYPT = "guard.redirect.mediaDecrypt";

    /**
     * 引导文案：该文件未存储完整性校验数据。
     */
    public static final String GUARD_INTEGRITY_MISSING = "guard.redirect.integrityMissing";

    /**
     * 引导文案：不支持的载体格式（参数为扩展名）。
     */
    public static final String GUARD_UNSUPPORTED_CARRIER = "guard.redirect.unsupportedCarrier";

    /**
     * 引导文案：该功能仅支持单个文件，不支持文件夹。
     */
    public static final String GUARD_REQUIRE_FILE = "guard.requireFile";

    /**
     * 引导文案：图像隐写的容器必须是 PNG。
     */
    public static final String GUARD_REQUIRE_PNG = "guard.requirePng";

    /**
     * 引导文案：所选加密档位与文件格式不匹配（参数依次为档位描述与格式名）。
     */
    public static final String GUARD_PROFILE_MISMATCH = "guard.mediaProfileMismatch";

    /**
     * 复用文案：不支持的音视频格式。
     */
    public static final String KEY_AV_UNSUPPORTED = "av.toast.unsupported";

    /**
     * 复用文案：该媒体文件未检测到本工具加密元数据。
     */
    public static final String KEY_AV_NOT_ENCRYPTED = "av.error.notEncrypted";

    /**
     * 复用文案：该文件未存储完整性校验数据。
     */
    public static final String KEY_AV_NO_INTEGRITY = "av.status.failed.verify.noIntegrity";

    /**
     * 复用文案：不支持的载体格式（参数为扩展名）。
     */
    public static final String KEY_STEGO_INVALID_CARRIER = "fileStego.toast.invalid.carrier";

    /**
     * 复用文案：载体容量不足（参数为需要量与可用量）。
     */
    public static final String KEY_STEGO_CAPACITY = "fileStego.toast.capacity.exceeded";

    /**
     * 复用文案：未检测到可识别的隐写数据。
     */
    public static final String KEY_STEGO_DETECT_FAILED = "fileStego.detect.failed";

    /**
     * 复用文案：文件不存在或已被移动。
     */
    public static final String KEY_NOT_FOUND = "error.notFound";

    /**
     * 复用文案：不支持的文件格式。
     */
    public static final String KEY_UNSUPPORTED_FORMAT = "error.unsupportedFormat";

    /**
     * 通用文件加密/解密的最小版本探测用密码学组件集合。
     */
    private static final RsCodecs RS_CODECS = new RsCodecs();

    /**
     * 扩展名不匹配载体格式时，仍做一次隐写魔数探测的文件大小上限（64 MiB）。
     *
     * <p>与 {@code FileStegoCodec} 的只读预检上限一致：超过该大小的非载体扩展名文件
     * 一律不做魔数探测，避免整文件读取带来的内存与耗时开销。
     */
    private static final long CARRIER_PROBE_MAX_BYTES = 64L << 20;

    private FileInputGuard() {
    }

    /**
     * 需要预检的功能入口。
     */
    public enum Feature {

        /**
         * 通用文件加密（任意文件 / 文件夹 / 多文件）。
         */
        GENERIC_ENCRYPT,

        /**
         * 通用文件解密（.ergou / .pcv / 分卷碎片 / 加密归档）。
         */
        GENERIC_DECRYPT,

        /**
         * 通用卷完整性校验。
         */
        VERIFY_INTEGRITY,

        /**
         * 音视频格式保持加密。
         */
        FPE_ENCRYPT,

        /**
         * 音视频格式保持解密。
         */
        FPE_DECRYPT,

        /**
         * 音视频完整性校验。
         */
        MEDIA_VERIFY,

        /**
         * 图像隐写：隐藏（容器必须为 PNG）。
         */
        IMAGE_STEGO_HIDE,

        /**
         * 图像隐写：提取（容器必须为 PNG）。
         */
        IMAGE_STEGO_EXTRACT,

        /**
         * 文件隐写：隐藏（载体须为受支持格式）。
         */
        FILE_STEGO_HIDE,

        /**
         * 文件隐写：提取（载体须含隐写数据）。
         */
        FILE_STEGO_EXTRACT
    }

    /**
     * 预检选项：只包含「会改变可接受输入类型」的开关。
     *
     * <p>与输入类型无关的选项（偏执、Reed-Solomon、加密前/后压缩、分卷、加密深度、
     * 备注、KDF 档位等）已逐项梳理过，不影响判定结果，故不在此列出。
     *
     * @param autoUnzip           通用解密：解压后解密，放行明文压缩包
     * @param decryptThenExtract  通用解密：解密后解压，其目标输入（加密归档）已由卷规则覆盖，
     *                            因此不单独放行明文压缩包
     * @param mediaDecompressFirst 音视频解密：解压后解密，放行含媒体的归档
     * @param mediaNoiseCheck     音视频解密：噪音文件解密，要求文件确实含加密元数据
     * @param mediaProfile        音视频加密：所选档位，null 表示自动
     * @param secretSizeBytes     文件隐写隐藏：待隐藏文件大小，未知时为 {@link #UNKNOWN_SIZE}
     */
    public record Options(boolean autoUnzip,
                          boolean decryptThenExtract,
                          boolean mediaDecompressFirst,
                          boolean mediaNoiseCheck,
                          MediaCryptProfile mediaProfile,
                          long secretSizeBytes) {

        /**
         * 未知待隐藏文件大小的哨兵值。
         */
        public static final long UNKNOWN_SIZE = -1L;

        /**
         * 返回全默认选项（所有开关关闭、档位自动、待隐藏大小未知）。
         *
         * @return 默认选项
         */
        public static Options none() {
            return builder().build();
        }

        /**
         * 创建选项构造器。
         *
         * @return 构造器
         */
        public static Builder builder() {
            return new Builder();
        }

        /**
         * {@link Options} 的链式构造器。
         */
        public static final class Builder {

            /**
             * 解压后解密。
             */
            private boolean autoUnzip;

            /**
             * 解密后解压。
             */
            private boolean decryptThenExtract;

            /**
             * 音视频：解压后解密。
             */
            private boolean mediaDecompressFirst;

            /**
             * 音视频：噪音文件解密（要求含元数据）。
             */
            private boolean mediaNoiseCheck;

            /**
             * 音视频加密档位，null 表示自动。
             */
            private MediaCryptProfile mediaProfile;

            /**
             * 待隐藏文件大小，未知时为 {@link #UNKNOWN_SIZE}。
             */
            private long secretSizeBytes = UNKNOWN_SIZE;

            private Builder() {
            }

            /**
             * @param value 解压后解密
             * @return 本构造器
             */
            public Builder autoUnzip(final boolean value) {
                this.autoUnzip = value;
                return this;
            }

            /**
             * @param value 解密后解压
             * @return 本构造器
             */
            public Builder decryptThenExtract(final boolean value) {
                this.decryptThenExtract = value;
                return this;
            }

            /**
             * @param value 音视频：解压后解密
             * @return 本构造器
             */
            public Builder mediaDecompressFirst(final boolean value) {
                this.mediaDecompressFirst = value;
                return this;
            }

            /**
             * @param value 音视频：噪音文件解密
             * @return 本构造器
             */
            public Builder mediaNoiseCheck(final boolean value) {
                this.mediaNoiseCheck = value;
                return this;
            }

            /**
             * @param value 音视频加密档位，null 表示自动
             * @return 本构造器
             */
            public Builder mediaProfile(final MediaCryptProfile value) {
                this.mediaProfile = value;
                return this;
            }

            /**
             * @param value 待隐藏文件大小（字节），未知时传 {@link #UNKNOWN_SIZE}
             * @return 本构造器
             */
            public Builder secretSizeBytes(final long value) {
                this.secretSizeBytes = value;
                return this;
            }

            /**
             * @return 构造完成的选项
             */
            public Options build() {
                return new Options(autoUnzip, decryptThenExtract, mediaDecompressFirst,
                        mediaNoiseCheck, mediaProfile, secretSizeBytes);
            }
        }
    }

    /**
     * 预检结果。
     *
     * @param accepted 是否放行
     * @param kind     拒绝时的错误分类；放行时为 {@code null}
     * @param guardKey 拒绝时的 i18n key；放行时为 {@code null}
     * @param args     拒绝时文案的格式化参数，可为 {@code null}
     */
    public record GuardResult(boolean accepted, ErrorKind kind, String guardKey, Object[] args) {

        /**
         * 放行结果。
         *
         * @return 放行
         */
        public static GuardResult accept() {
            return new GuardResult(true, null, null, null);
        }

        /**
         * 拒绝结果。
         *
         * @param kind     错误分类
         * @param guardKey 引导文案的 i18n key
         * @param args     文案格式化参数
         * @return 拒绝
         */
        public static GuardResult reject(final ErrorKind kind, final String guardKey,
                                         final Object... args) {
            return new GuardResult(false, kind, guardKey, args);
        }

        /**
         * 是否被拒绝。
         *
         * @return true 表示应中止启动并提示
         */
        public boolean rejected() {
            return !accepted;
        }

        /**
         * 返回可直接展示给用户的引导文案（按当前语言解析）。
         *
         * @return 放行时返回空串；拒绝时返回已解析的文案
         */
        public String message() {
            if (accepted || guardKey == null) {
                return "";
            }
            if (args == null || args.length == 0) {
                return Messages.get(guardKey);
            }
            return Messages.format(guardKey, args);
        }
    }

    /**
     * 按「功能 + 选项」校验输入文件。
     *
     * <p>只读探测，不修改文件；任何内部异常都回退为保守拒绝，绝不抛出。
     *
     * @param feature 当前功能
     * @param options 当前选项，可为 {@code null}（等价于全默认）
     * @param input   所选输入路径，可为 {@code null}
     * @return 预检结果，恒非 {@code null}
     */
    public static GuardResult check(final Feature feature, final Options options, final Path input) {
        if (feature == null) {
            return GuardResult.accept();
        }
        Options opts = options == null ? Options.none() : options;
        try {
            return doCheck(feature, opts, input);
        } catch (Throwable t) {
            LogService.warn("FileInputGuard", "预检探测失败，按保守策略拒绝: "
                    + (input == null ? "<null>" : input.getFileName()) + " - " + t);
            return GuardResult.reject(ErrorKind.IO_ERROR, KEY_UNSUPPORTED_FORMAT);
        }
    }

    /**
     * 执行实际判定（调用方已保证参数非空并处理兜底）。
     *
     * @param feature 功能
     * @param opts    选项
     * @param input   输入路径
     * @return 预检结果
     */
    private static GuardResult doCheck(final Feature feature, final Options opts, final Path input) {
        if (input == null || !Files.exists(input)) {
            return GuardResult.reject(ErrorKind.INPUT_NOT_FOUND, KEY_NOT_FOUND);
        }
        boolean directory = Files.isDirectory(input);
        return switch (feature) {
            case GENERIC_ENCRYPT -> GuardResult.accept();
            case GENERIC_DECRYPT -> checkGenericDecrypt(input, directory, opts);
            case VERIFY_INTEGRITY -> checkVerify(input, directory);
            case FPE_ENCRYPT -> checkFpeEncrypt(input, directory, opts);
            case FPE_DECRYPT -> checkFpeDecrypt(input, directory, opts);
            case MEDIA_VERIFY -> checkMediaVerify(input, directory);
            case IMAGE_STEGO_HIDE, IMAGE_STEGO_EXTRACT -> checkImageStego(input, directory);
            case FILE_STEGO_HIDE -> checkFileStegoHide(input, directory, opts);
            case FILE_STEGO_EXTRACT -> checkFileStegoExtract(input, directory);
        };
    }

    /**
     * 通用解密：分卷碎片 / 加密卷 / 加密归档放行，媒体密文与隐写载体引导去对应功能。
     *
     * @param input     输入路径
     * @param directory 输入是否为目录
     * @param opts      选项（是否勾选解压后解密）
     * @return 预检结果
     */
    private static GuardResult checkGenericDecrypt(final Path input, final boolean directory,
                                                   final Options opts) {
        // 1. 文件夹：可能包含加密文件，交由 FolderCrypt 自动识别
        if (directory) {
            return GuardResult.accept();
        }
        // 2. 分卷碎片：走合并分卷
        if (Splitter.isSplitChunkPath(input.toString())) {
            return GuardResult.accept();
        }
        // 3. 媒体密文：.enc.<mediaExt> 形态或含本工具媒体元数据 → 引导去音视频页解密
        if (looksLikeFpeCiphertext(input)) {
            return GuardResult.reject(ErrorKind.UNSUPPORTED_FORMAT, GUARD_FPE_DECRYPT);
        }
        // 4. 隐写载体：含隐写魔数（普通 PNG/ZIP 不会命中）→ 引导去隐写页提取
        if (detectCarrier(input)) {
            return GuardResult.reject(ErrorKind.UNSUPPORTED_FORMAT, GUARD_STEGO_EXTRACT);
        }
        // 5. 通用加密卷：按扩展名或卷头 version 判定（须在媒体扩展名判断之前，
        //    否则被改名的加密卷会被误判成"普通媒体文件"）
        if (isGenericVolume(input)) {
            return GuardResult.accept();
        }
        // 6. 普通媒体文件：通用解密无能为力，引导切换到「格式保持解密」
        if (MediaFormat.fromExtension(input) != null) {
            return GuardResult.reject(ErrorKind.UNSUPPORTED_FORMAT, GUARD_MEDIA_DECRYPT);
        }
        // 7. 明文压缩包：仅在勾选「解压后解密」时放行。
        // 注意「解密后解压」针对的是加密归档（x.zip.ergou，已在第 5 步放行），
        // 单独勾选它并不能让明文压缩包变得可解密，故不作放行条件。
        if (ArchiveExtractor.isArchive(input)) {
            if (opts.autoUnzip()) {
                return GuardResult.accept();
            }
            return GuardResult.reject(ErrorKind.UNSUPPORTED_FORMAT, GUARD_NOT_ENCRYPTED);
        }
        // 8. 其余：不是本工具加密的文件
        return GuardResult.reject(ErrorKind.UNSUPPORTED_FORMAT, GUARD_NOT_ENCRYPTED);
    }

    /**
     * 通用卷完整性校验：仅接受单文件加密卷或分卷碎片。
     *
     * @param input     输入路径
     * @param directory 输入是否为目录
     * @return 预检结果
     */
    private static GuardResult checkVerify(final Path input, final boolean directory) {
        if (directory) {
            return GuardResult.reject(ErrorKind.UNSUPPORTED_FORMAT, GUARD_REQUIRE_FILE);
        }
        if (Splitter.isSplitChunkPath(input.toString())) {
            return GuardResult.accept();
        }
        if (looksLikeFpeCiphertext(input)) {
            return GuardResult.reject(ErrorKind.UNSUPPORTED_FORMAT, GUARD_FPE_VERIFY);
        }
        if (isGenericVolume(input)) {
            return GuardResult.accept();
        }
        return GuardResult.reject(ErrorKind.UNSUPPORTED_FORMAT, GUARD_NOT_ENCRYPTED);
    }

    /**
     * 格式保持加密：仅接受受支持媒体，且所选档位必须与该格式匹配。
     *
     * @param input     输入路径
     * @param directory 输入是否为目录
     * @param opts      选项（含所选档位）
     * @return 预检结果
     */
    private static GuardResult checkFpeEncrypt(final Path input, final boolean directory,
                                               final Options opts) {
        MediaFormat format = directory ? null : MediaFormat.fromExtension(input);
        if (format == null) {
            return GuardResult.reject(ErrorKind.UNSUPPORTED_FORMAT, KEY_AV_UNSUPPORTED);
        }
        MediaCryptProfile profile = opts.mediaProfile();
        if (profile != null && profile.format() != format) {
            return GuardResult.reject(ErrorKind.UNSUPPORTED_FORMAT, GUARD_PROFILE_MISMATCH,
                    profile.name(), format.name());
        }
        return GuardResult.accept();
    }

    /**
     * 格式保持解密：接受媒体密文（噪声媒体也可），勾选解压后解密时额外接受归档。
     *
     * @param input     输入路径
     * @param directory 输入是否为目录
     * @param opts      选项（解压后解密、噪音校验）
     * @return 预检结果
     */
    private static GuardResult checkFpeDecrypt(final Path input, final boolean directory,
                                               final Options opts) {
        if (directory) {
            return GuardResult.reject(ErrorKind.UNSUPPORTED_FORMAT, GUARD_REQUIRE_FILE);
        }
        if (opts.mediaDecompressFirst() && ArchiveExtractor.isArchive(input)) {
            return GuardResult.accept();
        }
        if (MediaFormat.fromExtension(input) == null) {
            return GuardResult.reject(ErrorKind.UNSUPPORTED_FORMAT, KEY_AV_UNSUPPORTED);
        }
        if (opts.mediaNoiseCheck() && !isMediaEncrypted(input)) {
            return GuardResult.reject(ErrorKind.INVALID_HEADER, KEY_AV_NOT_ENCRYPTED);
        }
        return GuardResult.accept();
    }

    /**
     * 音视频完整性校验：要求文件为受支持媒体且加密时存储了完整性数据。
     *
     * @param input     输入路径
     * @param directory 输入是否为目录
     * @return 预检结果
     */
    private static GuardResult checkMediaVerify(final Path input, final boolean directory) {
        if (directory || MediaFormat.fromExtension(input) == null) {
            return GuardResult.reject(ErrorKind.UNSUPPORTED_FORMAT, KEY_AV_UNSUPPORTED);
        }
        MediaMetadata meta = peekMediaMetadata(input);
        if (meta == null) {
            return GuardResult.reject(ErrorKind.INVALID_HEADER, KEY_AV_NOT_ENCRYPTED);
        }
        if (!meta.hasIntegrity()) {
            return GuardResult.reject(ErrorKind.INVALID_HEADER, GUARD_INTEGRITY_MISSING);
        }
        return GuardResult.accept();
    }

    /**
     * 图像隐写：容器必须是 PNG 图片。
     *
     * <p>容量与隐写数据存在性由 {@code stego} 子系统在桌面端判定，此处只做扩展名护栏。
     *
     * @param input     输入路径
     * @param directory 输入是否为目录
     * @return 预检结果
     */
    private static GuardResult checkImageStego(final Path input, final boolean directory) {
        if (directory || !fileName(input).toLowerCase(Locale.ROOT).endsWith(".png")) {
            return GuardResult.reject(ErrorKind.CARRIER_INVALID, GUARD_REQUIRE_PNG);
        }
        return GuardResult.accept();
    }

    /**
     * 文件隐写隐藏：载体须为受支持格式；已知待隐藏大小时顺带复核容量。
     *
     * @param input     载体路径
     * @param directory 输入是否为目录
     * @param opts      选项（含待隐藏文件大小）
     * @return 预检结果
     */
    private static GuardResult checkFileStegoHide(final Path input, final boolean directory,
                                                  final Options opts) {
        if (directory) {
            return GuardResult.reject(ErrorKind.CARRIER_INVALID, GUARD_REQUIRE_FILE);
        }
        CarrierBootstrap.ensureRegistered();
        Optional<CarrierAdapter> adapter = CarrierRegistry.findByExtension(extensionOf(input));
        if (adapter.isEmpty()) {
            return GuardResult.reject(ErrorKind.UNSUPPORTED_FORMAT, GUARD_UNSUPPORTED_CARRIER,
                    extensionOf(input));
        }
        long secretSize = opts.secretSizeBytes();
        if (secretSize >= 0) {
            long capacity;
            try {
                capacity = adapter.get().capacity(input);
            } catch (Exception e) {
                // 容量探测失败时不拦截，交由核心在写入阶段报错
                return GuardResult.accept();
            }
            if (capacity != Long.MAX_VALUE && secretSize > capacity) {
                return GuardResult.reject(ErrorKind.CAPACITY_INSUFFICIENT, KEY_STEGO_CAPACITY,
                        LogService.humanSize(secretSize), LogService.humanSize(capacity));
            }
        }
        return GuardResult.accept();
    }

    /**
     * 文件隐写提取：载体扩展名须受支持，且必须真正含隐写数据（魔数判定）。
     *
     * @param input     载体路径
     * @param directory 输入是否为目录
     * @return 预检结果
     */
    private static GuardResult checkFileStegoExtract(final Path input, final boolean directory) {
        if (directory) {
            return GuardResult.reject(ErrorKind.NO_STEGO_DATA, KEY_STEGO_DETECT_FAILED);
        }
        CarrierBootstrap.ensureRegistered();
        if (adapterRegistered(extensionOf(input)) && detectCarrier(input)) {
            return GuardResult.accept();
        }
        return GuardResult.reject(ErrorKind.NO_STEGO_DATA, KEY_STEGO_DETECT_FAILED);
    }

    /**
     * 判断输入是否为「通用加密卷」：扩展名为 .ergou/.pcv，或卷头 version 合法。
     *
     * @param input 输入路径
     * @return 判定结果
     */
    private static boolean isGenericVolume(final Path input) {
        String lower = fileName(input).toLowerCase(Locale.ROOT);
        if (lower.endsWith(OutputNaming.GENERIC_SUFFIX) || lower.endsWith(OutputNaming.LEGACY_SUFFIX)) {
            return true;
        }
        try (InputStream in = Files.newInputStream(input)) {
            return HeaderReader.looksLikeVolume(in, RS_CODECS);
        } catch (java.io.IOException e) {
            return false;
        }
    }

    /**
     * 判断输入是否像「格式保持加密」的媒体密文。
     *
     * <p>判据：文件名含 {@code .enc} 标记且扩展名是受支持媒体；或该媒体文件确实内嵌了
     * 本工具的加密元数据。
     *
     * @param input 输入路径
     * @return 判定结果
     */
    private static boolean looksLikeFpeCiphertext(final Path input) {
        String lower = fileName(input).toLowerCase(Locale.ROOT);
        if (lower.contains(OutputNaming.FPE_MARKER + ".")
                && MediaFormat.fromExtension(input) != null) {
            return true;
        }
        return MediaFormat.fromExtension(input) != null && isMediaEncrypted(input);
    }

    /**
     * 只读探测媒体文件是否含本工具加密元数据，探测失败按「不含」处理。
     *
     * @param input 输入路径
     * @return true 表示含有加密元数据
     */
    private static boolean isMediaEncrypted(final Path input) {
        try {
            return new MediaCryptCodec().isEncrypted(input);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * 只读探测媒体的内嵌元数据，探测失败返回 {@code null}。
     *
     * @param input 输入路径
     * @return 元数据或 {@code null}
     */
    private static MediaMetadata peekMediaMetadata(final Path input) {
        return new MediaCryptCodec().peekMetadata(input);
    }

    /**
     * 魔数探测输入是否含隐写数据（普通 PNG/ZIP/PDF 等不会命中）。
     *
     * <p>为避免探测本身带来风险，探测策略按"代价"分层：
     * <ul>
     *   <li>扩展名命中某个载体格式时，只探测该格式的适配器；若该适配器的 {@code detect}
     *       会整读文件（PDF/WAV/FLAC），则仅对 {@link #CARRIER_PROBE_MAX_BYTES} 以内的
     *       文件探测，超大文件交给核心在提取阶段报错；</li>
     *   <li>扩展名不匹配任何载体格式时（如被改名的载体），仅对小文件做一次全适配器
     *       的"尽力而为"扫描。</li>
     * </ul>
     * 这样既保住了"改名的隐写载体也能被识别"，又不会因为一次预检把几百 MB 的文件读进内存。
     *
     * @param input 输入路径
     * @return true 表示含隐写数据
     */
    private static boolean detectCarrier(final Path input) {
        try {
            CarrierBootstrap.ensureRegistered();
            Optional<CarrierAdapter> byExtension = CarrierRegistry.findByExtension(extensionOf(input));
            if (byExtension.isPresent()) {
                CarrierAdapter adapter = byExtension.get();
                if (!adapter.supportsStreamingExtract()
                        && !isWithinProbeLimit(input)) {
                    return false;
                }
                return adapter.detect(input);
            }
            return isWithinProbeLimit(input)
                    && CarrierRegistry.detectByMagic(input).isPresent();
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * 判断文件大小是否在只读探测上限内。
     *
     * @param input 输入路径
     * @return true 表示大小已知且不超过上限
     */
    private static boolean isWithinProbeLimit(final Path input) {
        try {
            return Files.size(input) <= CARRIER_PROBE_MAX_BYTES;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * 判断扩展名是否已注册载体适配器。
     *
     * @param extension 扩展名（含点，小写）
     * @return true 表示受支持
     */
    private static boolean adapterRegistered(final String extension) {
        return CarrierRegistry.findByExtension(extension).isPresent();
    }

    /**
     * 取文件名（含扩展名）。
     *
     * @param path 路径
     * @return 文件名
     */
    private static String fileName(final Path path) {
        return path.getFileName().toString();
    }

    /**
     * 取小写扩展名（含点前缀，无扩展名时返回空串）。
     *
     * @param path 路径
     * @return 形如 {@code .png} 的扩展名
     */
    private static String extensionOf(final Path path) {
        String name = fileName(path).toLowerCase(Locale.ROOT);
        int dot = name.lastIndexOf('.');
        return dot >= 0 ? name.substring(dot) : "";
    }
}
