package hbnu.project.ergoutreecrypt.imagecrypt.interop;

import hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptCodec;
import hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptFrame;
import hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptMetadata;
import hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptMode;
import hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptOptions;
import hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptPassword;
import hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptProgress;
import hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptProtocol;
import hbnu.project.ergoutreecrypt.imagecrypt.png.PixelPngReader;
import hbnu.project.ergoutreecrypt.log.LogService;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

/**
 * 生成 EGTC-IMG v1 跨端互操作永久语料。
 *
 * <h3>为什么是一个可执行入口而不是单元测试</h3>
 * <p>语料是<b>冻结资产</b>：一旦提交，它的字节就是协议契约的一部分，两端测试都只读取、不重写。
 * 因此生成动作必须显式、可审计、可重复，而不是"跑测试时顺手覆盖一下"。
 * 语料需要变更时，用本入口重新生成并提交 diff，让评审看到字节层面的变化。
 *
 * <h3>用法</h3>
 * <pre>
 *   mvn -q test-compile
 *   java -cp "target/classes;target/test-classes;&lt;deps&gt;" \
 *        hbnu.project.ergoutreecrypt.imagecrypt.interop.InteropCorpusGenerator \
 *        src/test/resources/imagecrypt/interop/v1
 * </pre>
 *
 * <h3>可重复性</h3>
 * <p>重新运行会<b>覆盖</b>已存在的产物：语料需要变更时这是刻意的动作，提交前请先清理目录，
 * 让 diff 只反映真正的内容变化，而不是新旧文件混杂。
 *
 * <h3>产物</h3>
 * <ul>
 *   <li>{@code corpus-input.png} / {@code corpus-input.jpg}：确定性生成的原始输入；</li>
 *   <li>{@code desktop-*.egimg.png}：桌面 JVM 生成的公开恢复与密码保护产物；</li>
 *   <li>{@code corpus.properties}：输入、密码（含 NFC/NFD 两种形态的规范化后字节）、
 *       协议中间值、恢复名与全部 SHA-256。文件以 <b>UTF-8</b> 写出，读取方必须显式指定
 *       UTF-8 —— {@code Properties.load(InputStream)} 的默认编码是 ISO-8859-1，
 *       会把组合字符口令读成乱码并让 keyConfirm 无声失败。</li>
 * </ul>
 *
 * <p>Android 侧通过 Gradle 同步任务读取同一份目录，作为 instrumentation 的 assets，
 * 因此两端看到的是<b>同一批字节</b>，不存在"两边各生成一份再互相比对"的伪互操作。
 *
 * @author ErgouTree
 * @since 2026/9/16
 */
public final class InteropCorpusGenerator {

    /**
     * 语料版本号。协议或语料结构变化时递增。
     */
    private static final int CORPUS_VERSION = 1;

    /**
     * 输入图片宽度。
     */
    private static final char LINE_FEED = 10;

    private static final int INPUT_WIDTH = 160;

    /**
     * 输入图片高度。
     */
    private static final int INPUT_HEIGHT = 120;

    /**
     * ASCII 测试口令。
     */
    private static final String ASCII_PASSWORD = "Str0ng-Pass";

    /**
     * 组合字符测试口令（NFC 形态：é 为单码点 U+00E9）。
     */
    private static final String UNICODE_PASSWORD = "café-中文";

    /**
     * 同一口令的 NFD 形态（é 拆成 e + U+0301 组合音标）。
     *
     * <p>它存在的意义是证明"密码必须经 NFC 规范化"这条约束在两端都成立：NFC 与 NFD 是同一段
     * 文本的两种合法编码，若某一端漏了归一化，两端就会派生出不同的密钥。语料里同时记下两种
     * 形态的规范化结果，两端各自断言它们相等。
     */
    private static final String UNICODE_PASSWORD_NFD =
            "café-中文";

    private InteropCorpusGenerator() {
    }

    /**
     * 生成语料。
     *
     * @param args 唯一参数：输出目录
     * @throws Exception 生成或写入失败
     */
    public static void main(final String[] args) throws Exception {
        if (args.length != 1) {
            System.err.println("用法: InteropCorpusGenerator <输出目录>");
            System.exit(2);
        }
        Path outputDirectory = Path.of(args[0]).toAbsolutePath().normalize();
        Files.createDirectories(outputDirectory);

        Path pngInput = outputDirectory.resolve("corpus-input.png");
        Path jpgInput = outputDirectory.resolve("corpus-input.jpg");
        writeImage(pngInput, "png");
        writeImage(jpgInput, "jpg");

        Properties properties = new Properties();
        properties.setProperty("corpus.version", Integer.toString(CORPUS_VERSION));
        properties.setProperty("corpus.generator", "desktop-jvm");
        properties.setProperty("corpus.jdk", System.getProperty("java.version", "unknown"));
        properties.setProperty("corpus.bouncycastle", bouncyCastleVersion());
        properties.setProperty("corpus.appVersion", "2.6.0");
        properties.setProperty("password.ascii", ASCII_PASSWORD);
        properties.setProperty("password.unicode", UNICODE_PASSWORD);
        properties.setProperty("password.unicode.nfd", UNICODE_PASSWORD_NFD);
        // 规范化后的 UTF-8 字节是 KDF 的真实输入，两端都必须导出完全相同的字节
        properties.setProperty("password.ascii.utf8Hex",
                hex(ImageCryptPassword.encodeForV1(ASCII_PASSWORD)));
        properties.setProperty("password.unicode.utf8Hex",
                hex(ImageCryptPassword.encodeForV1(UNICODE_PASSWORD)));
        properties.setProperty("password.unicode.nfdUtf8Hex",
                hex(ImageCryptPassword.encodeForV1(UNICODE_PASSWORD_NFD)));

        List<Path> inputs = new ArrayList<>();
        inputs.add(pngInput);
        inputs.add(jpgInput);
        properties.setProperty("input.count", Integer.toString(inputs.size()));
        for (int i = 0; i < inputs.size(); i++) {
            Path input = inputs.get(i);
            properties.setProperty("input." + i + ".file", input.getFileName().toString());
            properties.setProperty("input." + i + ".length",
                    Long.toString(Files.size(input)));
            properties.setProperty("input." + i + ".sha256", sha256(Files.readAllBytes(input)));
        }

        ImageCryptCodec codec = new ImageCryptCodec();
        Path scratch = Files.createDirectories(outputDirectory.resolve(".scratch"));
        int entryIndex = 0;
        for (Path input : inputs) {
            // 两条输入若只取主干会重名（corpus-input.png / corpus-input.jpg），
            // 因此标识带上扩展名，保证产物名唯一且自解释
            String stem = input.getFileName().toString().replace('.', '-');
            entryIndex = emitEntry(codec, properties, entryIndex, input, stem, "public",
                    ImageCryptMode.PUBLIC_RECOVERY, null, scratch);
            entryIndex = emitEntry(codec, properties, entryIndex, input, stem, "password-ascii",
                    ImageCryptMode.PASSWORD, "ascii", scratch);
            entryIndex = emitEntry(codec, properties, entryIndex, input, stem, "password-unicode",
                    ImageCryptMode.PASSWORD, "unicode", scratch);
        }
        properties.setProperty("entry.count", Integer.toString(entryIndex));

        writeProperties(properties, outputDirectory.resolve("corpus.properties"));
        deleteTree(scratch);

        System.out.println("已生成 " + entryIndex + " 条语料于 " + outputDirectory);
        System.out.println("输入 SHA-256:");
        for (Path input : inputs) {
            System.out.println("  " + input.getFileName() + "  "
                    + sha256(Files.readAllBytes(input)));
        }
    }

    /**
     * 以确定性格式写出语料属性表。
     *
     * <p>刻意不用 {@link Properties#store(OutputStream, String)}：它会写入当前时间戳，
     * 使每次重新生成的 diff 都包含一行无意义的噪声，掩盖真正的字节变化。这里按键名排序输出，
     * 同一份语料无论何时生成都得到逐字节相同的文本。
     *
     * @param properties 属性表
     * @param target     目标文件
     * @throws IOException 写入失败
     */
    private static void writeProperties(final Properties properties, final Path target)
            throws IOException {
        List<String> keys = new ArrayList<>(properties.stringPropertyNames());
        keys.sort(null);
        StringBuilder builder = new StringBuilder();
        builder.append("# EGTC-IMG v1 跨端互操作永久语料（由 InteropCorpusGenerator 生成）").append(LINE_FEED);
        builder.append("# 本文件是冻结资产：两端测试只读取，不重写。变更请重跑生成器并提交 diff。").append(LINE_FEED);
        for (String key : keys) {
            builder.append(key).append('=').append(properties.getProperty(key)).append(LINE_FEED);
        }
        Files.write(target, builder.toString().getBytes(StandardCharsets.UTF_8));
    }

    /**
     * 生成一条语料条目并记录其全部可观测信息。
     *
     * @param codec       图片加密门面
     * @param properties  语料属性表（原地写入）
     * @param index       条目序号
     * @param input       原始输入图片
     * @param stem        输入文件名主干（用于产物命名）
     * @param tag         条目标签（用于产物命名与检索）
     * @param mode        保护模式
     * @param passwordKey 密码在属性表中的键名；公开恢复模式传 {@code null}
     * @param scratch     还原验证用的临时目录
     * @return 下一条目序号
     * @throws Exception 加解密或写入失败
     */
    private static int emitEntry(final ImageCryptCodec codec, final Properties properties,
                                 final int index, final Path input, final String stem,
                                 final String tag, final ImageCryptMode mode,
                                 final String passwordKey, final Path scratch)
            throws Exception {
        String prefix = "entry." + index + ".";
        byte[] password = passwordKey == null
                ? null : ImageCryptPassword.encodeForV1(properties.getProperty("password." + passwordKey));
        String artifactName = "desktop-" + stem + "-" + tag + "-v1.egimg.png";
        Path artifact = input.getParent().resolve(artifactName);

        // 生成器允许覆盖：语料需要变更时显式重跑并提交 diff，是刻意的可审计动作
        codec.encrypt(input, artifact, password, ImageCryptOptions.overwriting(mode),
                ImageCryptProgress.NONE);

        ImageCryptMetadata metadata = codec.peekMetadata(artifact);
        ImageCryptFrame frame = readFrame(artifact);
        byte[] artifactBytes = Files.readAllBytes(artifact);

        Path restoreDirectory = Files.createDirectories(scratch.resolve("entry-" + index));
        Path restored = codec.decrypt(artifact, restoreDirectory, password, true,
                ImageCryptProgress.NONE);
        byte[] restoredBytes = Files.readAllBytes(restored);
        byte[] originalBytes = Files.readAllBytes(input);
        if (!java.util.Arrays.equals(restoredBytes, originalBytes)) {
            throw new IllegalStateException("生成的语料无法还原: " + artifactName);
        }

        properties.setProperty(prefix + "id", stem + "-" + tag);
        properties.setProperty(prefix + "file", artifactName);
        properties.setProperty(prefix + "input", input.getFileName().toString());
        properties.setProperty(prefix + "mode", mode.name());
        properties.setProperty(prefix + "passwordKey", passwordKey == null ? "" : passwordKey);
        properties.setProperty(prefix + "restoredName", restored.getFileName().toString());
        properties.setProperty(prefix + "canvasWidth", Integer.toString(metadata.canvasWidth()));
        properties.setProperty(prefix + "canvasHeight", Integer.toString(metadata.canvasHeight()));
        properties.setProperty(prefix + "innerPlainLength",
                Long.toString(metadata.payloadLength()));
        properties.setProperty(prefix + "argon2Salt",
                password == null ? "" : hex(frame.argon2Salt()));
        properties.setProperty(prefix + "hkdfSalt", hex(frame.hkdfSalt()));
        properties.setProperty(prefix + "nonce", hex(frame.nonce()));
        properties.setProperty(prefix + "keyConfirm", hex(frame.keyConfirm()));
        properties.setProperty(prefix + "authTag",
                hex(extractAuthTag(artifact, frame)));
        properties.setProperty(prefix + "artifactLength", Long.toString(artifactBytes.length));
        properties.setProperty(prefix + "artifactSha256", sha256(artifactBytes));
        properties.setProperty(prefix + "restoredLength", Long.toString(restoredBytes.length));
        properties.setProperty(prefix + "restoredSha256", sha256(restoredBytes));

        Path materialized = scratch.resolve("entry-" + index);
        if (Files.exists(materialized)) {
            deleteTree(materialized);
        }
        return index + 1;
    }

    /**
     * 从产物中取出认证标签。
     *
     * @param artifact 产物路径
     * @param frame    协议头
     * @return 64 字节认证标签
     * @throws Exception PNG 或协议解析失败
     */
    private static byte[] extractAuthTag(final Path artifact, final ImageCryptFrame frame)
            throws Exception {
        ByteArrayOutputStream frameOut = new ByteArrayOutputStream();
        try (InputStream in = Files.newInputStream(artifact)) {
            new PixelPngReader().readFrame(in, frameOut);
        }
        byte[] all = frameOut.toByteArray();
        int offset = ImageCryptProtocol.OUTER_HEADER_LENGTH + (int) frame.ciphertextLength();
        byte[] tag = new byte[ImageCryptProtocol.AUTH_TAG_LENGTH];
        System.arraycopy(all, offset, tag, 0, tag.length);
        return tag;
    }

    /**
     * 读取产物的协议头。
     *
     * @param artifact 产物路径
     * @return 协议头
     * @throws Exception PNG 或协议解析失败
     */
    private static ImageCryptFrame readFrame(final Path artifact) throws Exception {
        try (InputStream in = Files.newInputStream(artifact)) {
            return new PixelPngReader().peekFrame(in);
        }
    }

    /**
     * 用固定算法生成一张确定性输入图片。
     *
     * <p>刻意不用随机噪声：语料要在仓库里长期存在，渐变图案同样不可压缩，但更容易被人工
     * 目视确认"解密后确实还原了原图"。
     *
     * @param target 目标路径
     * @param format 格式名（png/jpg）
     * @throws IOException 编码失败
     */
    private static void writeImage(final Path target, final String format) throws IOException {
        BufferedImage image = new BufferedImage(INPUT_WIDTH, INPUT_HEIGHT,
                BufferedImage.TYPE_INT_RGB);
        for (int y = 0; y < INPUT_HEIGHT; y++) {
            for (int x = 0; x < INPUT_WIDTH; x++) {
                int red = (x * 255) / (INPUT_WIDTH - 1);
                int green = (y * 255) / (INPUT_HEIGHT - 1);
                int blue = ((x + y) * 255) / (INPUT_WIDTH + INPUT_HEIGHT - 2);
                image.setRGB(x, y, (red << 16) | (green << 8) | blue);
            }
        }
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        if (!ImageIO.write(image, format, buffer)) {
            throw new IOException("ImageIO 缺少 " + format + " 编码器");
        }
        Files.write(target, buffer.toByteArray());
    }

    /**
     * 去除文件名最后一个点之后的扩展名。
     *
     * @param fileName 文件名
     * @return 主干
     */
    private static String stripExtension(final String fileName) {
        int dot = fileName.lastIndexOf('.');
        return dot <= 0 ? fileName : fileName.substring(0, dot);
    }

    /**
     * 返回当前 Bouncy Castle 提供者版本。
     *
     * @return 版本号；无法读取时返回 unknown
     */
    private static String bouncyCastleVersion() {
        try {
            Class<?> provider = org.bouncycastle.jce.provider.BouncyCastleProvider.class;
            Package pkg = provider.getPackage();
            String version = pkg == null ? null : pkg.getImplementationVersion();
            if (version != null && !version.isEmpty()) {
                return version;
            }
            // 类路径以目录形式装配时包版本可能缺失，退回从 jar 文件名提取
            java.security.CodeSource source = provider.getProtectionDomain().getCodeSource();
            if (source != null && source.getLocation() != null) {
                String jar = Path.of(source.getLocation().toURI()).getFileName().toString();
                int end = jar.lastIndexOf(".jar");
                int separator = jar.lastIndexOf('-', end < 0 ? jar.length() - 1 : end);
                if (separator > 0) {
                    return jar.substring(separator + 1, end < 0 ? jar.length() : end);
                }
            }
        } catch (RuntimeException | java.net.URISyntaxException e) {
            LogService.trace("ImageCrypt", "无法读取 Bouncy Castle 版本: " + e.getMessage());
        }
        return "unknown";
    }

    /**
     * 计算 SHA-256。
     *
     * @param data 字节数组
     * @return 小写十六进制摘要
     * @throws Exception 摘要算法缺失
     */
    private static String sha256(final byte[] data) throws Exception {
        return hex(MessageDigest.getInstance("SHA-256").digest(data));
    }

    /**
     * 渲染为小写十六进制。
     *
     * @param data 字节数组
     * @return 十六进制文本
     */
    private static String hex(final byte[] data) {
        StringBuilder builder = new StringBuilder(data.length * 2);
        for (byte value : data) {
            builder.append(Character.forDigit((value >> 4) & 0xf, 16));
            builder.append(Character.forDigit(value & 0xf, 16));
        }
        return builder.toString();
    }

    /**
     * 尽力删除目录树。
     *
     * @param root 根路径
     * @throws IOException 遍历失败
     */
    private static void deleteTree(final Path root) throws IOException {
        if (!Files.exists(root)) {
            return;
        }
        try (java.util.stream.Stream<Path> stream = Files.walk(root)) {
            for (Path path : stream.sorted((left, right) ->
                    right.getNameCount() - left.getNameCount()).toList()) {
                Files.deleteIfExists(path);
            }
        }
    }
}
