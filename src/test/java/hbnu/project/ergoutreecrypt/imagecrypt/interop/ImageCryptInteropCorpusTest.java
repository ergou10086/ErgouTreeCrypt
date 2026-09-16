package hbnu.project.ergoutreecrypt.imagecrypt.interop;

import hbnu.project.ergoutreecrypt.exception.ErrorKind;
import hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptCodec;
import hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptException;
import hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptFrame;
import hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptMetadata;
import hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptMode;
import hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptPassword;
import hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptProgress;
import hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptProtocol;
import hbnu.project.ergoutreecrypt.imagecrypt.png.PixelPngReader;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 桌面 JVM 侧的互操作语料回归测试。
 *
 * <h3>它证明什么</h3>
 * <p>本测试读取 {@code imagecrypt/interop/v1} 中**冻结的产物字节**，重新解析协议头、逐字段
 * 比对中间值、完整还原并与记录的原图 SHA-256 对照。因此它同时守住两件事：
 * <ol>
 *   <li>协议契约未被改动——任何字段偏移、KDF 参数或认证覆盖范围的变化都会让解析结果与
 *       {@code corpus.properties} 中记录的值不符；</li>
 *   <li>v1 reader 长期可用——这是"永久保留 v1 reader"这条兼容承诺的回归防线。</li>
 * </ol>
 *
 * <h3>它不证明什么</h3>
 * <p>本测试运行在宿主 JVM 上，<b>不能</b>证明 Android ART 上的行为。跨端结论必须由
 * {@code ImageCryptInteropTest}（instrumentation）在真实设备或模拟器上给出，两者不可互相替代。
 *
 * @author ErgouTree
 * @since 2026/9/16
 */
final class ImageCryptInteropCorpusTest {

    /**
     * 语料在 classpath 上的根路径。
     */
    private static final String CORPUS_ROOT = "/imagecrypt/interop/v1/";

    /**
     * 还原验证用的临时目录。
     */
    @TempDir
    Path workDir;

    /**
     * 每条语料都必须在桌面 JVM 上逐字节还原，且恢复文件名符合记录。
     *
     * @throws Exception 读取或加解密失败
     */
    @Test
    void everyCorpusEntryRestoresByteForByte() throws Exception {
        Properties corpus = loadCorpus();
        int count = Integer.parseInt(corpus.getProperty("entry.count"));
        assertTrue(count >= 6, "语料至少应覆盖 2 种输入 × 3 种保护组合，实际 " + count);

        ImageCryptCodec codec = new ImageCryptCodec();
        List<String> restoredIds = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            String prefix = "entry." + i + ".";
            String id = corpus.getProperty(prefix + "id");
            Path artifact = materialize(corpus.getProperty(prefix + "file"));
            byte[] password = passwordOf(corpus, prefix);

            Path restoreDirectory = Files.createDirectories(workDir.resolve("entry-" + i));
            Path restored = codec.decrypt(artifact, restoreDirectory, password,
                    ImageCryptProgress.NONE);

            assertEquals(corpus.getProperty(prefix + "restoredName"),
                    restored.getFileName().toString(), id + " 恢复文件名不符");
            assertEquals(corpus.getProperty(prefix + "restoredLength"),
                    Long.toString(Files.size(restored)), id + " 恢复长度不符");
            assertEquals(corpus.getProperty(prefix + "restoredSha256"),
                    sha256(Files.readAllBytes(restored)), id + " 恢复内容 SHA-256 不符");
            assertTrue(codec.isEncrypted(artifact), id + " 应被识别为 EGTC-IMG 产物");
            codec.verify(artifact, password, ImageCryptProgress.NONE);
            restoredIds.add(id);
        }
        assertTrue(restoredIds.contains("corpus-input-png-public"), restoredIds.toString());
        assertTrue(restoredIds.contains("corpus-input-png-password-unicode"), restoredIds.toString());
        assertTrue(restoredIds.contains("corpus-input-jpg-password-ascii"), restoredIds.toString());
    }

    /**
     * 协议头字段必须与语料记录的中间值逐一相符。
     *
     * <p>这条断言是"协议被冻结"的实际含义：salt、nonce、keyConfirm、认证标签与画布尺寸都被
     * 写死在语料里，实现不得再改变它们的语义。</p>
     *
     * @throws Exception 读取或解析失败
     */
    @Test
    void recordedProtocolIntermediatesStillMatch() throws Exception {
        Properties corpus = loadCorpus();
        int count = Integer.parseInt(corpus.getProperty("entry.count"));

        for (int i = 0; i < count; i++) {
            String prefix = "entry." + i + ".";
            String id = corpus.getProperty(prefix + "id");
            Path artifact = materialize(corpus.getProperty(prefix + "file"));
            ImageCryptFrame frame = readFrame(artifact);

            assertEquals(corpus.getProperty(prefix + "canvasWidth"),
                    Integer.toString(frame.canvasWidth()), id + " 画布宽度不符");
            assertEquals(corpus.getProperty(prefix + "canvasHeight"),
                    Integer.toString(frame.canvasHeight()), id + " 画布高度不符");
            assertEquals(corpus.getProperty(prefix + "innerPlainLength"),
                    Long.toString(frame.innerPlainLength()), id + " 封装区长度不符");
            assertEquals(corpus.getProperty(prefix + "hkdfSalt"), hex(frame.hkdfSalt()),
                    id + " hkdfSalt 不符");
            assertEquals(corpus.getProperty(prefix + "nonce"), hex(frame.nonce()),
                    id + " nonce 不符");
            assertEquals(corpus.getProperty(prefix + "keyConfirm"), hex(frame.keyConfirm()),
                    id + " keyConfirm 不符");
            assertEquals(corpus.getProperty(prefix + "authTag"), hex(extractAuthTag(artifact, frame)),
                    id + " 认证标签不符");
            assertEquals(corpus.getProperty(prefix + "artifactSha256"),
                    sha256(Files.readAllBytes(artifact)), id + " 产物被改动过");
        }
    }

    /**
     * 语料必须同时覆盖公开恢复与密码保护，且两者的 KDF 字段语义与协议一致。
     *
     * <p>公开模式不得出现任何 Argon2 痕迹（否则说明无密码路径偷偷进了 KDF），密码模式必须
     * 使用 v1 固定的互操作档。</p>
     *
     * @throws Exception 读取或解析失败
     */
    @Test
    void corpusCoversBothProtectionModesWithCanonicalKdfFields() throws Exception {
        Properties corpus = loadCorpus();
        int count = Integer.parseInt(corpus.getProperty("entry.count"));
        int publicEntries = 0;
        int passwordEntries = 0;

        for (int i = 0; i < count; i++) {
            String prefix = "entry." + i + ".";
            String id = corpus.getProperty(prefix + "id");
            Path artifact = materialize(corpus.getProperty(prefix + "file"));
            ImageCryptMetadata metadata = new ImageCryptCodec().peekMetadata(artifact);
            ImageCryptFrame frame = readFrame(artifact);

            if (metadata.mode() == ImageCryptMode.PUBLIC_RECOVERY) {
                publicEntries++;
                assertTrue(corpus.getProperty(prefix + "argon2Salt").isEmpty(),
                        id + " 公开模式不得有 argon2Salt");
                assertEquals(0, metadata.argon2MemoryKiB(), id + " 公开模式不得声明 Argon2 内存");
                assertFalse(isAllZero(frame.embeddedMasterKey()),
                        id + " 公开模式必须携带随机主密钥");
            } else {
                passwordEntries++;
                assertEquals(ImageCryptProtocol.ARGON2_MEMORY_KIB, metadata.argon2MemoryKiB(),
                        id + " 密码模式内存参数非规范值");
                assertEquals(ImageCryptProtocol.ARGON2_PASSES, metadata.argon2Passes(),
                        id + " 密码模式迭代次数非规范值");
                assertEquals(ImageCryptProtocol.ARGON2_LANES, metadata.argon2Lanes(),
                        id + " 密码模式并行度非规范值");
                assertEquals(ImageCryptProtocol.ARGON2_SALT_LENGTH,
                        corpus.getProperty(prefix + "argon2Salt").length() / 2,
                        id + " argon2Salt 长度不符");
                assertTrue(isAllZero(frame.embeddedMasterKey()),
                        id + " 密码模式不得在文件内保存可恢复密钥");
            }
        }
        assertEquals(2, publicEntries, "语料应含 2 条公开恢复产物");
        assertEquals(4, passwordEntries, "语料应含 4 条密码保护产物（ASCII 与 Unicode 各 2 条）");
    }

    /**
     * 用错误口令还原语料中的密码条目必须报密码错误，且不产生任何文件。
     *
     * @throws Exception 读取或加解密失败
     */
    @Test
    void wrongPasswordOnCorpusEntryIsRejected() throws Exception {
        Properties corpus = loadCorpus();
        byte[] wrong = ImageCryptPassword.encodeForV1("definitely-not-the-corpus-password");
        Path artifact = materialize("desktop-corpus-input-png-password-ascii-v1.egimg.png");
        Path restoreDirectory = Files.createDirectories(workDir.resolve("wrong"));

        ImageCryptException thrown = org.junit.jupiter.api.Assertions.assertThrows(
                ImageCryptException.class,
                () -> new ImageCryptCodec().decrypt(artifact, restoreDirectory, wrong));
        assertEquals(ErrorKind.WRONG_PASSWORD, thrown.kind());
        assertEquals(List.of(), listFiles(restoreDirectory));
    }

    /**
     * 组合字符口令的 NFC 与 NFD 两种形态必须导出完全相同的 UTF-8 字节。
     *
     * <p>这是"密码规范化口径双端一致"的可执行定义：同一段文本在 macOS（习惯 NFD）与
     * Windows（习惯 NFC）上输入时，必须派生同一把密钥。语料里记下了两种形态的规范化结果，
     * 因此任何一端漏掉 NFC 都会在这里失败，而不是等到用户投诉"同一个密码有的机器打不开"。
     *
     * @throws Exception 读取或规范化失败
     */
    @Test
    void composedPasswordNormalizesIdenticallyAcrossForms() throws Exception {
        Properties corpus = loadCorpus();
        String nfc = corpus.getProperty("password.unicode");
        String nfd = corpus.getProperty("password.unicode.nfd");
        assertFalse(nfc.equals(nfd), "两种形态的码点序列本就应当不同，否则这条用例没有意义");

        String nfcHex = hex(ImageCryptPassword.encodeForV1(nfc));
        String nfdHex = hex(ImageCryptPassword.encodeForV1(nfd));
        assertEquals(corpus.getProperty("password.unicode.utf8Hex"), nfcHex,
                "NFC 口令的规范化字节与语料不符");
        assertEquals(nfcHex, nfdHex, "NFD 输入必须被归一化为与 NFC 完全相同的字节");
        assertEquals(corpus.getProperty("password.ascii.utf8Hex"),
                hex(ImageCryptPassword.encodeForV1(corpus.getProperty("password.ascii"))),
                "ASCII 口令的规范化字节与语料不符");
    }

    // ==================== 语料读取工具 ====================

    /**
     * 读取语料属性表。
     *
     * @return 属性表
     * @throws IOException 读取失败
     */
    private static Properties loadCorpus() throws IOException {
        Properties properties = new Properties();
        try (InputStream in = ImageCryptInteropCorpusTest.class
                .getResourceAsStream(CORPUS_ROOT + "corpus.properties")) {
            if (in == null) {
                throw new IOException("缺少互操作语料: " + CORPUS_ROOT + "corpus.properties");
            }
            // 必须以 UTF-8 读取：Properties.load(InputStream) 默认按 ISO-8859-1 解码，
            // 会把组合字符口令读成乱码，导致派生出不同的密钥并报出误导性的"头部被修改"
            properties.load(new InputStreamReader(in, StandardCharsets.UTF_8));
        }
        return properties;
    }

    /**
     * 把语料文件从 classpath 复制到临时目录，模拟"用户拿到一个文件"。
     *
     * <p>刻意不直接读资源流：真实流程里输入总是一个文件路径，而核心的预检、临时文件与原子
     * 提交都建立在文件系统语义上。
     *
     * @param name 语料文件名
     * @return 临时文件路径
     * @throws IOException 读取或写入失败
     */
    private Path materialize(final String name) throws IOException {
        Path target = workDir.resolve(name);
        if (Files.exists(target)) {
            return target;
        }
        try (InputStream in = ImageCryptInteropCorpusTest.class
                .getResourceAsStream(CORPUS_ROOT + name)) {
            if (in == null) {
                throw new IOException("缺少语料文件: " + CORPUS_ROOT + name);
            }
            Files.write(target, in.readAllBytes());
        }
        return target;
    }

    /**
     * 取出条目对应的口令字节。
     *
     * @param corpus 语料属性表
     * @param prefix 条目前缀
     * @return 密码字节；公开恢复模式返回 {@code null}
     * @throws ImageCryptException 口令规范化失败
     */
    private static byte[] passwordOf(final Properties corpus, final String prefix)
            throws ImageCryptException {
        String key = corpus.getProperty(prefix + "passwordKey");
        if (key == null || key.isEmpty()) {
            return null;
        }
        return ImageCryptPassword.encodeForV1(corpus.getProperty("password." + key));
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
     * 抽取产物的完整认证标签。
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
     * 列出目录下的文件名。
     *
     * @param directory 目录
     * @return 文件名列表
     * @throws IOException 读取失败
     */
    private static List<String> listFiles(final Path directory) throws IOException {
        if (!Files.isDirectory(directory)) {
            return List.of();
        }
        try (java.util.stream.Stream<Path> stream = Files.list(directory)) {
            return stream.map(path -> path.getFileName().toString()).sorted().toList();
        }
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
     * 判断字节数组是否全为 0。
     *
     * @param data 字节数组
     * @return true 表示全为 0
     */
    private static boolean isAllZero(final byte[] data) {
        for (byte value : data) {
            if (value != 0) {
                return false;
            }
        }
        return true;
    }

}
