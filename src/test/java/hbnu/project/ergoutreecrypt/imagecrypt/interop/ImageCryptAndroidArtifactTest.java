package hbnu.project.ergoutreecrypt.imagecrypt.interop;

import hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptCodec;
import hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptMetadata;
import hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptMode;
import hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptPassword;
import hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptProgress;
import hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptProtocol;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Properties;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Android → Desktop 方向的互操作校验：在真实设备上生成的产物由桌面 JVM 还原。
 *
 * <h3>为什么期望值取自桌面语料而不是设备自报</h3>
 * <p>设备导出的 {@code export-N.properties} 里也记了一份 {@code restoredSha256}。如果直接拿它
 * 当断言目标，那么"设备写错了期望值"和"设备真的能还原"就无法区分，互操作变成了自证。
 * 因此这里一律以冻结的 {@code corpus.properties} 中**输入文件自身的 SHA-256** 为准，
 * 设备记录只用于核对来源。
 *
 * <h3>为什么默认跳过</h3>
 * <p>本测试需要一份由设备导出、再经 adb 拉取到本机的产物目录。CI 与日常开发不会随手具备这个
 * 前置条件，因此未提供目录时跳过并给出完整命令，而不是把一次真实的互操作闸门降级成"绿灯"。
 * <b>跳过不等于通过</b>：Phase 4 的验收要求是显式提供目录并看到它通过。
 *
 * @author ErgouTree
 * @since 2026/9/16
 */
final class ImageCryptAndroidArtifactTest {

    /**
     * 指定设备导出目录的系统属性名。
     */
    private static final String EXPORT_PROPERTY = "imagecrypt.android.export";

    /**
     * 指定设备导出目录的环境变量名。
     */
    private static final String EXPORT_ENV = "IMAGECRYPT_ANDROID_EXPORT";

    /**
     * 桌面语料在 classpath 上的根路径。
     */
    private static final String CORPUS_ROOT = "/imagecrypt/interop/v1/";

    /**
     * 还原验证用的临时目录。
     */
    @TempDir
    Path workDir;

    /**
     * 设备生成的每条产物都必须能被桌面 JVM 逐字节还原。
     *
     * @throws Exception 读取或加解密失败
     */
    @Test
    void androidArtifactsRestoreOnDesktop() throws Exception {
        Path exportDirectory = resolveExportDirectory();
        Properties corpus = loadCorpus();
        Properties export = loadProperties(exportDirectory.resolve("export.properties"));

        assertEquals("android-art", export.getProperty("export.generator"),
                "导出目录不是由 Android 端生成的");
        int entryCount = Integer.parseInt(export.getProperty("export.entryCount"));
        assertTrue(entryCount >= 6, "设备应导出至少 2 种输入 × 3 种保护组合，实际 " + entryCount);

        ImageCryptCodec codec = new ImageCryptCodec();
        for (int index = 0; index < entryCount; index++) {
            Properties entry = loadProperties(exportDirectory.resolve("export-" + index + ".properties"));
            String id = entry.getProperty("id");
            Path artifact = exportDirectory.resolve(entry.getProperty("file"));
            assertTrue(Files.isRegularFile(artifact), id + " 缺少产物文件");

            byte[] password = passwordOf(corpus, entry.getProperty("passwordKey"));
            assertTrue(codec.isEncrypted(artifact), id + " 桌面端未识别出 EGTC-IMG");

            ImageCryptMetadata metadata = codec.peekMetadata(artifact);
            assertEquals(entry.getProperty("mode"), metadata.mode().name(), id + " 保护模式不符");
            if (metadata.mode() == ImageCryptMode.PASSWORD) {
                assertEquals(ImageCryptProtocol.ARGON2_MEMORY_KIB, metadata.argon2MemoryKiB(),
                        id + " 设备未采用 v1 固定 Argon2 内存参数");
                assertEquals(ImageCryptProtocol.ARGON2_PASSES, metadata.argon2Passes(),
                        id + " 设备未采用 v1 固定 Argon2 迭代次数");
                assertEquals(ImageCryptProtocol.ARGON2_LANES, metadata.argon2Lanes(),
                        id + " 设备未采用 v1 固定 Argon2 并行度");
            }
            codec.verify(artifact, password, ImageCryptProgress.NONE);

            Path restoreDirectory = Files.createDirectories(workDir.resolve("entry-" + index));
            Path restored = codec.decrypt(artifact, restoreDirectory, password,
                    ImageCryptProgress.NONE);

            // 期望值来自冻结语料：输入理应原样回来
            String expectedSha = corpus.getProperty(
                    "input." + inputIndexOf(corpus, entry.getProperty("input")) + ".sha256");
            assertEquals(expectedSha, sha256(Files.readAllBytes(restored)),
                    id + " 桌面还原结果与原始输入不一致");
            assertEquals(expectedSha, entry.getProperty("restoredSha256"),
                    id + " 设备自报的期望值与桌面语料不符，说明导出被篡改或读错了输入");

            // 恢复扩展名以魔数判定为准；本语料的输入名与内容一致，因此等于输入的扩展名
            String restoredName = restored.getFileName().toString();
            String extension = restoredName.substring(restoredName.lastIndexOf('.') + 1);
            String inputName = entry.getProperty("input");
            assertEquals(inputName.substring(inputName.lastIndexOf('.') + 1), extension,
                    id + " 恢复扩展名不符");
        }
    }

    /**
     * 设备导出的产物不得在协议头里留下任何非规范字段。
     *
     * <p>这条断言守住 INT-06：解密只服从文件里的协议版本、算法 ID 与 KDF 参数，而设备写出的
     * 也必须只有 v1 定义的那一种组合。</p>
     *
     * @throws Exception 读取或解析失败
     */
    @Test
    void androidArtifactsUseCanonicalProtocolFields() throws Exception {
        Path exportDirectory = resolveExportDirectory();
        Properties export = loadProperties(exportDirectory.resolve("export.properties"));
        int entryCount = Integer.parseInt(export.getProperty("export.entryCount"));

        for (int index = 0; index < entryCount; index++) {
            Properties entry = loadProperties(exportDirectory.resolve("export-" + index + ".properties"));
            Path artifact = exportDirectory.resolve(entry.getProperty("file"));
            ImageCryptMetadata metadata = new ImageCryptCodec().peekMetadata(artifact);
            String id = entry.getProperty("id");

            assertEquals(ImageCryptProtocol.VERSION, metadata.protocolVersion(), id + " 协议版本不符");
            assertFalse(metadata.canvasWidth() <= 0 || metadata.canvasHeight() <= 0,
                    id + " 画布尺寸非法");
            assertTrue(metadata.canvasWidth() <= ImageCryptProtocol.LIMIT_CANVAS_SIDE
                            && metadata.canvasHeight() <= ImageCryptProtocol.LIMIT_CANVAS_SIDE,
                    id + " 画布超出单边上限");
            long frameBytes = ImageCryptProtocol.OUTER_HEADER_LENGTH + metadata.payloadLength()
                    + ImageCryptProtocol.AUTH_TAG_LENGTH;
            assertTrue(ImageCryptProtocol.canvasCapacity(metadata.canvasWidth(),
                            metadata.canvasHeight()) >= frameBytes,
                    id + " 画布容量不足以容纳协议帧");
        }
    }

    // ==================== 工具 ====================

    /**
     * 解析设备导出目录。
     *
     * @return 导出目录
     */
    private static Path resolveExportDirectory() {
        String configured = System.getProperty(EXPORT_PROPERTY);
        if (configured == null || configured.isBlank()) {
            configured = System.getenv(EXPORT_ENV);
        }
        Assumptions.assumeTrue(configured != null && !configured.isBlank(),
                "未提供设备导出目录，跳过 Android → Desktop 方向。请先执行：\n"
                        + "  adb shell am instrument -w -e class "
                        + "hbnu.project.ergoutreecrypt.android.ImageCryptInteropTest "
                        + "hbnu.project.ergoutreecrypt.debug.test/"
                        + "androidx.test.runner.AndroidJUnitRunner\n"
                        + "  adb pull /sdcard/Android/data/hbnu.project.ergoutreecrypt.debug/files/"
                        + "imagecrypt-interop-out <本地目录>\n"
                        + "  mvn test -Dtest=ImageCryptAndroidArtifactTest "
                        + "-D" + EXPORT_PROPERTY + "=<本地目录>");

        Path directory = Path.of(configured).toAbsolutePath().normalize();
        Assumptions.assumeTrue(Files.isDirectory(directory),
                "设备导出目录不存在: " + directory);
        return directory;
    }

    /**
     * 读取桌面语料属性表。
     *
     * @return 属性表
     * @throws IOException 读取失败
     */
    private static Properties loadCorpus() throws IOException {
        try (InputStream in = ImageCryptAndroidArtifactTest.class
                .getResourceAsStream(CORPUS_ROOT + "corpus.properties")) {
            if (in == null) {
                throw new IOException("缺少互操作语料: " + CORPUS_ROOT + "corpus.properties");
            }
            Properties properties = new Properties();
            properties.load(new InputStreamReader(in, StandardCharsets.UTF_8));
            return properties;
        }
    }

    /**
     * 读取一个 UTF-8 属性文件。
     *
     * @param file 文件路径
     * @return 属性表
     * @throws IOException 读取失败
     */
    private static Properties loadProperties(final Path file) throws IOException {
        Properties properties = new Properties();
        try (InputStream in = Files.newInputStream(file)) {
            properties.load(new InputStreamReader(in, StandardCharsets.UTF_8));
        }
        return properties;
    }

    /**
     * 按口令键名取出口令字节。
     *
     * @param corpus      桌面语料
     * @param passwordKey 口令键名；公开恢复模式为空
     * @return 口令字节；公开恢复模式返回 {@code null}
     * @throws Exception 口令规范化失败
     */
    private static byte[] passwordOf(final Properties corpus, final String passwordKey)
            throws Exception {
        if (passwordKey == null || passwordKey.isEmpty()) {
            return null;
        }
        return ImageCryptPassword.encodeForV1(corpus.getProperty("password." + passwordKey));
    }

    /**
     * 查找输入文件名在语料中的序号。
     *
     * @param corpus    桌面语料
     * @param inputName 输入文件名
     * @return 序号
     */
    private static int inputIndexOf(final Properties corpus, final String inputName) {
        int count = Integer.parseInt(corpus.getProperty("input.count"));
        for (int index = 0; index < count; index++) {
            if (inputName.equals(corpus.getProperty("input." + index + ".file"))) {
                return index;
            }
        }
        throw new AssertionError("语料中没有输入: " + inputName);
    }

    /**
     * 计算 SHA-256。
     *
     * @param data 字节数组
     * @return 小写十六进制摘要
     * @throws Exception 摘要算法缺失
     */
    private static String sha256(final byte[] data) throws Exception {
        StringBuilder builder = new StringBuilder();
        for (byte value : MessageDigest.getInstance("SHA-256").digest(data)) {
            builder.append(Character.forDigit((value >> 4) & 0xf, 16));
            builder.append(Character.forDigit(value & 0xf, 16));
        }
        return builder.toString();
    }

}
