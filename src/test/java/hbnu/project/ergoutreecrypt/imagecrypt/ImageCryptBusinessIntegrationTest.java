package hbnu.project.ergoutreecrypt.imagecrypt;

import hbnu.project.ergoutreecrypt.exception.ErrorKind;
import hbnu.project.ergoutreecrypt.filetypes.FileInputGuard;
import hbnu.project.ergoutreecrypt.filetypes.FileInputGuard.Feature;
import hbnu.project.ergoutreecrypt.filetypes.FileInputGuard.GuardResult;
import hbnu.project.ergoutreecrypt.filetypes.FileInputGuard.Options;
import hbnu.project.ergoutreecrypt.history.FileHistoryStore;
import hbnu.project.ergoutreecrypt.history.OperationRecord;
import hbnu.project.ergoutreecrypt.history.OperationType;
import hbnu.project.ergoutreecrypt.i18n.Messages;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Phase 5 共享业务接入测试。
 *
 * <p>覆盖图片加密三类输入护栏、通用入口分流、历史类型和双语阶段文案。测试只生成一个
 * 极小公开恢复产物，不执行 Argon2，也不依赖平台 UI，因此桌面与 Android 同步源码采用的是
 * 同一组稳定业务契约。
 *
 * @author ErgouTree
 * @since 2026/9/16
 */
final class ImageCryptBusinessIntegrationTest {

    /**
     * 每个测试独立的临时目录。
     */
    @TempDir
    private Path workDir;

    /**
     * 图片加密护栏必须按魔数接受五种首期格式，并拒绝目录与非图片文件。
     *
     * @throws IOException 测试文件写入失败
     */
    @Test
    void imageEncryptGuardAcceptsSupportedMagicFormats() throws IOException {
        Map<String, byte[]> samples = new LinkedHashMap<>();
        samples.put("sample.png", ImageCryptTestSupport.minimalPng(32, 24));
        samples.put("sample.jpg", ImageCryptTestSupport.minimalJpeg(32, 24));
        samples.put("sample.gif", ImageCryptTestSupport.minimalGif(32, 24));
        samples.put("sample.bmp", ImageCryptTestSupport.minimalBmp(32, 24, 40));
        samples.put("sample.webp", ImageCryptTestSupport.webpVp8x(32, 24));

        for (Map.Entry<String, byte[]> sample : samples.entrySet()) {
            GuardResult result = FileInputGuard.check(Feature.IMAGE_CRYPT_ENCRYPT,
                    Options.none(), write(sample.getKey(), sample.getValue()));
            assertTrue(result.accepted(), () -> sample.getKey() + " 被错误拒绝: "
                    + result.guardKey());
        }

        GuardResult unsupported = FileInputGuard.check(Feature.IMAGE_CRYPT_ENCRYPT,
                Options.none(), write("plain.txt", "not an image".getBytes(StandardCharsets.UTF_8)));
        assertEquals(ErrorKind.UNSUPPORTED_FORMAT, unsupported.kind());
        assertEquals(FileInputGuard.GUARD_IMAGE_CRYPT_UNSUPPORTED, unsupported.guardKey());

        Path directory = Files.createDirectories(workDir.resolve("images"));
        GuardResult folder = FileInputGuard.check(Feature.IMAGE_CRYPT_ENCRYPT,
                Options.none(), directory);
        assertEquals(FileInputGuard.GUARD_REQUIRE_FILE, folder.guardKey());
    }

    /**
     * 图片密文必须被三类图片入口正确接收，并从通用解密与通用校验入口精确分流。
     *
     * @throws Exception 极小公开恢复产物生成失败
     */
    @Test
    void imageCryptEnvelopeIsAcceptedAndRedirectedByFeature() throws Exception {
        Path source = write("source.gif", ImageCryptTestSupport.minimalGif(16, 12));
        Path encrypted = workDir.resolve("source.egimg.png");
        new ImageCryptCodec().encrypt(source, encrypted, null, ImageCryptOptions.DEFAULT,
                ImageCryptProgress.NONE);

        assertAccepted(Feature.IMAGE_CRYPT_DECRYPT, encrypted);
        assertAccepted(Feature.IMAGE_CRYPT_VERIFY, encrypted);

        assertRedirected(Feature.IMAGE_CRYPT_ENCRYPT, encrypted,
                FileInputGuard.GUARD_IMAGE_CRYPT_DECRYPT);
        assertRedirected(Feature.GENERIC_DECRYPT, encrypted,
                FileInputGuard.GUARD_IMAGE_CRYPT_DECRYPT);
        assertRedirected(Feature.VERIFY_INTEGRITY, encrypted,
                FileInputGuard.GUARD_IMAGE_CRYPT_VERIFY);
    }

    /**
     * 图片还原与校验入口必须保留协议错误分类，而不是退化为普通格式错误。
     *
     * @throws IOException 测试文件写入失败
     */
    @Test
    void imageDecryptAndVerifyPreserveProtocolErrorKind() throws IOException {
        Path plain = write("plain.bin", new byte[] {1, 2, 3, 4});
        for (Feature feature : new Feature[] {
                Feature.IMAGE_CRYPT_DECRYPT, Feature.IMAGE_CRYPT_VERIFY}) {
            GuardResult result = FileInputGuard.check(feature, Options.none(), plain);
            assertTrue(result.rejected(), "普通文件必须被拒绝: " + feature);
            assertEquals(ErrorKind.NOT_IMAGE_CRYPT, result.kind());
            assertEquals(ErrorKind.NOT_IMAGE_CRYPT.i18nKey(), result.guardKey());
        }
    }

    /**
     * 新增历史类型与图片阶段必须在中英文资源中都有可展示文案。
     */
    @Test
    void historyTypesAndPhasesHaveBilingualLabels() {
        Locale previous = Messages.getLocale();
        try {
            for (Locale locale : new Locale[] {Locale.SIMPLIFIED_CHINESE, Locale.ENGLISH}) {
                Messages.setLocale(locale);
                for (OperationType type : new OperationType[] {
                        OperationType.IMAGE_ENCRYPT,
                        OperationType.IMAGE_DECRYPT,
                        OperationType.IMAGE_VERIFY}) {
                    assertResolved(type.getI18nKey());
                }
                for (ImageCryptPhase phase : ImageCryptPhase.values()) {
                    assertResolved(phase.i18nKey());
                }
            }
        } finally {
            Messages.setLocale(previous);
        }
    }

    /**
     * 三种图片历史类型必须按稳定枚举名完成持久化往返。
     */
    @Test
    void imageOperationTypesRoundTripThroughHistoryStore() {
        FileHistoryStore store = new FileHistoryStore(workDir.resolve("history"));
        List<OperationType> types = List.of(OperationType.IMAGE_ENCRYPT,
                OperationType.IMAGE_DECRYPT, OperationType.IMAGE_VERIFY);
        for (int i = 0; i < types.size(); i++) {
            store.record(new OperationRecord("image-" + i + ".png", null, null,
                    types.get(i), i + 1L));
        }

        List<OperationRecord> records = store.list();
        assertEquals(List.of(OperationType.IMAGE_VERIFY, OperationType.IMAGE_DECRYPT,
                        OperationType.IMAGE_ENCRYPT),
                records.stream().map(OperationRecord::type).toList());
    }

    /**
     * 写入一个测试文件。
     *
     * @param name 文件名
     * @param data 文件内容
     * @return 写入后的路径
     * @throws IOException 写入失败
     */
    private Path write(final String name, final byte[] data) throws IOException {
        return Files.write(workDir.resolve(name), data);
    }

    /**
     * 断言指定功能放行输入。
     *
     * @param feature 功能入口
     * @param input   输入文件
     */
    private static void assertAccepted(final Feature feature, final Path input) {
        GuardResult result = FileInputGuard.check(feature, Options.none(), input);
        assertTrue(result.accepted(), () -> feature + " 被错误拒绝: " + result.guardKey());
    }

    /**
     * 断言指定功能以预期文案分流输入。
     *
     * @param feature     功能入口
     * @param input       输入文件
     * @param expectedKey 预期文案键
     */
    private static void assertRedirected(final Feature feature, final Path input,
                                         final String expectedKey) {
        GuardResult result = FileInputGuard.check(feature, Options.none(), input);
        assertTrue(result.rejected(), "应分流而不是放行: " + feature);
        assertEquals(ErrorKind.UNSUPPORTED_FORMAT, result.kind());
        assertEquals(expectedKey, result.guardKey());
    }

    /**
     * 断言资源键已解析成实际文案。
     *
     * @param key 资源键
     */
    private static void assertResolved(final String key) {
        String text = Messages.get(key);
        assertFalse(text.isBlank(), "文案不得为空: " + key);
        assertFalse(text.equals("!" + key + "!"), "缺少文案: " + key);
    }
}
