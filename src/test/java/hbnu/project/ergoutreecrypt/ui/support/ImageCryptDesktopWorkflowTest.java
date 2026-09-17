package hbnu.project.ergoutreecrypt.ui.support;

import hbnu.project.ergoutreecrypt.filetypes.OutputNaming;
import hbnu.project.ergoutreecrypt.i18n.Messages;
import hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptMode;
import hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptProgress;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.InputStream;
import java.awt.image.BufferedImage;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Locale;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 桌面图片加密无界面工作流测试。
 *
 * <p>使用仓库中的真实 PNG、JPEG、GIF、BMP 与 WebP 样本验证桌面层的密码规范化和核心调用，
 * 不启动 JavaFX 工具包，因此可在常规 Maven 与 CI 环境稳定运行。
 *
 * @author ErgouTree
 * @since 2026/9/16
 */
final class ImageCryptDesktopWorkflowTest {

    /** 真实图片样本目录。 */
    private static final Path SAMPLE_DIRECTORY =
            Path.of("src/test/resources/imagecrypt/test_picture");

    /** 五种首期格式的真实样本。 */
    private static final List<String> SUPPORTED_SAMPLES = List.of(
            "png.png", "jpeg.jpeg", "gif.gif", "bmp.bmp", "webp.webp");

    /** 每个测试独立的临时目录。 */
    @TempDir
    private Path workDirectory;

    /**
     * 公开恢复与密码保护模式必须让五种真实格式逐字节往返。
     *
     * @throws Exception 图片处理失败
     */
    @Test
    void bothProtectionModesRoundTripFiveRealFormats() throws Exception {
        ImageCryptDesktopWorkflow workflow = new ImageCryptDesktopWorkflow();
        for (ImageCryptMode mode : ImageCryptMode.values()) {
            String password = mode == ImageCryptMode.PASSWORD ? "Phase6-五格式" : "stale-ui-password";
            for (String sampleName : SUPPORTED_SAMPLES) {
                Path input = SAMPLE_DIRECTORY.resolve(sampleName);
                Path formatDirectory = Files.createDirectories(
                        workDirectory.resolve(mode.name()).resolve(sampleName));
                Path encrypted = formatDirectory.resolve(
                        OutputNaming.imageCryptOutputName(input.getFileName().toString()));
                workflow.encrypt(input, encrypted, mode, password, false,
                        ImageCryptProgress.NONE);
                Path restoredDirectory = Files.createDirectories(
                        formatDirectory.resolve("restored"));
                Path restored = workflow.decrypt(encrypted, restoredDirectory,
                        password, false, ImageCryptProgress.NONE);

                assertEquals(-1L, Files.mismatch(input, restored),
                        mode + " / " + sampleName + " 必须逐字节还原");
            }
        }
    }

    /**
     * 密码模式必须由桌面工作流统一执行 NFC 与 UTF-8 规范化后完成真实 WebP 往返。
     *
     * @throws Exception 图片处理失败
     */
    @Test
    void passwordModeNormalizesAndRoundTripsRealWebp() throws Exception {
        ImageCryptDesktopWorkflow workflow = new ImageCryptDesktopWorkflow();
        Path input = SAMPLE_DIRECTORY.resolve("webp.webp");
        Path encrypted = workDirectory.resolve("webp.egimg.png");
        String decomposedPassword = "cafe\u0301-桌面端";
        String composedPassword = "caf\u00e9-桌面端";

        workflow.encrypt(input, encrypted, ImageCryptMode.PASSWORD,
                decomposedPassword, false, ImageCryptProgress.NONE);
        workflow.verify(encrypted, composedPassword, ImageCryptProgress.NONE);
        Path restored = workflow.decrypt(encrypted, workDirectory.resolve("password-restored"),
                composedPassword, false, ImageCryptProgress.NONE);

        assertEquals(-1L, Files.mismatch(input, restored));
    }

    /**
     * Phase 6 新增桌面文案必须在中英文资源包中完整解析。
     */
    @Test
    void desktopImagePageKeysAreBilingual() {
        Locale previous = Messages.getLocale();
        List<String> keys = List.of(
                "tab.imageCrypt",
                "imageCrypt.tab.encrypt",
                "imageCrypt.tab.decrypt",
                "imageCrypt.file.reselect",
                "imageCrypt.file.clearSelection",
                "imageCrypt.public.warning",
                "imageCrypt.sendAsFile.hint",
                "imageCrypt.kdf.hint",
                "imageCrypt.action.verify",
                "imageCrypt.preview.inputCaption",
                "imageCrypt.preview.resultTitle",
                "imageCrypt.preview.encryptedCaption",
                "imageCrypt.preview.decryptedCaption",
                "imageCrypt.preview.loading",
                "imageCrypt.preview.unavailable",
                "imageCrypt.status.encryptSuccess",
                "imageCrypt.status.decryptSuccess",
                "imageCrypt.progress.info");
        try {
            for (Locale locale : List.of(Locale.SIMPLIFIED_CHINESE, Locale.ENGLISH)) {
                Messages.setLocale(locale);
                for (String key : keys) {
                    String text = Messages.get(key);
                    assertFalse(text.isBlank(), "文案不得为空: " + key);
                    assertTrue(!text.equals("!" + key + "!"), "缺少文案: " + key);
                }
            }
            Messages.setLocale(Locale.SIMPLIFIED_CHINESE);
            assertEquals("解密还原图片", Messages.get("imageCrypt.tab.decrypt"));
        } finally {
            Messages.setLocale(previous);
        }
    }

    /**
     * 桌面 FXML 必须同时保留输入预览、重新选择、清空选择和结果预览节点。
     *
     * @throws Exception 读取 FXML 失败
     */
    @Test
    void desktopFxmlKeepsBothPreviewSurfacesAndSelectionActions() throws Exception {
        String resource = "/hbnu/project/ergoutreecrypt/ui/image-crypt-view.fxml";
        try (InputStream input = getClass().getResourceAsStream(resource)) {
            assertTrue(input != null, "缺少桌面图片页面 FXML");
            String fxml = new String(input.readAllBytes(), StandardCharsets.UTF_8);
            assertTrue(fxml.contains("fx:id=\"imageInputPreview\""));
            assertTrue(fxml.contains("fx:id=\"imageReselectFileBtn\""));
            assertTrue(fxml.contains("onAction=\"#onReselectFile\""));
            assertTrue(fxml.contains("fx:id=\"imageClearFileBtn\""));
            assertTrue(fxml.contains("fx:id=\"imagePublicWarningCard\""));
            assertTrue(fxml.contains("fx:id=\"imagePreviewCard\""));
            assertTrue(fxml.contains("fx:id=\"imageResultCard\""));
        }
    }

    /**
     * 桌面有界预览器必须解码首期五种真实图片格式，包括 JavaFX 原生不支持的 WebP。
     *
     * @throws Exception 图片读取失败
     */
    @Test
    void boundedPreviewDecodesFiveRealFormatsIncludingWebp() throws Exception {
        for (String sampleName : SUPPORTED_SAMPLES) {
            BufferedImage preview = BoundedImagePreviewLoader.readThumbnail(
                    SAMPLE_DIRECTORY.resolve(sampleName), 360, 220);
            assertTrue(preview != null, "无法预览 " + sampleName);
            assertTrue(preview.getWidth() <= 360, "预览宽度越界: " + sampleName);
            assertTrue(preview.getHeight() <= 220, "预览高度越界: " + sampleName);
            preview.flush();
        }
    }
}
