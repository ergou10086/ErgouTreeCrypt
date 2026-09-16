package hbnu.project.ergoutreecrypt.imagecrypt;

import hbnu.project.ergoutreecrypt.exception.ErrorKind;
import hbnu.project.ergoutreecrypt.filetypes.OutputNaming;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 图片加密的命名规则与画布尺寸编排的纯函数测试。
 *
 * <p>这两组函数都是双端共享的纯逻辑：命名决定产物与恢复文件叫什么，画布决定产物能否被普通
 * 看图软件打开。它们不依赖文件系统与密码学，因此可以逐条穷举边界，而不必跑完整流程。
 *
 * @author ErgouTree
 * @since 2026/9/16
 */
final class ImageCryptNamingAndCanvasTest {

    /**
     * 加密产物命名必须丢掉原扩展名并统一落到 PNG 外壳。
     */
    @Test
    void encryptionOutputNameReplacesExtensionWithPngShell() {
        assertEquals("holiday.egimg.png", OutputNaming.imageCryptOutputName("holiday.jpg"));
        assertEquals("holiday.egimg.png", OutputNaming.imageCryptOutputName("holiday.jpeg"));
        assertEquals("holiday.egimg.png", OutputNaming.imageCryptOutputName("holiday.PNG"));
        assertEquals("archive.tar.egimg.png", OutputNaming.imageCryptOutputName("archive.tar.gif"));
        assertEquals("noext.egimg.png", OutputNaming.imageCryptOutputName("noext"));
        // 前导点属于文件名本身而非扩展名，因此保留隐藏属性，只追加标记
        assertEquals(".hidden.egimg.png", OutputNaming.imageCryptOutputName(".hidden"));
    }

    /**
     * 恢复命名必须覆盖协议文档给出的三种情形。
     */
    @Test
    void restoredOutputNameCoversAllThreeDocumentedCases() {
        assertEquals("holiday.restored.jpg",
                OutputNaming.imageRestoredOutputName("holiday.jpg", "jpg"));
        assertEquals("café 假期.restored.jpg",
                OutputNaming.imageRestoredOutputName("café 假期.jpg", "jpg"));
        assertEquals("restored.gif",
                OutputNaming.imageRestoredOutputName("", "gif"));
        assertEquals("restored.gif",
                OutputNaming.imageRestoredOutputName(null, "gif"));
        assertEquals("restored",
                OutputNaming.imageRestoredOutputName("", ""));
    }

    /**
     * 对<b>已经清洗过</b>的清单基名，恢复命名必须产出一个普通文件名。
     *
     * <p>路径穿越防护不在本函数里：清单侧 {@code InnerManifest.safeBasename()} 负责剥离目录与
     * 盘符，{@code ImageCryptCodec} 侧还会复查解析出的父目录是否就是目标目录。这里只确认
     * 正常输入下的拼接形态，避免把安全责任错误地摊到命名函数上。
     */
    @Test
    void restoredOutputNameUsesSanitizedBasenameAsIs() {
        for (String sanitized : List.of("holiday.jpg", "假期.jpg", "photo", "photo_2026-09-16")) {
            String name = OutputNaming.imageRestoredOutputName(sanitized, "png");
            assertFalse(name.contains("/"), name);
            assertFalse(name.contains("\\"), name);
            assertFalse(name.isEmpty(), "恢复名不得为空");
            assertFalse(name.startsWith("."), name);
            assertTrue(name.endsWith(".png"), name);
            assertTrue(name.contains(OutputNaming.IMAGE_RESTORED_SUFFIX), name);
        }
    }

    /**
     * 图片加密标记不得与格式保持加密标记混用。
     *
     * <p>{@code .enc} 会被输入护栏路由到格式保持分支，而图片密文本身就是 PNG；
     * 若两者共用标记，{@code .egimg.png} 会被错误分流。
     */
    @Test
    void imageCryptMarkerIsDistinctFromFormatPreservingMarker() {
        assertFalse(OutputNaming.IMAGE_CRYPT_MARKER.equals(OutputNaming.FPE_MARKER));
        assertFalse(OutputNaming.imageCryptOutputName("a.png").contains(OutputNaming.FPE_MARKER));
        assertTrue(OutputNaming.imageCryptOutputName("a.png")
                .contains(OutputNaming.IMAGE_CRYPT_MARKER));
    }

    /**
     * 画布必须至少容纳整帧，且两个维度都不超过单边上限。
     */
    @Test
    void canvasAlwaysFitsFrameWithinSideLimit() throws Exception {
        long[] payloadLengths = {1L, 28L, 1024L, 1L << 20, 64L << 20};
        int[][] hints = {{0, 0}, {4000, 3000}, {1, 8000}, {8000, 1}, {1, 1}, {-1, 0}};
        for (long payloadLength : payloadLengths) {
            long required = ImageCryptProtocol.requiredPixels(payloadLength);
            assertTrue(required > 0, "载荷 " + payloadLength + " 应有合法像素需求");
            for (int[] hint : hints) {
                int[] canvas = ImageCryptProtocol.chooseCanvasSize(required, hint[0], hint[1]);
                assertTrue(canvas[0] > 0 && canvas[0] <= ImageCryptProtocol.LIMIT_CANVAS_SIDE,
                        "宽度越界: " + canvas[0]);
                assertTrue(canvas[1] > 0 && canvas[1] <= ImageCryptProtocol.LIMIT_CANVAS_SIDE,
                        "高度越界: " + canvas[1]);
                long capacity = ImageCryptProtocol.canvasCapacity(canvas[0], canvas[1]);
                assertTrue(capacity >= required * ImageCryptProtocol.PNG_BYTES_PER_PIXEL,
                        "画布容量不足以容纳载荷 " + payloadLength);
            }
        }
    }

    /**
     * 原图长宽比必须影响画布形状，且极端比例被裁剪到 1/16 与 16。
     */
    @Test
    void canvasFollowsSourceAspectRatioWithinClamp() throws Exception {
        long required = 300_000L;
        int[] wide = ImageCryptProtocol.chooseCanvasSize(required, 4000, 250);
        int[] square = ImageCryptProtocol.chooseCanvasSize(required, 1000, 1000);
        int[] tall = ImageCryptProtocol.chooseCanvasSize(required, 250, 4000);

        assertTrue(wide[0] > wide[1] * 10, "横向原图应得到扁画布: " + wide[0] + "x" + wide[1]);
        assertTrue(tall[1] > tall[0] * 10, "纵向原图应得到高画布: " + tall[0] + "x" + tall[1]);
        assertTrue(square[0] == square[1], "正方形原图应得到正方形画布");

        double wideRatio = (double) wide[0] / wide[1];
        assertTrue(wideRatio >= ImageCryptProtocol.CANVAS_RATIO_MIN
                        && wideRatio <= ImageCryptProtocol.CANVAS_RATIO_MAX + 1,
                "长宽比必须落在裁剪区间内，实际 " + wideRatio);
    }

    /**
     * 超出画布总容量的载荷必须被明确拒绝，而不是回绕或尝试分配。
     */
    @Test
    void oversizedPayloadIsRejected() {
        long maxPixels = (long) ImageCryptProtocol.LIMIT_CANVAS_SIDE
                * ImageCryptProtocol.LIMIT_CANVAS_SIDE;
        ImageCryptTestSupport.assertKind(ErrorKind.CAPACITY_INSUFFICIENT,
                () -> ImageCryptProtocol.chooseCanvasSize(maxPixels + 1, 100, 100));
        ImageCryptTestSupport.assertKind(ErrorKind.CAPACITY_INSUFFICIENT,
                () -> ImageCryptProtocol.chooseCanvasSize(0, 100, 100));
        ImageCryptTestSupport.assertKind(ErrorKind.CAPACITY_INSUFFICIENT,
                () -> ImageCryptProtocol.chooseCanvasSize(-1, 100, 100));
    }

    /**
     * 恢复大小的上下界必须包住真实原文件长度。
     */
    @Test
    void metadataRestoredBoundsBracketOriginalLength() throws Exception {
        long originalLength = 123_456L;
        int descriptorLength = ImageCryptProtocol.INNER_MANIFEST_FIXED_LENGTH + 12;
        long payloadLength = descriptorLength + originalLength;
        ImageCryptMetadata metadata = new ImageCryptMetadata(ImageCryptProtocol.VERSION,
                ImageCryptMode.PUBLIC_RECOVERY, 64, 64, payloadLength, 100, 200, 0, 0, 0);

        assertTrue(metadata.maxRestoredBytes() >= originalLength, "上界必须覆盖原文件长度");
        assertTrue(metadata.minRestoredBytes() <= originalLength, "下界必须不超过原文件长度");
        assertEquals(ImageCryptProtocol.LIMIT_MANIFEST_BYTES
                        - ImageCryptProtocol.INNER_MANIFEST_FIXED_LENGTH,
                metadata.maxRestoredBytes() - metadata.minRestoredBytes(),
                "上下界之差必须等于描述区长度的可能范围");
        assertTrue(metadata.hasSourceSizeHint());
        assertFalse(metadata.requiresPassword());
    }
}
