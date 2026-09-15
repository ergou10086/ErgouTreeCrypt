package hbnu.project.ergoutreecrypt.imagecrypt;

import hbnu.project.ergoutreecrypt.exception.ErrorKind;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptTestSupport.assertKind;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

/**
 * {@link ImageCryptPassword} 的规范化口径测试。
 *
 * <p>这些断言是跨端互操作的前提：只要两端都调用本入口，组合字符与平台默认编码差异
 * 就不会导致同一口令派生出两把密钥。
 *
 * @author ErgouTree
 * @since 2026/9/15
 */
final class ImageCryptPasswordTest {

    /**
     * NFC 形式的 {@code café}（é 为单个码点 U+00E9）。
     */
    private static final String COMPOSED = "café";

    /**
     * NFD 形式的 {@code café}（e + 组合尖音符 U+0301），与 {@link #COMPOSED} 视觉相同、字节不同。
     */
    private static final String DECOMPOSED = "café";

    /**
     * 圈号数字一（U+2460），用于证明未做 NFKC 兼容归一。
     */
    private static final String CIRCLED_ONE = "①";

    @Test
    void asciiPasswordEncodesAsUtf8() throws Exception {
        byte[] encoded = ImageCryptPassword.encodeForV1("hunter2");
        assertArrayEquals("hunter2".getBytes(StandardCharsets.UTF_8), encoded);
    }

    @Test
    void composedAndDecomposedFormsCollapseToTheSameBytes() throws Exception {
        assertNotEquals(COMPOSED, DECOMPOSED, "两个字符串在 Java 层面必须不同");
        assertArrayEquals(ImageCryptPassword.encodeForV1(COMPOSED),
                ImageCryptPassword.encodeForV1(DECOMPOSED));
    }

    @Test
    void normalizationIsNfcNotNfkc() throws Exception {
        // NFKC 会把圈号数字折叠成普通数字，从而降低口令熵；v1 明确不做兼容归一。
        byte[] encoded = ImageCryptPassword.encodeForV1(CIRCLED_ONE);
        assertArrayEquals(CIRCLED_ONE.getBytes(StandardCharsets.UTF_8), encoded);
        assertNotEquals("1", new String(encoded, StandardCharsets.UTF_8));
    }

    @Test
    void passwordIsNotTrimmedOrCaseFolded() throws Exception {
        assertArrayEquals(" a B ".getBytes(StandardCharsets.UTF_8),
                ImageCryptPassword.encodeForV1(" a B "));
        assertNotEquals(new String(ImageCryptPassword.encodeForV1("ABC"), StandardCharsets.UTF_8),
                new String(ImageCryptPassword.encodeForV1("abc"), StandardCharsets.UTF_8));
    }

    @Test
    void emptyPasswordIsRejectedSoCallersUsePublicMode() {
        assertKind(ErrorKind.INTERNAL_ERROR, () -> ImageCryptPassword.encodeForV1(""));
        assertKind(ErrorKind.INTERNAL_ERROR, () -> ImageCryptPassword.encodeForV1(null));
    }

    @Test
    void malformedUnicodeIsRejectedInsteadOfBeingReplaced() {
        String unpairedSurrogate = "abc\uD800def";
        assertKind(ErrorKind.INTERNAL_ERROR,
                () -> ImageCryptPassword.encodeForV1(unpairedSurrogate));
    }

    @Test
    void overlongPasswordIsRejected() {
        String huge = "x".repeat(ImageCryptProtocol.LIMIT_PASSWORD_BYTES + 1);
        assertKind(ErrorKind.INTERNAL_ERROR, () -> ImageCryptPassword.encodeForV1(huge));
    }

    @Test
    void passwordAtTheLimitIsAccepted() throws Exception {
        String atLimit = "é".repeat(ImageCryptProtocol.LIMIT_PASSWORD_BYTES / 2);
        byte[] encoded = ImageCryptPassword.encodeForV1(atLimit);
        assertEquals(ImageCryptProtocol.LIMIT_PASSWORD_BYTES, encoded.length);
    }
}
