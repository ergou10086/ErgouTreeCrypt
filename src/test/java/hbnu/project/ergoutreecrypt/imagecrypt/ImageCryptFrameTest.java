package hbnu.project.ergoutreecrypt.imagecrypt;

import hbnu.project.ergoutreecrypt.exception.ErrorKind;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptTestSupport.assertKind;
import static hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptTestSupport.hex;
import static hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptTestSupport.refreshCrc32;
import static hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptTestSupport.rewriteByte;
import static hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptTestSupport.rewriteField;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link ImageCryptFrame} 的编解码与字段边界测试。
 *
 * <p>覆盖每个字段的合法/非法取值、未知 version/ID/flag、头 CRC 错误、非规范 KDF 组合与
 * 画布容量越界。篡改一律通过 {@code rewriteField}/{@code rewriteByte} 重算 CRC，使每个
 * 用例只隔离一个缺陷，不依赖校验顺序的偶然性。
 *
 * @author ErgouTree
 * @since 2026/9/15
 */
final class ImageCryptFrameTest {

    /**
     * 测试用载荷长度。
     */
    private static final long PAYLOAD_LENGTH = 300L;

    /**
     * 测试用画布边长。
     */
    private static final int CANVAS_SIDE = 64;

    /**
     * 测试用原图宽度提示。
     */
    private static final int SOURCE_WIDTH = 1280;

    /**
     * 测试用原图高度提示。
     */
    private static final int SOURCE_HEIGHT = 720;

    // ================================================================
    // 往返
    // ================================================================

    @Test
    void publicFrameRoundTripsThroughBytes() throws Exception {
        ImageCryptFrame frame = publicFrame();
        byte[] raw = frame.toBytes();
        assertEquals(ImageCryptProtocol.OUTER_HEADER_LENGTH, raw.length);

        ImageCryptFrame parsed = ImageCryptFrame.fromBytes(raw);
        assertEquals(ImageCryptMode.PUBLIC_RECOVERY, parsed.protectionMode());
        assertEquals(ImageCryptProtocol.KDF_ID_EMBEDDED_MASTER_KEY, parsed.kdfId());
        assertEquals(ImageCryptProtocol.CIPHER_ID_XCHACHA20, parsed.cipherId());
        assertEquals(ImageCryptProtocol.MAC_ID_BLAKE2B_KEYED, parsed.macId());
        assertEquals(CANVAS_SIDE, parsed.canvasWidth());
        assertEquals(CANVAS_SIDE, parsed.canvasHeight());
        assertEquals(PAYLOAD_LENGTH, parsed.innerPlainLength());
        assertEquals(PAYLOAD_LENGTH, parsed.ciphertextLength());
        assertEquals(SOURCE_WIDTH, parsed.sourceWidthHint());
        assertEquals(SOURCE_HEIGHT, parsed.sourceHeightHint());
        assertEquals(0, parsed.argon2MemoryKiB());
        assertEquals(0, parsed.argon2Passes());
        assertEquals(0, parsed.argon2Lanes());
        assertArrayEquals(frame.hkdfSalt(), parsed.hkdfSalt());
        assertArrayEquals(frame.nonce(), parsed.nonce());
        assertArrayEquals(frame.embeddedMasterKey(), parsed.embeddedMasterKey());
        assertArrayEquals(frame.keyConfirm(), parsed.keyConfirm());
    }

    @Test
    void passwordFrameRoundTripsThroughBytes() throws Exception {
        ImageCryptFrame frame = passwordFrame();
        ImageCryptFrame parsed = ImageCryptFrame.fromBytes(frame.toBytes());

        assertEquals(ImageCryptMode.PASSWORD, parsed.protectionMode());
        assertEquals(ImageCryptProtocol.KDF_ID_ARGON2ID, parsed.kdfId());
        assertEquals(ImageCryptProtocol.ARGON2_MEMORY_KIB, parsed.argon2MemoryKiB());
        assertEquals(ImageCryptProtocol.ARGON2_PASSES, parsed.argon2Passes());
        assertEquals(ImageCryptProtocol.ARGON2_LANES, parsed.argon2Lanes());
        assertArrayEquals(frame.argon2Salt(), parsed.argon2Salt());
        assertArrayEquals(frame.keyConfirm(), parsed.keyConfirm());
    }

    // ================================================================
    // 结构与标识校验
    // ================================================================

    @Test
    void wrongHeaderLengthIsRejected() {
        assertKind(ErrorKind.INVALID_HEADER, () -> ImageCryptFrame.fromBytes(new byte[183]));
        assertKind(ErrorKind.INVALID_HEADER, () -> ImageCryptFrame.fromBytes(null));
    }

    @Test
    void missingMagicIsReportedAsNotImageCrypt() {
        byte[] raw = rewriteByte(publicBytes(), ImageCryptProtocol.OFF_MAGIC, 'X');
        assertKind(ErrorKind.NOT_IMAGE_CRYPT, () -> ImageCryptFrame.fromBytes(raw));
    }

    @Test
    void unknownVersionIsRejected() {
        byte[] raw = rewriteByte(publicBytes(), ImageCryptProtocol.OFF_VERSION, 2);
        assertKind(ErrorKind.UNSUPPORTED_VERSION, () -> ImageCryptFrame.fromBytes(raw));
    }

    @Test
    void unknownProtectionModeCipherAndMacIdsAreRejected() {
        assertKind(ErrorKind.INVALID_HEADER, () -> ImageCryptFrame.fromBytes(
                rewriteByte(publicBytes(), ImageCryptProtocol.OFF_PROTECTION_MODE, 7)));
        assertKind(ErrorKind.INVALID_HEADER, () -> ImageCryptFrame.fromBytes(
                rewriteByte(publicBytes(), ImageCryptProtocol.OFF_CIPHER_ID, 9)));
        assertKind(ErrorKind.INVALID_HEADER, () -> ImageCryptFrame.fromBytes(
                rewriteByte(publicBytes(), ImageCryptProtocol.OFF_MAC_ID, 9)));
    }

    @Test
    void kdfIdMustMatchProtectionMode() throws Exception {
        byte[] publicRaw = rewriteByte(publicBytes(), ImageCryptProtocol.OFF_KDF_ID,
                ImageCryptProtocol.KDF_ID_ARGON2ID);
        assertKind(ErrorKind.INVALID_HEADER, () -> ImageCryptFrame.fromBytes(publicRaw));

        byte[] passwordRaw = rewriteByte(passwordBytes(), ImageCryptProtocol.OFF_KDF_ID,
                ImageCryptProtocol.KDF_ID_EMBEDDED_MASTER_KEY);
        assertKind(ErrorKind.INVALID_HEADER, () -> ImageCryptFrame.fromBytes(passwordRaw));
    }

    @Test
    void unknownFlagBitsAreRejected() {
        byte[] raw = rewriteByte(publicBytes(), ImageCryptProtocol.OFF_FLAGS, 0x80);
        assertKind(ErrorKind.INVALID_HEADER, () -> ImageCryptFrame.fromBytes(raw));
    }

    @Test
    void v1HeaderMustCarryKeyConfirmFlag() {
        byte[] raw = rewriteByte(publicBytes(), ImageCryptProtocol.OFF_FLAGS,
                ImageCryptProtocol.FLAG_SOURCE_SIZE_HINT);
        assertKind(ErrorKind.INVALID_HEADER, () -> ImageCryptFrame.fromBytes(raw));
    }

    @Test
    void declaredHeaderLengthFieldMustBeFrozenValue() {
        byte[] raw = rewriteField(publicBytes(), ImageCryptProtocol.OFF_HEADER_LENGTH, 200, 2);
        assertKind(ErrorKind.INVALID_HEADER, () -> ImageCryptFrame.fromBytes(raw));
    }

    @Test
    void reservedFieldMustBeZero() {
        byte[] raw = rewriteField(publicBytes(), ImageCryptProtocol.OFF_RESERVED, 1, 2);
        assertKind(ErrorKind.INVALID_HEADER, () -> ImageCryptFrame.fromBytes(raw));
    }

    @Test
    void corruptedCrcIsDetectedBeforeAnyKeyWork() throws Exception {
        byte[] raw = publicBytes();
        raw[ImageCryptProtocol.OFF_HEADER_CRC32 + 3] ^= 0x01;
        assertKind(ErrorKind.INVALID_HEADER, () -> ImageCryptFrame.fromBytes(raw));
    }

    // ================================================================
    // KDF 字段的规范组合
    // ================================================================

    @Test
    void publicModeRejectsAnyArgon2Field() {
        byte[] withPasses = rewriteField(publicBytes(), ImageCryptProtocol.OFF_ARGON2_PASSES, 3, 4);
        assertKind(ErrorKind.INVALID_HEADER, () -> ImageCryptFrame.fromBytes(withPasses));

        byte[] withSalt = publicBytes();
        withSalt[ImageCryptProtocol.OFF_ARGON2_SALT] = 1;
        refreshCrc32(withSalt);
        assertKind(ErrorKind.INVALID_HEADER, () -> ImageCryptFrame.fromBytes(withSalt));
    }

    @Test
    void passwordModeOnlyAcceptsTheCrossPlatformArgon2Profile() {
        byte[] doubled = rewriteField(passwordBytes(), ImageCryptProtocol.OFF_ARGON2_MEMORY_KIB,
                ImageCryptProtocol.ARGON2_MEMORY_KIB * 2L, 4);
        assertKind(ErrorKind.INVALID_HEADER, () -> ImageCryptFrame.fromBytes(doubled));

        byte[] weakened = rewriteField(passwordBytes(), ImageCryptProtocol.OFF_ARGON2_PASSES, 1, 4);
        assertKind(ErrorKind.INVALID_HEADER, () -> ImageCryptFrame.fromBytes(weakened));

        byte[] singleLane = rewriteField(passwordBytes(), ImageCryptProtocol.OFF_ARGON2_LANES, 1, 2);
        assertKind(ErrorKind.INVALID_HEADER, () -> ImageCryptFrame.fromBytes(singleLane));
    }

    @Test
    void passwordModeMustNotCarryAnEmbeddedMasterKey() {
        byte[] raw = rewriteByte(passwordBytes(), ImageCryptProtocol.OFF_EMBEDDED_MASTER_KEY, 1);
        assertKind(ErrorKind.INVALID_HEADER, () -> ImageCryptFrame.fromBytes(raw));
    }

    @Test
    void publicModeMustNotCarryAnAllZeroMasterKey() {
        byte[] master = new byte[ImageCryptProtocol.MASTER_KEY_LENGTH];
        assertKind(ErrorKind.INTERNAL_ERROR, () -> ImageCryptFrame.newPublicFrame(CANVAS_SIDE,
                CANVAS_SIDE, 0, 0, 0, new byte[ImageCryptProtocol.HKDF_SALT_LENGTH],
                new byte[ImageCryptProtocol.NONCE_LENGTH], master));
    }

    // ================================================================
    // 画布与容量
    // ================================================================

    @Test
    void canvasSidesAreBounded() {
        assertKind(ErrorKind.INVALID_HEADER, () -> ImageCryptFrame.fromBytes(
                rewriteField(publicBytes(), ImageCryptProtocol.OFF_CANVAS_WIDTH, 0, 4)));
        assertKind(ErrorKind.INVALID_HEADER, () -> ImageCryptFrame.fromBytes(
                rewriteField(publicBytes(), ImageCryptProtocol.OFF_CANVAS_HEIGHT, 0, 4)));
        assertKind(ErrorKind.INVALID_HEADER, () -> ImageCryptFrame.fromBytes(
                rewriteField(publicBytes(), ImageCryptProtocol.OFF_CANVAS_WIDTH,
                        ImageCryptProtocol.LIMIT_CANVAS_SIDE + 1L, 4)));
    }

    @Test
    void payloadMustFitInsideTheDeclaredCanvas() {
        byte[] oversized = rewriteField(publicBytes(),
                ImageCryptProtocol.OFF_INNER_PLAIN_LENGTH, 1_000_000L, 8);
        byte[] both = rewriteField(oversized, ImageCryptProtocol.OFF_CIPHERTEXT_LENGTH,
                1_000_000L, 8);
        assertKind(ErrorKind.INVALID_HEADER, () -> ImageCryptFrame.fromBytes(both));
    }

    @Test
    void ciphertextLengthMustEqualInnerPlainLengthInV1() {
        byte[] raw = rewriteField(publicBytes(), ImageCryptProtocol.OFF_CIPHERTEXT_LENGTH, 1, 8);
        assertKind(ErrorKind.INVALID_HEADER, () -> ImageCryptFrame.fromBytes(raw));
    }

    @Test
    void negativeLengthsAreRejected() {
        byte[] inner = rewriteField(publicBytes(), ImageCryptProtocol.OFF_INNER_PLAIN_LENGTH, -1L, 8);
        byte[] both = rewriteField(inner, ImageCryptProtocol.OFF_CIPHERTEXT_LENGTH, -1L, 8);
        assertKind(ErrorKind.INVALID_HEADER, () -> ImageCryptFrame.fromBytes(both));
    }

    // ================================================================
    // 尺寸提示一致性
    // ================================================================

    @Test
    void sizeHintsMustAgreeWithTheirFlag() {
        byte[] flagCleared = rewriteByte(publicBytes(), ImageCryptProtocol.OFF_FLAGS,
                ImageCryptProtocol.FLAG_KEY_CONFIRM);
        assertKind(ErrorKind.INVALID_HEADER, () -> ImageCryptFrame.fromBytes(flagCleared));

        byte[] hintCleared = rewriteField(publicBytes(), ImageCryptProtocol.OFF_SOURCE_WIDTH_HINT, 0, 4);
        assertKind(ErrorKind.INVALID_HEADER, () -> ImageCryptFrame.fromBytes(hintCleared));
    }

    @Test
    void unknownSourceSizeOmitsTheHintFlagEntirely() throws Exception {
        ImageCryptFrame frame = ImageCryptFrame.newPublicFrame(CANVAS_SIDE, CANVAS_SIDE,
                PAYLOAD_LENGTH, 0, 0, new byte[ImageCryptProtocol.HKDF_SALT_LENGTH],
                new byte[ImageCryptProtocol.NONCE_LENGTH], filled(ImageCryptProtocol.MASTER_KEY_LENGTH));
        ImageCryptFrame parsed = ImageCryptFrame.fromBytes(
                frame.withKeyConfirm(new byte[ImageCryptProtocol.KEY_CONFIRM_LENGTH]).toBytes());
        assertEquals(0, parsed.sourceWidthHint());
        assertEquals(0, parsed.sourceHeightHint());
        assertEquals(ImageCryptProtocol.FLAG_KEY_CONFIRM, parsed.flags());
    }

    // ================================================================
    // 认证输入构造
    // ================================================================

    @Test
    void authenticationPrefixesCoverTheSpecifiedRanges() throws Exception {
        ImageCryptFrame frame = publicFrame();
        byte[] keyConfirmPrefix = frame.keyConfirmPrefixBytes();
        byte[] authPrefix = frame.authenticationPrefixBytes();
        byte[] serialized = frame.toBytes();

        assertEquals(ImageCryptProtocol.KEY_CONFIRM_COVERED_HEADER_LENGTH, keyConfirmPrefix.length);
        assertEquals(ImageCryptProtocol.MAC_COVERED_HEADER_LENGTH, authPrefix.length);
        assertArrayEquals(keyConfirmPrefix, Arrays.copyOf(authPrefix, keyConfirmPrefix.length));
        assertArrayEquals(authPrefix, Arrays.copyOf(serialized, authPrefix.length));
    }

    @Test
    void keyConfirmLiesOutsideItsOwnInputPrefix() throws Exception {
        ImageCryptFrame frame = publicFrame();
        byte[] otherConfirm = new byte[ImageCryptProtocol.KEY_CONFIRM_LENGTH];
        Arrays.fill(otherConfirm, (byte) 0x11);
        ImageCryptFrame mutated = frame.withKeyConfirm(otherConfirm);
        assertArrayEquals(frame.keyConfirmPrefixBytes(), mutated.keyConfirmPrefixBytes(),
                "keyConfirm 覆盖范围 [0,164) 不应包含 keyConfirm 自身");
        assertFalse(Arrays.equals(frame.authenticationPrefixBytes(),
                mutated.authenticationPrefixBytes()),
                "keyConfirm 位于 [164,180)，必须进入完整认证标签的覆盖范围");
    }

    @Test
    void headerCrc32LiesOutsideTheAuthenticationPrefix() throws Exception {
        byte[] reference = publicBytes();
        byte[] tampered = reference.clone();
        tampered[ImageCryptProtocol.OFF_HEADER_CRC32 + 3] ^= 0x7f;
        assertArrayEquals(
                Arrays.copyOf(reference, ImageCryptProtocol.MAC_COVERED_HEADER_LENGTH),
                Arrays.copyOf(tampered, ImageCryptProtocol.MAC_COVERED_HEADER_LENGTH),
                "headerCrc32 不参与 MAC，改变它不应影响认证前缀");
    }

    // ================================================================
    // 其他
    // ================================================================

    @Test
    void writingWithoutKeyConfirmFails() throws Exception {
        ImageCryptFrame frame = ImageCryptFrame.newPublicFrame(CANVAS_SIDE, CANVAS_SIDE,
                PAYLOAD_LENGTH, SOURCE_WIDTH, SOURCE_HEIGHT,
                new byte[ImageCryptProtocol.HKDF_SALT_LENGTH],
                new byte[ImageCryptProtocol.NONCE_LENGTH], filled(ImageCryptProtocol.MASTER_KEY_LENGTH));
        assertKind(ErrorKind.INTERNAL_ERROR, frame::toBytes);
    }

    @Test
    void diagnosticTextDoesNotLeakKeyMaterial() throws Exception {
        ImageCryptFrame frame = publicFrame();
        String text = frame.toString();
        assertFalse(text.contains(hex(frame.nonce())));
        assertFalse(text.contains(hex(frame.embeddedMasterKey())));
        assertFalse(text.contains(hex(frame.hkdfSalt())));
        assertTrue(text.contains("canvas=64x64"));
    }

    @Test
    void constructorRejectsWrongSizedSecrets() {
        assertKind(ErrorKind.INTERNAL_ERROR, () -> ImageCryptFrame.newPublicFrame(CANVAS_SIDE,
                CANVAS_SIDE, 0, 0, 0, new byte[31], new byte[ImageCryptProtocol.NONCE_LENGTH],
                filled(ImageCryptProtocol.MASTER_KEY_LENGTH)));
        assertKind(ErrorKind.INTERNAL_ERROR, () -> ImageCryptFrame.newPublicFrame(CANVAS_SIDE,
                CANVAS_SIDE, 0, 0, 0, new byte[ImageCryptProtocol.HKDF_SALT_LENGTH], new byte[23],
                filled(ImageCryptProtocol.MASTER_KEY_LENGTH)));
        assertKind(ErrorKind.INTERNAL_ERROR, () -> ImageCryptFrame.newPublicFrame(CANVAS_SIDE,
                CANVAS_SIDE, 0, 0, 0, new byte[ImageCryptProtocol.HKDF_SALT_LENGTH],
                new byte[ImageCryptProtocol.NONCE_LENGTH], new byte[31]));
    }

    @Test
    void modeIdsAreStableAndRejectUnknownValues() {
        assertEquals(0, ImageCryptMode.PUBLIC_RECOVERY.id());
        assertEquals(1, ImageCryptMode.PASSWORD.id());
        assertTrue(ImageCryptMode.isKnownId(0));
        assertTrue(ImageCryptMode.isKnownId(1));
        assertFalse(ImageCryptMode.isKnownId(2));
        assertThrows(IllegalArgumentException.class, () -> ImageCryptMode.fromId(2));
    }

    // ================================================================
    // 夹具
    // ================================================================

    /**
     * 构造一个合法的公开恢复协议头。
     *
     * @return 已写入 keyConfirm 的协议头
     * @throws ImageCryptException 构造失败
     */
    private static ImageCryptFrame publicFrame() throws ImageCryptException {
        return ImageCryptFrame.newPublicFrame(CANVAS_SIDE, CANVAS_SIDE, PAYLOAD_LENGTH,
                        SOURCE_WIDTH, SOURCE_HEIGHT,
                        new byte[ImageCryptProtocol.HKDF_SALT_LENGTH],
                        new byte[ImageCryptProtocol.NONCE_LENGTH],
                        filled(ImageCryptProtocol.MASTER_KEY_LENGTH))
                .withKeyConfirm(filled(ImageCryptProtocol.KEY_CONFIRM_LENGTH));
    }

    /**
     * 构造一个合法的密码保护协议头。
     *
     * @return 已写入 keyConfirm 的协议头
     * @throws ImageCryptException 构造失败
     */
    private static ImageCryptFrame passwordFrame() throws ImageCryptException {
        byte[] salt = new byte[ImageCryptProtocol.ARGON2_SALT_LENGTH];
        salt[0] = 7;
        return ImageCryptFrame.newPasswordFrame(CANVAS_SIDE, CANVAS_SIDE, PAYLOAD_LENGTH,
                        SOURCE_WIDTH, SOURCE_HEIGHT, salt,
                        new byte[ImageCryptProtocol.HKDF_SALT_LENGTH],
                        new byte[ImageCryptProtocol.NONCE_LENGTH])
                .withKeyConfirm(filled(ImageCryptProtocol.KEY_CONFIRM_LENGTH));
    }

    /**
     * 返回公开恢复协议头的字节形式。
     *
     * @return 协议头字节
     */
    private static byte[] publicBytes() {
        try {
            return publicFrame().toBytes();
        } catch (ImageCryptException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * 返回密码保护协议头的字节形式。
     *
     * @return 协议头字节
     */
    private static byte[] passwordBytes() {
        try {
            return passwordFrame().toBytes();
        } catch (ImageCryptException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * 生成指定长度的非零填充字节。
     *
     * @param length 长度
     * @return 填充数组
     */
    private static byte[] filled(final int length) {
        byte[] out = new byte[length];
        Arrays.fill(out, (byte) 0x5a);
        return out;
    }
}
