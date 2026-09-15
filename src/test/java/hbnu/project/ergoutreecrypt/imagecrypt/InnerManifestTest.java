package hbnu.project.ergoutreecrypt.imagecrypt;

import hbnu.project.ergoutreecrypt.exception.ErrorKind;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;

import static hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptTestSupport.assertKind;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link InnerManifest} 的编解码、边界与路径安全测试。
 *
 * <p>清单位于加密区，是唯一携带原始文件名的地方，因此除了常规往返，还着重验证
 * "写入侧严格拒绝路径、读取侧主动剥离路径"这条双向约束。
 *
 * @author ErgouTree
 * @since 2026/9/15
 */
final class InnerManifestTest {

    /**
     * 测试用原文件长度。
     */
    private static final long FILE_LENGTH = 123_456L;

    // ================================================================
    // 往返
    // ================================================================

    @Test
    void manifestRoundTripsWithUnicodeName() throws Exception {
        InnerManifest manifest = InnerManifest.create(ImageFormat.JPEG, FILE_LENGTH,
                "假期照片.jpg", "image/jpeg", "jpg", false);
        byte[] raw = manifest.toBytes();
        assertEquals(manifest.descriptorLength(), raw.length);

        InnerManifest parsed = InnerManifest.fromBytes(raw);
        assertEquals(ImageFormat.JPEG, parsed.format());
        assertEquals(FILE_LENGTH, parsed.originalFileLength());
        assertEquals("假期照片.jpg", parsed.originalName());
        assertEquals("image/jpeg", parsed.mediaType());
        assertEquals("jpg", parsed.extension());
        assertFalse(parsed.animated());
        assertTrue(parsed.safeBasename().contains("假期照片"));
    }

    @Test
    void manifestFallsBackToFormatDefaultsWhenOptionalFieldsAreBlank() throws Exception {
        InnerManifest manifest = InnerManifest.create(ImageFormat.WEBP, FILE_LENGTH,
                "", null, null, true);
        InnerManifest parsed = InnerManifest.fromBytes(manifest.toBytes());
        assertEquals("", parsed.originalName());
        assertEquals("image/webp", parsed.mediaType());
        assertEquals("webp", parsed.extension());
        assertTrue(parsed.animated());
        assertEquals("", parsed.safeBasename());
    }

    @Test
    void descriptorLengthExcludesTheOriginalFilePayload() throws Exception {
        InnerManifest manifest = InnerManifest.create(ImageFormat.PNG, FILE_LENGTH,
                "a.png", "image/png", "png", false);
        int nameBytes = "a.png".getBytes(StandardCharsets.UTF_8).length;
        assertEquals(ImageCryptProtocol.INNER_MANIFEST_FIXED_LENGTH + nameBytes
                + "image/png".length() + "png".length(), manifest.descriptorLength());
        assertEquals(manifest.descriptorLength() + FILE_LENGTH, manifest.totalLength());
    }

    @Test
    void explicitExtensionIsLowerCased() throws Exception {
        InnerManifest manifest = InnerManifest.create(ImageFormat.JPEG, FILE_LENGTH,
                "a.JPG", "image/jpeg", "JPG", false);
        assertEquals("jpg", manifest.extension());
    }

    // ================================================================
    // 写入侧：严格拒绝路径
    // ================================================================

    @Test
    void writeSideRejectsAnyPathComponent() {
        assertKind(ErrorKind.INTERNAL_ERROR, () -> InnerManifest.create(ImageFormat.PNG, 1,
                "../evil.png", "image/png", "png", false));
        assertKind(ErrorKind.INTERNAL_ERROR, () -> InnerManifest.create(ImageFormat.PNG, 1,
                "C:\\Users\\x\\evil.png", "image/png", "png", false));
        assertKind(ErrorKind.INTERNAL_ERROR, () -> InnerManifest.create(ImageFormat.PNG, 1,
                "sub/evil.png", "image/png", "png", false));
        assertKind(ErrorKind.INTERNAL_ERROR, () -> InnerManifest.create(ImageFormat.PNG, 1,
                "..", "image/png", "png", false));
    }

    @Test
    void writeSideRejectsNonCanonicalExtension() {
        assertKind(ErrorKind.INTERNAL_ERROR, () -> InnerManifest.create(ImageFormat.PNG, 1,
                "a.png", "image/png", "p n g", false));
        assertKind(ErrorKind.INTERNAL_ERROR, () -> InnerManifest.create(ImageFormat.PNG, 1,
                "a.png", "image/png", "p/g", false));
    }

    @Test
    void writeSideRejectsOverlongName() {
        String name = "x".repeat(ImageCryptProtocol.LIMIT_NAME_BYTES + 1) + ".png";
        assertKind(ErrorKind.INTERNAL_ERROR, () -> InnerManifest.create(ImageFormat.PNG, 1,
                name, "image/png", "png", false));
    }

    // ================================================================
    // 读取侧：主动剥离路径与非法字符
    // ================================================================

    @Test
    void readSideStripsDirectoriesAndDriveLetters() throws Exception {
        assertEquals("photo.jpg", manifestWithName("../tmp/photo.jpg").safeBasename());
        assertEquals("photo.jpg", manifestWithName("C:\\Users\\x\\photo.jpg").safeBasename());
        assertEquals("photo.jpg", manifestWithName("C:photo.jpg").safeBasename());
        assertEquals("passwd", manifestWithName("/etc/passwd").safeBasename());
    }

    @Test
    void readSideRemovesIllegalCharactersAndRejectsDots() throws Exception {
        assertEquals("ab.png", manifestWithName("a<b.png").safeBasename());
        assertEquals("", manifestWithName("..").safeBasename());
        assertEquals("", manifestWithName("....").safeBasename());
    }

    @Test
    void readSideGuardsWindowsReservedDeviceNames() throws Exception {
        assertEquals("_CON.png", manifestWithName("CON.png").safeBasename());
        assertEquals("_con.txt", manifestWithName("con.txt").safeBasename());
        assertEquals("console.txt", manifestWithName("console.txt").safeBasename());
    }

    // ================================================================
    // 读取侧：结构性拒绝
    // ================================================================

    @Test
    void truncatedManifestIsRejected() {
        assertKind(ErrorKind.INVALID_HEADER, () -> InnerManifest.fromBytes(new byte[10]));
        assertKind(ErrorKind.INVALID_HEADER, () -> InnerManifest.fromBytes(null));
    }

    @Test
    void wrongInnerMagicIsRejected() {
        byte[] raw = rawManifest(ImageFormat.PNG, FILE_LENGTH, "a.png", "image/png", "png",
                ImageCryptProtocol.INNER_FLAG_HAS_NAME);
        raw[0] = 'X';
        assertKind(ErrorKind.INVALID_HEADER, () -> InnerManifest.fromBytes(raw));
    }

    @Test
    void unknownInnerVersionIsRejected() {
        byte[] raw = rawManifest(ImageFormat.PNG, FILE_LENGTH, "a.png", "image/png", "png",
                ImageCryptProtocol.INNER_FLAG_HAS_NAME);
        raw[8] = 2;
        assertKind(ErrorKind.UNSUPPORTED_VERSION, () -> InnerManifest.fromBytes(raw));
    }

    @Test
    void unknownFormatIdIsRejected() {
        byte[] raw = rawManifest(ImageFormat.PNG, FILE_LENGTH, "a.png", "image/png", "png",
                ImageCryptProtocol.INNER_FLAG_HAS_NAME);
        raw[9] = 99;
        assertKind(ErrorKind.INVALID_HEADER, () -> InnerManifest.fromBytes(raw));
    }

    @Test
    void unknownInnerFlagsAreRejected() {
        byte[] raw = rawManifest(ImageFormat.PNG, FILE_LENGTH, "a.png", "image/png", "png",
                ImageCryptProtocol.INNER_FLAG_HAS_NAME | 0x80);
        assertKind(ErrorKind.INVALID_HEADER, () -> InnerManifest.fromBytes(raw));
    }

    @Test
    void inconsistentManifestLengthIsRejected() {
        byte[] raw = rawManifest(ImageFormat.PNG, FILE_LENGTH, "a.png", "image/png", "png",
                ImageCryptProtocol.INNER_FLAG_HAS_NAME);
        ByteBuffer.wrap(raw).order(ByteOrder.BIG_ENDIAN).putInt(12, raw.length + 4);
        assertKind(ErrorKind.INVALID_HEADER, () -> InnerManifest.fromBytes(raw));
    }

    @Test
    void declaredManifestLengthBeyondActualBytesIsRejected() {
        byte[] raw = new byte[ImageCryptProtocol.INNER_MANIFEST_FIXED_LENGTH];
        ByteBuffer buffer = ByteBuffer.wrap(raw).order(ByteOrder.BIG_ENDIAN);
        buffer.put(ImageCryptProtocol.INNER_MAGIC.getBytes(StandardCharsets.US_ASCII));
        buffer.put((byte) ImageCryptProtocol.INNER_VERSION);
        buffer.put((byte) ImageFormat.PNG.id());
        buffer.putShort((short) ImageCryptProtocol.INNER_FLAG_HAS_NAME);
        buffer.putInt(ImageCryptProtocol.INNER_MANIFEST_FIXED_LENGTH + 10);
        buffer.putLong(FILE_LENGTH);
        buffer.putShort((short) 10);
        assertKind(ErrorKind.INVALID_HEADER, () -> InnerManifest.fromBytes(raw));
    }

    @Test
    void nameFlagMustAgreeWithNameLength() {
        byte[] withoutFlag = rawManifest(ImageFormat.PNG, FILE_LENGTH, "a.png", "image/png", "png", 0);
        assertKind(ErrorKind.INVALID_HEADER, () -> InnerManifest.fromBytes(withoutFlag));

        byte[] withFlagNoName = rawManifest(ImageFormat.PNG, FILE_LENGTH, "", "image/png", "png",
                ImageCryptProtocol.INNER_FLAG_HAS_NAME);
        assertKind(ErrorKind.INVALID_HEADER, () -> InnerManifest.fromBytes(withFlagNoName));
    }

    @Test
    void invalidUtf8NameIsRejected() {
        byte[] raw = rawManifestRawName(ImageFormat.PNG, FILE_LENGTH,
                new byte[] {(byte) 0xc3, (byte) 0x28}, "image/png".getBytes(StandardCharsets.UTF_8),
                "png".getBytes(StandardCharsets.US_ASCII),
                ImageCryptProtocol.INNER_FLAG_HAS_NAME);
        assertKind(ErrorKind.INVALID_HEADER, () -> InnerManifest.fromBytes(raw));
    }

    @Test
    void nonCanonicalExtensionIsRejectedOnRead() {
        byte[] raw = rawManifest(ImageFormat.PNG, FILE_LENGTH, "a.png", "image/png", "PNG",
                ImageCryptProtocol.INNER_FLAG_HAS_NAME);
        assertKind(ErrorKind.INVALID_HEADER, () -> InnerManifest.fromBytes(raw));
    }

    @Test
    void overlongMimeIsRejectedOnRead() {
        byte[] raw = rawManifest(ImageFormat.PNG, FILE_LENGTH, "a.png",
                "m".repeat(ImageCryptProtocol.LIMIT_MIME_BYTES + 1), "png",
                ImageCryptProtocol.INNER_FLAG_HAS_NAME);
        assertKind(ErrorKind.INVALID_HEADER, () -> InnerManifest.fromBytes(raw));
    }

    @Test
    void leadingBomIsToleratedAndStripped() throws Exception {
        byte[] bom = {(byte) 0xEF, (byte) 0xBB, (byte) 0xBF};
        byte[] nameBytes = new byte[bom.length + 5];
        System.arraycopy(bom, 0, nameBytes, 0, bom.length);
        System.arraycopy("a.png".getBytes(StandardCharsets.UTF_8), 0, nameBytes, bom.length, 5);

        byte[] raw = rawManifestRawName(ImageFormat.PNG, FILE_LENGTH, nameBytes,
                "image/png".getBytes(StandardCharsets.UTF_8),
                "png".getBytes(StandardCharsets.US_ASCII),
                ImageCryptProtocol.INNER_FLAG_HAS_NAME);

        InnerManifest parsed = InnerManifest.fromBytes(raw);
        assertEquals("a.png", parsed.originalName());
    }

    // ================================================================
    // 夹具
    // ================================================================

    /**
     * 构造一份带指定文件名的清单并解析，用于验证读取侧的清洗行为。
     *
     * @param name 写入清单的文件名（可含路径成分）
     * @return 解析后的清单
     * @throws ImageCryptException 解析失败
     */
    private static InnerManifest manifestWithName(final String name) throws ImageCryptException {
        return InnerManifest.fromBytes(rawManifest(ImageFormat.PNG, FILE_LENGTH, name,
                "image/png", "png", ImageCryptProtocol.INNER_FLAG_HAS_NAME));
    }

    /**
     * 按字段拼装一份清单描述区。
     *
     * @param format     格式
     * @param fileLength 原文件长度
     * @param name       文件名
     * @param mime       MIME
     * @param extension  扩展名
     * @param flags      flags 位
     * @return 描述区字节
     */
    private static byte[] rawManifest(final ImageFormat format, final long fileLength,
                                      final String name, final String mime, final String extension,
                                      final int flags) {
        return rawManifestRawName(format, fileLength, name.getBytes(StandardCharsets.UTF_8),
                mime.getBytes(StandardCharsets.UTF_8),
                extension.getBytes(StandardCharsets.US_ASCII), flags);
    }

    /**
     * 按原始字节拼装清单描述区，允许注入非法 UTF-8。
     *
     * @param format      格式
     * @param fileLength  原文件长度
     * @param nameBytes   文件名字节
     * @param mimeBytes   MIME 字节
     * @param extensionBytes 扩展名字节
     * @param flags       flags 位
     * @return 描述区字节
     */
    private static byte[] rawManifestRawName(final ImageFormat format, final long fileLength,
                                             final byte[] nameBytes, final byte[] mimeBytes,
                                             final byte[] extensionBytes, final int flags) {
        int length = ImageCryptProtocol.INNER_MANIFEST_FIXED_LENGTH
                + nameBytes.length + mimeBytes.length + extensionBytes.length;
        ByteBuffer buffer = ByteBuffer.allocate(length).order(ByteOrder.BIG_ENDIAN);
        buffer.put(ImageCryptProtocol.INNER_MAGIC.getBytes(StandardCharsets.US_ASCII));
        buffer.put((byte) ImageCryptProtocol.INNER_VERSION);
        buffer.put((byte) format.id());
        buffer.putShort((short) flags);
        buffer.putInt(length);
        buffer.putLong(fileLength);
        buffer.putShort((short) nameBytes.length);
        buffer.put((byte) mimeBytes.length);
        buffer.put((byte) extensionBytes.length);
        buffer.put(nameBytes);
        buffer.put(mimeBytes);
        buffer.put(extensionBytes);
        return buffer.array();
    }
}
