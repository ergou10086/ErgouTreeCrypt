package hbnu.project.ergoutreecrypt.imagecrypt;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link ImageCryptProtocol} 的冻结常量自检。
 *
 * <p>这些断言的作用是"防止有人在重构中悄悄改动偏移"，它们本身就是协议冻结的一部分：
 * 任何一条失败都说明 v1 契约被破坏，而不是说明测试需要更新。
 *
 * @author ErgouTree
 * @since 2026/9/15
 */
final class ImageCryptProtocolTest {

    /**
     * 头部各字段必须首尾相接、不重叠，并恰好占满 184 字节。
     */
    @Test
    void headerFieldsTileExactlyOneHundredEightyFourBytes() {
        int[][] layout = {
                {ImageCryptProtocol.OFF_MAGIC, 8},
                {ImageCryptProtocol.OFF_VERSION, 1},
                {ImageCryptProtocol.OFF_PROTECTION_MODE, 1},
                {ImageCryptProtocol.OFF_CIPHER_ID, 1},
                {ImageCryptProtocol.OFF_MAC_ID, 1},
                {ImageCryptProtocol.OFF_KDF_ID, 1},
                {ImageCryptProtocol.OFF_FLAGS, 1},
                {ImageCryptProtocol.OFF_HEADER_LENGTH, 2},
                {ImageCryptProtocol.OFF_CANVAS_WIDTH, 4},
                {ImageCryptProtocol.OFF_CANVAS_HEIGHT, 4},
                {ImageCryptProtocol.OFF_INNER_PLAIN_LENGTH, 8},
                {ImageCryptProtocol.OFF_CIPHERTEXT_LENGTH, 8},
                {ImageCryptProtocol.OFF_SOURCE_WIDTH_HINT, 4},
                {ImageCryptProtocol.OFF_SOURCE_HEIGHT_HINT, 4},
                {ImageCryptProtocol.OFF_ARGON2_MEMORY_KIB, 4},
                {ImageCryptProtocol.OFF_ARGON2_PASSES, 4},
                {ImageCryptProtocol.OFF_ARGON2_LANES, 2},
                {ImageCryptProtocol.OFF_RESERVED, 2},
                {ImageCryptProtocol.OFF_ARGON2_SALT, ImageCryptProtocol.ARGON2_SALT_LENGTH},
                {ImageCryptProtocol.OFF_HKDF_SALT, ImageCryptProtocol.HKDF_SALT_LENGTH},
                {ImageCryptProtocol.OFF_NONCE, ImageCryptProtocol.NONCE_LENGTH},
                {ImageCryptProtocol.OFF_EMBEDDED_MASTER_KEY, ImageCryptProtocol.MASTER_KEY_LENGTH},
                {ImageCryptProtocol.OFF_KEY_CONFIRM, ImageCryptProtocol.KEY_CONFIRM_LENGTH},
                {ImageCryptProtocol.OFF_HEADER_CRC32, 4}
        };
        int cursor = 0;
        for (int[] field : layout) {
            assertEquals(cursor, field[0], "字段偏移不连续");
            cursor += field[1];
        }
        assertEquals(ImageCryptProtocol.OUTER_HEADER_LENGTH, cursor, "头部总长必须是 184 字节");
    }

    /**
     * 协议头长度必须等于 184，且 keyConfirm 恰好在其前一个字段结束处开始。
     */
    @Test
    void frozenHeaderGeometryMatchesSpecification() {
        assertEquals(184, ImageCryptProtocol.OUTER_HEADER_LENGTH);
        assertEquals(180, ImageCryptProtocol.MAC_COVERED_HEADER_LENGTH);
        assertEquals(164, ImageCryptProtocol.KEY_CONFIRM_COVERED_HEADER_LENGTH);
        assertEquals(ImageCryptProtocol.OFF_KEY_CONFIRM, ImageCryptProtocol.KEY_CONFIRM_COVERED_HEADER_LENGTH);
        assertEquals(ImageCryptProtocol.OFF_HEADER_CRC32, ImageCryptProtocol.MAC_COVERED_HEADER_LENGTH);
    }

    /**
     * 协议常数中的长度字段必须自洽。
     */
    @Test
    void declaredLengthsAreSelfConsistent() {
        assertEquals(64, ImageCryptProtocol.AUTH_TAG_LENGTH);
        assertEquals(ImageCryptProtocol.ENC_KEY_LENGTH + ImageCryptProtocol.MAC_KEY_LENGTH,
                ImageCryptProtocol.KEY_MATERIAL_LENGTH);
        assertEquals(8, ImageCryptProtocol.MAGIC.length());
        assertEquals(8, ImageCryptProtocol.INNER_MAGIC.length());
        assertEquals(15, ImageCryptProtocol.MAC_CONTEXT.length());
        assertEquals(21, ImageCryptProtocol.KEY_CHECK_CONTEXT.length());
        assertEquals("ErgouTreeCrypt/EGTC-IMG/v1", ImageCryptProtocol.HKDF_INFO);
        assertEquals(ImageCryptProtocol.INNER_MANIFEST_FIXED_LENGTH,
                8 + 1 + 1 + 2 + 4 + 8 + 2 + 1 + 1);
    }

    /**
     * v1 密码模式必须固定为 RFC 9106 的移动端互操作档。
     */
    @Test
    void argon2InteropProfileIsFrozen() {
        assertEquals(65_536, ImageCryptProtocol.ARGON2_MEMORY_KIB);
        assertEquals(3, ImageCryptProtocol.ARGON2_PASSES);
        assertEquals(4, ImageCryptProtocol.ARGON2_LANES);
        assertEquals(32, ImageCryptProtocol.ARGON2_OUTPUT_LENGTH);
    }

    /**
     * 画布容量计算必须带溢出保护，伪造的荒谬尺寸不得回绕成"容量充足"。
     */
    @Test
    void canvasCapacityRejectsOverflowAndIllegalSides() {
        assertEquals(3L * 64 * 64, ImageCryptProtocol.canvasCapacity(64, 64));
        assertEquals(0L, ImageCryptProtocol.canvasCapacity(0, 100));
        assertEquals(0L, ImageCryptProtocol.canvasCapacity(-1, 100));
        assertEquals(0L, ImageCryptProtocol.canvasCapacity(8193, 10));
        assertEquals(0L, ImageCryptProtocol.canvasCapacity(Integer.MAX_VALUE, Integer.MAX_VALUE));
        assertTrue(ImageCryptProtocol.isCanvasSideValid(1, 8192));
        assertTrue(ImageCryptProtocol.isCanvasSideValid(8192, 1));
        assertFalse(ImageCryptProtocol.isCanvasSideValid(0, 10));
        assertFalse(ImageCryptProtocol.isCanvasSideValid(10, 8193));
    }

    /**
     * 所需像素数按 3 字节/像素向上取整，并在溢出时返回 -1。
     */
    @Test
    void requiredPixelsRoundsUpAndGuardsOverflow() {
        assertEquals((184L + 64 + 2) / 3, ImageCryptProtocol.requiredPixels(0));
        assertEquals((184L + 3 + 64 + 2) / 3, ImageCryptProtocol.requiredPixels(3));
        assertEquals(-1L, ImageCryptProtocol.requiredPixels(-1));
        assertEquals(-1L, ImageCryptProtocol.requiredPixels(Long.MAX_VALUE));
    }

    /**
     * 魔数比较只接受逐字节相等的 ASCII 序列。
     */
    @Test
    void magicComparisonIsExact() {
        byte[] data = "xxEGTC-IMGyy".getBytes(StandardCharsets.US_ASCII);
        assertTrue(ImageCryptProtocol.hasMagicAt(data, 2));
        assertFalse(ImageCryptProtocol.hasMagicAt(data, 0));
        assertFalse(ImageCryptProtocol.hasMagicAt(data, 5));
        assertFalse(ImageCryptProtocol.hasMagicAt(data, -1));
        assertFalse(ImageCryptProtocol.hasMagicAt(null, 0));
        assertFalse(ImageCryptProtocol.hasMagicAt(new byte[3], 0));
    }
}
