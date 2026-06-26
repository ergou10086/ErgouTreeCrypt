package hbnu.project.ergoutreecrypt.encoding;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Random;

import org.junit.jupiter.api.Test;

/** 验证 {@link Padding} 的 PKCS#7（块大小 128）填充/去填充。 */
class PaddingTest {

    @Test
    void padNonMultiple() {
        byte[] data = new byte[100];
        new Random(1).nextBytes(data);
        byte[] padded = Padding.pad(data);
        assertEquals(128, padded.length);
        int padLen = 128 - 100; // 28
        for (int i = 100; i < 128; i++) {
            assertEquals((byte) padLen, padded[i]);
        }
        assertArrayEquals(data, Padding.unpad(padded));
    }

    @Test
    void padExactMultipleAddsFullBlock() {
        byte[] data = new byte[128];
        new Random(2).nextBytes(data);
        byte[] padded = Padding.pad(data);
        assertEquals(256, padded.length);
        for (int i = 128; i < 256; i++) {
            assertEquals((byte) 128, padded[i]);
        }
        // 整块填充时，末块为全 0x80（值 128）；unpad 该块应得到长度 0。
        byte[] lastBlock = java.util.Arrays.copyOfRange(padded, 128, 256);
        assertEquals(0, Padding.unpad(lastBlock).length);
    }

    @Test
    void padSmall() {
        byte[] data = { 1, 2, 3 };
        byte[] padded = Padding.pad(data);
        assertEquals(128, padded.length);
        assertArrayEquals(data, Padding.unpad(padded));
    }

    @Test
    void unpadTooShortReturnsAsIs() {
        byte[] data = { 1, 2, 3 };
        assertArrayEquals(data, Padding.unpad(data));
    }
}
