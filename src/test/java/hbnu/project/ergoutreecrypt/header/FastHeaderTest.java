package hbnu.project.ergoutreecrypt.header;

import hbnu.project.ergoutreecrypt.exception.CryptoException;
import org.junit.jupiter.api.Test;
import java.io.ByteArrayInputStream;
import java.nio.ByteBuffer;
import java.util.Arrays;
import static org.junit.jupiter.api.Assertions.*;

/** 固定头的字段偏移、资源上限、未知值及防御性复制回归。 */
final class FastHeaderTest {
    /** @throws Exception 编码异常 */
    @Test
    void offsetsAndLengthsAreFrozen() throws Exception {
        byte[] unsigned = FastHeaderReaderWriter.unsignedHeader(17, new byte[16], new byte[32]);
        var b = ByteBuffer.wrap(unsigned);
        assertEquals(128, unsigned.length);
        assertTrue(FastHeaderReaderWriter.hasMagic(Arrays.copyOf(unsigned, 8)));
        assertEquals(1, b.getShort(8)); assertEquals(0, b.getShort(10));
        assertEquals(2, b.getShort(12)); assertEquals(1, b.getShort(14));
        assertEquals(160, b.getInt(16)); assertEquals(0, b.getInt(20));
        assertEquals(65536, b.getInt(24)); assertEquals(3, b.getInt(28)); assertEquals(4, b.getInt(32));
        assertEquals(19, b.get(36)); assertEquals(1, b.get(37)); assertEquals(17, b.getLong(88));
        FastHeader header = FastHeaderReaderWriter.withMac(unsigned, new byte[32]);
        unsigned[40] = 5; byte[] returned = header.bytes(); returned[40] = 6;
        assertEquals(0, header.argonSalt()[0]);
        assertEquals(17, header.plaintextLength());
        assertEquals(216, FastHeaderReaderWriter.containerLength(0));
        long first = (1 << 20) - 56;
        assertEquals(160L + (1 << 20), FastHeaderReaderWriter.containerLength(first));
        assertEquals(160L + (1 << 20) + 17, FastHeaderReaderWriter.containerLength(first + 1));
        assertTrue(FastHeaderReaderWriter.containerLength(1L << 40) > (1L << 40));
    }

    /** @throws Exception 编码异常 */
    @Test
    void unsupportedFieldsFailBeforeKdf() throws Exception {
        byte[] valid = FastHeaderReaderWriter.withMac(
                FastHeaderReaderWriter.unsignedHeader(17, new byte[16], new byte[32]), new byte[32]).bytes();
        for (int offset : new int[]{0,8,10,12,14,16,20,24,28,32,36,37,38,39,96,127}) {
            byte[] invalid = valid.clone(); invalid[offset] ^= 1;
            assertThrows(CryptoException.class, () -> FastHeaderReaderWriter.parse(invalid), "偏移 " + offset);
        }
        for (int value : new int[]{0, -1, Integer.MAX_VALUE, 65535, 65537}) {
            byte[] invalid = valid.clone(); ByteBuffer.wrap(invalid).putInt(24, value);
            assertThrows(CryptoException.class, () -> FastHeaderReaderWriter.parse(invalid));
        }
        byte[] aes128 = valid.clone(); ByteBuffer.wrap(aes128).putShort(12, (short) 1);
        assertThrows(CryptoException.class, () -> FastHeaderReaderWriter.parse(aes128));
        for (long length : new long[]{-1, (1L << 40) + 1, Long.MAX_VALUE}) {
            byte[] invalid = valid.clone(); ByteBuffer.wrap(invalid).putLong(88, length);
            assertThrows(CryptoException.class, () -> FastHeaderReaderWriter.parse(invalid));
            assertThrows(CryptoException.class, () -> FastHeaderReaderWriter.containerLength(length));
        }
        for (int size : new int[]{0,7,127,128,159,161}) {
            assertThrows(CryptoException.class, () -> FastHeaderReaderWriter.parse(Arrays.copyOf(valid, size)));
        }
        var stream = new ByteArrayInputStream(Arrays.copyOf(valid, 161));
        FastHeaderReaderWriter.read(stream); assertEquals(1, stream.available());
    }
}
