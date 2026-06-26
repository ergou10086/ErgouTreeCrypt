package hbnu.project.ergoutreecrypt.encoding;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Random;

import org.junit.jupiter.api.Test;

/**
 * 验证 {@link ReedSolomon} 高层封装：各 RS 规格的编解码往返、fastDecode、纠错与损坏标记。
 * 这些规格正是 Picocrypt header 字段所用，必须能解码既有 .pcv。
 */
class ReedSolomonTest {

    private final RsCodecs codecs = new RsCodecs();

    @Test
    void rs5RoundTrip() {
        byte[] data = "v2.14".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        byte[] enc = ReedSolomon.encode(codecs.rs5, data);
        assertEquals(15, enc.length);

        ReedSolomon.DecodeResult dr = ReedSolomon.decode(codecs.rs5, enc, false);
        assertFalse(dr.corrupted);
        assertArrayEquals(data, dr.data);
    }

    @Test
    void allHeaderCodecsRoundTrip() {
        check(codecs.rs1, 1);
        check(codecs.rs5, 5);
        check(codecs.rs16, 16);
        check(codecs.rs24, 24);
        check(codecs.rs32, 32);
        check(codecs.rs64, 64);
    }

    private void check(Fec fec, int dataLen) {
        byte[] data = new byte[dataLen];
        new Random(dataLen).nextBytes(data);
        byte[] enc = ReedSolomon.encode(fec, data);
        assertEquals(dataLen * 3, enc.length);
        ReedSolomon.DecodeResult dr = ReedSolomon.decode(fec, enc, false);
        assertFalse(dr.corrupted, "RS" + dataLen + " 解码不应损坏");
        assertArrayEquals(data, dr.data, "RS" + dataLen + " 往返");
    }

    @Test
    void rs128FastDecodeReturnsFirst128() {
        byte[] data = new byte[128];
        new Random(1).nextBytes(data);
        byte[] enc = ReedSolomon.encode(codecs.rs128, data);
        assertEquals(136, enc.length);

        // fastDecode：直接取前 128 字节（不纠错）。
        ReedSolomon.DecodeResult dr = ReedSolomon.decode(codecs.rs128, enc, true);
        assertFalse(dr.corrupted);
        byte[] first128 = new byte[128];
        System.arraycopy(enc, 0, first128, 0, 128);
        assertArrayEquals(first128, dr.data);
    }

    @Test
    void rs16CorrectsErrors() {
        byte[] data = new byte[16];
        new Random(99).nextBytes(data);
        byte[] enc = ReedSolomon.encode(codecs.rs16, data);
        // RS16 (16->48) 可纠正 (48-16)/2 = 16 个错误，这里改 3 个。
        enc[0] ^= 0xFF;
        enc[20] ^= 0x0F;
        enc[47] ^= 0xA5;

        ReedSolomon.DecodeResult dr = ReedSolomon.decode(codecs.rs16, enc, false);
        assertFalse(dr.corrupted);
        assertArrayEquals(data, dr.data);
    }

    @Test
    void rs5MarksCorruptedWhenUnrecoverable() {
        byte[] data = "v2.14".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        byte[] enc = ReedSolomon.encode(codecs.rs5, data);
        // RS5 (5->15) 可纠正 (15-5)/2 = 5 个错误，破坏 8 个使其无法纠正。
        for (int i = 0; i < 8; i++) {
            enc[i] ^= 0xFF;
        }
        ReedSolomon.DecodeResult dr = ReedSolomon.decode(codecs.rs5, enc, false);
        assertTrue(dr.corrupted, "超出纠错能力应标记 corrupted");
        // 仍返回 total/3 = 5 字节（尽力恢复）。
        assertEquals(5, dr.data.length);
    }
}
