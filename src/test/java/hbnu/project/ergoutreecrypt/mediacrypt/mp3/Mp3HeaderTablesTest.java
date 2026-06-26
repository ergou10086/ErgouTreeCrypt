package hbnu.project.ergoutreecrypt.mediacrypt.mp3;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/**
 * {@link Mp3HeaderTables} 查表与帧长计算的正确性（纯计算，快速测试）。
 *
 * @author ErgouTree
 */
class Mp3HeaderTablesTest {

    @Test
    void mpeg1LayerIII_128k_44100_mono() {
        // 帧头：FF FB 90 C0 —— MPEG-1 LayerIII 128kbps 44.1kHz mono 无 CRC。
        Mp3HeaderTables.FrameHeader h = Mp3HeaderTables.parse(0xFF, 0xFB, 0x90, 0xC0);
        assertTrue(h.valid());
        assertEquals(Mp3HeaderTables.MPEG_1, h.version());
        assertEquals(Mp3HeaderTables.LAYER_3, h.layer());
        assertFalse(h.hasCrc());
        assertEquals(128000, h.bitrate());
        assertEquals(44100, h.sampleRate());
        assertEquals(0, h.padding());
        assertTrue(h.isMono());
        // 帧长 = 144 * 128000 / 44100 = 417。
        assertEquals(417, h.frameLength());
        // side info：MPEG-1 mono = 17。
        assertEquals(17, Mp3HeaderTables.sideInfoLength(h.version(), h.channelMode()));
    }

    @Test
    void mpeg1LayerIII_withPadding() {
        // 同上但 padding=1（b2 = 0x92）。帧长应 +1 = 418。
        Mp3HeaderTables.FrameHeader h = Mp3HeaderTables.parse(0xFF, 0xFB, 0x92, 0xC0);
        assertTrue(h.valid());
        assertEquals(1, h.padding());
        assertEquals(418, h.frameLength());
    }

    @Test
    void mpeg1LayerIII_stereo320k_48000() {
        // FF FB E4 00 —— bitrate idx 1110=320k, samplerate 01=48k(b2 低位 ..0100), stereo(00)。
        Mp3HeaderTables.FrameHeader h = Mp3HeaderTables.parse(0xFF, 0xFB, 0xE4, 0x00);
        assertTrue(h.valid());
        assertEquals(320000, h.bitrate());
        assertEquals(48000, h.sampleRate());
        assertFalse(h.isMono());
        // 帧长 = 144 * 320000 / 48000 = 960。
        assertEquals(960, h.frameLength());
        // side info：MPEG-1 stereo = 32。
        assertEquals(32, Mp3HeaderTables.sideInfoLength(h.version(), h.channelMode()));
    }

    @Test
    void rejectsInvalidSync() {
        assertFalse(Mp3HeaderTables.parse(0xFF, 0x1B, 0x90, 0xC0).valid()); // 同步字不全
        assertFalse(Mp3HeaderTables.parse(0x00, 0x00, 0x00, 0x00).valid());
    }

    @Test
    void rejectsFreeAndReservedBitrate() {
        assertFalse(Mp3HeaderTables.parse(0xFF, 0xFB, 0x00, 0xC0).valid()); // bitrate idx 0 = free
        assertFalse(Mp3HeaderTables.parse(0xFF, 0xFB, 0xF0, 0xC0).valid()); // bitrate idx 15 = bad
    }

    @Test
    void rejectsReservedSampleRate() {
        // samplerate idx 11 (0x0C in bits) 非法。b2 = bitrate(1001) samplerate(11) pad(0) -> 1001 1100 = 0x9C
        assertFalse(Mp3HeaderTables.parse(0xFF, 0xFB, 0x9C, 0xC0).valid());
    }
}
