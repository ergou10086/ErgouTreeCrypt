package hbnu.project.ergoutreecrypt.mediacrypt;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import hbnu.project.ergoutreecrypt.mediacrypt.mp3.Mp3Frame;
import hbnu.project.ergoutreecrypt.mediacrypt.mp3.Mp3FrameScanner;
import hbnu.project.ergoutreecrypt.mediacrypt.mp4.BoxParser;
import hbnu.project.ergoutreecrypt.mediacrypt.mp4.Mp4Box;
import hbnu.project.ergoutreecrypt.mediacrypt.wav.WavChunk;
import hbnu.project.ergoutreecrypt.mediacrypt.wav.WavParser;

/**
 * 各格式解析器的结构识别测试（构造内存样本，无需 KDF，快速）。
 *
 * @author ErgouTree
 */
class MediaParserTest {

    // ---- WAV ----

    @Test
    void wavParserLocatesDataChunk(@TempDir Path dir) throws Exception {
        byte[] pcm = MediaTestFixtures.pseudoData(1000);
        Path f = MediaTestFixtures.write(dir, "a.wav", MediaTestFixtures.buildWav(pcm));

        WavParser parser = WavParser.parse(f);
        assertNotNull(parser.findChunk("fmt "));
        WavChunk data = parser.requireDataChunk();
        assertEquals(1000, data.payloadSize());
        // data payload 偏移 = 12(RIFF头) + 8(fmt头) + 16(fmt payload) + 8(data头) = 44。
        assertEquals(44, data.payloadOffset());
    }

    @Test
    void wavParserRejectsNonRiff(@TempDir Path dir) throws Exception {
        Path f = MediaTestFixtures.write(dir, "bad.wav", new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12});
        assertThrows(MediaCryptException.class, () -> WavParser.parse(f));
    }

    // ---- MP3 ----

    @Test
    void mp3ScannerFindsAllFrames(@TempDir Path dir) throws Exception {
        byte[] mp3 = MediaTestFixtures.buildMp3(10);
        Path f = MediaTestFixtures.write(dir, "a.mp3", mp3);

        Mp3FrameScanner scanner = Mp3FrameScanner.scan(f);
        assertEquals(10, scanner.frames().size());
        // 首帧从 0 开始（无 ID3v2）。
        assertEquals(0, scanner.audioStart());
        for (Mp3Frame frame : scanner.frames()) {
            assertEquals(417, frame.frameLength());
            assertEquals(4, frame.headerLength());
            // body = frameLen - header = 413。
            assertEquals(413, frame.bodyRange().length());
        }
    }

    @Test
    void mp3ScannerSkipsId3v2(@TempDir Path dir) throws Exception {
        byte[] audio = MediaTestFixtures.buildMp3(5);
        // 构造一个 30 字节 payload 的 ID3v2 头（10 头 + 30 = 40 字节）。
        byte[] id3 = new byte[40];
        id3[0] = 'I';
        id3[1] = 'D';
        id3[2] = '3';
        id3[3] = 3; // version
        // synchsafe size = 30 -> 字节 [6..9]
        id3[6] = 0;
        id3[7] = 0;
        id3[8] = 0;
        id3[9] = 30;
        byte[] full = new byte[id3.length + audio.length];
        System.arraycopy(id3, 0, full, 0, id3.length);
        System.arraycopy(audio, 0, full, id3.length, audio.length);

        Path f = MediaTestFixtures.write(dir, "tagged.mp3", full);
        Mp3FrameScanner scanner = Mp3FrameScanner.scan(f);
        assertEquals(5, scanner.frames().size());
        assertEquals(40, scanner.audioStart());
    }

    // ---- MP4 ----

    @Test
    void mp4ParserLocatesMdat(@TempDir Path dir) throws Exception {
        byte[] mdatData = MediaTestFixtures.pseudoData(2000);
        Path f = MediaTestFixtures.write(dir, "a.mp4", MediaTestFixtures.buildMp4(mdatData));

        BoxParser parser = BoxParser.parse(f);
        assertNotNull(parser.findBox("ftyp"));
        assertNotNull(parser.findBox("moov"));
        Mp4Box mdat = parser.requireMdat();
        assertEquals(2000, mdat.payloadSize());
    }

    @Test
    void mp4ParserRejectsGarbage(@TempDir Path dir) throws Exception {
        Path f = MediaTestFixtures.write(dir, "bad.mp4", MediaTestFixtures.pseudoData(64));
        assertThrows(MediaCryptException.class, () -> BoxParser.parse(f));
    }

    // ---- M4A ----

    @Test
    void m4aParserLocatesMdatAndMoov(@TempDir Path dir) throws Exception {
        byte[] audioData = MediaTestFixtures.pseudoData(3000);
        Path f = MediaTestFixtures.write(dir, "a.m4a", MediaTestFixtures.buildM4a(audioData));

        BoxParser parser = BoxParser.parse(f);
        // M4A 应有 ftyp（brand = "M4A "）
        assertNotNull(parser.findBox("ftyp"), "M4A 应包含 ftyp box");
        // M4A 应有 moov（含完整音频轨道结构）
        assertNotNull(parser.findBox("moov"), "M4A 应包含 moov box");
        // M4A 应有 mdat
        Mp4Box mdat = parser.requireMdat();
        assertEquals(3000, mdat.payloadSize(), "M4A mdat payload 大小应正确");
    }

    @Test
    void m4aFormatRecognizedByExtension() {
        // 验证 .m4a 扩展名能被 MediaFormat 识别为 MP4
        Path p = Path.of("song.m4a");
        MediaFormat fmt = MediaFormat.fromExtension(p);
        assertTrue(fmt == MediaFormat.MP4, ".m4a 应映射到 MediaFormat.MP4");
    }

    @Test
    void byteRangeBasics() {
        ByteRange r = new ByteRange(10, 5);
        assertEquals(15, r.end());
        assertTrue(new ByteRange(0, 0).isEmpty());
    }
}
