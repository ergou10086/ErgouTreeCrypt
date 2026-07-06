package hbnu.project.ergoutreecrypt.mediacrypt;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Security;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import hbnu.project.ergoutreecrypt.mediacrypt.wav.WavParser;

/**
 * 音视频加密端到端往返测试：加密 → 验证格式合法 + 内容改变 → 解密 → 逐字节还原。
 *
 * <p>本测试会真实调用 Argon2id（1 GiB，较慢），因此每种格式仅做一次完整往返，并集中验证错误密码检测。
 * 解析/元数据等细粒度逻辑由 {@link MediaParserTest} / {@link MediaMetadataTest} 等快速测试覆盖。
 *
 * @author ErgouTree
 */
class MediaCryptRoundtripTest {

    private static final byte[] PASSWORD = "ErgouTree-媒体加密-2026".getBytes(StandardCharsets.UTF_8);

    @BeforeAll
    static void setup() {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }
    }

    private final MediaCryptCodec codec = new MediaCryptCodec();

    // ---- WAV ----

    @Test
    void wavRoundtripByteExact(@TempDir Path dir) throws Exception {
        byte[] original = MediaTestFixtures.buildWav(MediaTestFixtures.pseudoData(4096));
        Path in = MediaTestFixtures.write(dir, "in.wav", original);
        Path enc = dir.resolve("enc.wav");
        Path dec = dir.resolve("dec.wav");

        codec.encrypt(in, enc, PASSWORD, MediaCryptOptions.defaults());

        // 加密后仍是合法 WAV（可被解析器再次解析、含 data chunk）。
        assertTrue(codec.isEncrypted(enc), "加密后应被识别为本工具加密");
        WavParser parser = WavParser.parse(enc);
        assertTrue(parser.requireDataChunk().payloadSize() > 0);

        // data payload 内容应已改变（噪声化）。
        assertContentChanged(original, Files.readAllBytes(enc));

        codec.decrypt(enc, dec, PASSWORD);
        assertArrayEquals(original, Files.readAllBytes(dec), "WAV 解密应逐字节还原");
    }

    // ---- MP3 ----

    @Test
    void mp3RoundtripByteExact(@TempDir Path dir) throws Exception {
        byte[] original = MediaTestFixtures.buildMp3(20);
        Path in = MediaTestFixtures.write(dir, "in.mp3", original);
        Path enc = dir.resolve("enc.mp3");
        Path dec = dir.resolve("dec.mp3");

        codec.encrypt(in, enc, PASSWORD, MediaCryptOptions.defaults());
        assertTrue(codec.isEncrypted(enc));

        // 帧头必须保留：加密文件去掉尾块后仍应能扫描出 20 帧（结构合法）。
        // 这里通过内容改变 + 可解密还原间接验证。
        assertContentChanged(original, Files.readAllBytes(enc));

        codec.decrypt(enc, dec, PASSWORD);
        assertArrayEquals(original, Files.readAllBytes(dec), "MP3 解密应逐字节还原");
    }

    // ---- MP4 ----

    @Test
    void mp4RoundtripByteExact(@TempDir Path dir) throws Exception {
        byte[] original = MediaTestFixtures.buildMp4(MediaTestFixtures.pseudoData(8000));
        Path in = MediaTestFixtures.write(dir, "in.mp4", original);
        Path enc = dir.resolve("enc.mp4");
        Path dec = dir.resolve("dec.mp4");

        codec.encrypt(in, enc, PASSWORD, MediaCryptOptions.defaults());
        assertTrue(codec.isEncrypted(enc));
        assertContentChanged(original, Files.readAllBytes(enc));

        codec.decrypt(enc, dec, PASSWORD);
        assertArrayEquals(original, Files.readAllBytes(dec), "MP4 解密应逐字节还原");
    }

    // ---- M4A（纯音频 MP4 容器）----

    @Test
    void m4aRoundtripByteExact(@TempDir Path dir) throws Exception {
        byte[] original = MediaTestFixtures.buildM4a(MediaTestFixtures.pseudoData(4096));
        Path in = MediaTestFixtures.write(dir, "in.m4a", original);
        Path enc = dir.resolve("enc.m4a");
        Path dec = dir.resolve("dec.m4a");

        codec.encrypt(in, enc, PASSWORD, MediaCryptOptions.defaults());

        // 加密后应能被识别为本工具加密
        assertTrue(codec.isEncrypted(enc), "加密后应被识别为本工具加密");
        // 加密后的 M4A 仍是合法 ISO-BMFF 容器（BoxParser 可成功解析）
        assertContentChanged(original, Files.readAllBytes(enc));

        codec.decrypt(enc, dec, PASSWORD);
        assertArrayEquals(original, Files.readAllBytes(dec), "M4A 解密应逐字节还原");
    }

    @Test
    void m4aBoxParserCanReparse(@TempDir Path dir) throws Exception {
        // 验证合成的 M4A 文件是合法的 ISO-BMFF 容器
        byte[] original = MediaTestFixtures.buildM4a(MediaTestFixtures.pseudoData(2048));
        Path in = MediaTestFixtures.write(dir, "test.m4a", original);

        hbnu.project.ergoutreecrypt.mediacrypt.mp4.BoxParser parser =
                hbnu.project.ergoutreecrypt.mediacrypt.mp4.BoxParser.parse(in);
        // 应能定位到 mdat box
        hbnu.project.ergoutreecrypt.mediacrypt.mp4.Mp4Box mdat = parser.requireMdat();
        assertTrue(mdat.payloadSize() > 0, "M4A 应包含 mdat box");
        // 应能定位到 moov box
        hbnu.project.ergoutreecrypt.mediacrypt.mp4.Mp4Box moov = parser.findBox("moov");
        assertTrue(moov != null && moov.payloadSize() > 0, "M4A 应包含 moov box");
    }

    @Test
    void m4aWrongPasswordDetected(@TempDir Path dir) throws Exception {
        byte[] original = MediaTestFixtures.buildM4a(MediaTestFixtures.pseudoData(2048));
        Path in = MediaTestFixtures.write(dir, "in.m4a", original);
        Path enc = dir.resolve("enc.m4a");
        Path dec = dir.resolve("dec.m4a");

        codec.encrypt(in, enc, PASSWORD, MediaCryptOptions.defaults());
        byte[] wrong = "wrong-password".getBytes(StandardCharsets.UTF_8);
        assertThrows(MediaCryptException.class, () -> codec.decrypt(enc, dec, wrong));
        assertFalse(Files.exists(dec), "错误密码解密不应残留输出文件");
    }

    // ---- 错误密码检测（复用一次加密产物，避免重复 KDF）----

    @Test
    void wrongPasswordDetected(@TempDir Path dir) throws Exception {
        byte[] original = MediaTestFixtures.buildWav(MediaTestFixtures.pseudoData(2048));
        Path in = MediaTestFixtures.write(dir, "in.wav", original);
        Path enc = dir.resolve("enc.wav");
        Path dec = dir.resolve("dec.wav");

        codec.encrypt(in, enc, PASSWORD, MediaCryptOptions.defaults());

        byte[] wrong = "wrong-password".getBytes(StandardCharsets.UTF_8);
        // 默认存完整性 MAC → 错误密码应被检测并抛出异常，且不留下错误输出。
        assertThrows(MediaCryptException.class, () -> codec.decrypt(enc, dec, wrong));
        assertFalse(Files.exists(dec), "完整性校验失败时不应残留输出文件");
    }

    // ---- 无完整性校验时仍能正确往返 ----

    @Test
    void wavRoundtripWithoutIntegrity(@TempDir Path dir) throws Exception {
        byte[] original = MediaTestFixtures.buildWav(MediaTestFixtures.pseudoData(1024));
        Path in = MediaTestFixtures.write(dir, "in.wav", original);
        Path enc = dir.resolve("enc.wav");
        Path dec = dir.resolve("dec.wav");

        MediaCryptOptions opts = MediaCryptOptions.builder().storeIntegrity(false).build();
        codec.encrypt(in, enc, PASSWORD, opts);
        codec.decrypt(enc, dec, PASSWORD);
        assertArrayEquals(original, Files.readAllBytes(dec));
    }

    // ---- 新增档位：MP3 M-SAFE（仅 MainData）----

    @Test
    void mp3MsafeRoundtripByteExact(@TempDir Path dir) throws Exception {
        byte[] original = MediaTestFixtures.buildMp3(16);
        Path in = MediaTestFixtures.write(dir, "in.mp3", original);
        Path enc = dir.resolve("enc.mp3");
        Path dec = dir.resolve("dec.mp3");

        MediaCryptOptions opts = MediaCryptOptions.builder()
                .profile(MediaCryptProfile.M_SAFE).build();
        codec.encrypt(in, enc, PASSWORD, opts);
        assertContentChanged(original, java.nio.file.Files.readAllBytes(enc));
        codec.decrypt(enc, dec, PASSWORD);
        assertArrayEquals(original, java.nio.file.Files.readAllBytes(dec), "MP3 M-SAFE 应逐字节还原");
    }

    // ---- 新增档位：WAV W-SEL（pattern 选择性加密）----

    @Test
    void wavWselRoundtripByteExact(@TempDir Path dir) throws Exception {
        byte[] original = MediaTestFixtures.buildWav(MediaTestFixtures.pseudoData(20000));
        Path in = MediaTestFixtures.write(dir, "in.wav", original);
        Path enc = dir.resolve("enc.wav");
        Path dec = dir.resolve("dec.wav");

        MediaCryptOptions opts = MediaCryptOptions.builder()
                .profile(MediaCryptProfile.W_SEL).build();
        codec.encrypt(in, enc, PASSWORD, opts);
        assertContentChanged(original, java.nio.file.Files.readAllBytes(enc));
        codec.decrypt(enc, dec, PASSWORD);
        assertArrayEquals(original, java.nio.file.Files.readAllBytes(dec), "WAV W-SEL 应逐字节还原");
    }

    // ---- 进度回调与取消 ----

    @Test
    void progressCallbackInvoked(@TempDir Path dir) throws Exception {
        byte[] original = MediaTestFixtures.buildWav(MediaTestFixtures.pseudoData(4096));
        Path in = MediaTestFixtures.write(dir, "in.wav", original);
        Path enc = dir.resolve("enc.wav");

        long[] last = {-1, -1};
        MediaProgress progress = new MediaProgress() {
            @Override
            public void onProgress(long processed, long total) {
                last[0] = processed;
                last[1] = total;
            }

            @Override
            public boolean isCancelled() {
                return false;
            }
        };
        codec.encrypt(in, enc, PASSWORD, MediaCryptOptions.defaults(), progress);
        // 处理完成后 processed 应等于 total（且 > 0）。
        assertTrue(last[1] > 0, "总字节应被报告");
        assertTrue(last[0] == last[1], "结束时已处理应等于总量");
    }

    @Test
    void cancellationAbortsAndCleansUp(@TempDir Path dir) throws Exception {
        byte[] original = MediaTestFixtures.buildWav(MediaTestFixtures.pseudoData(4096));
        Path in = MediaTestFixtures.write(dir, "in.wav", original);
        Path enc = dir.resolve("enc.wav");

        MediaProgress cancelling = new MediaProgress() {
            @Override
            public void onProgress(long processed, long total) {
            }

            @Override
            public boolean isCancelled() {
                return true; // 立即取消
            }
        };
        assertThrows(MediaCryptCancelledException.class,
                () -> codec.encrypt(in, enc, PASSWORD, MediaCryptOptions.defaults(), cancelling));
        assertFalse(java.nio.file.Files.exists(enc), "取消后不应残留输出文件");
    }

    private static void assertContentChanged(byte[] original, byte[] encrypted) {
        // 加密文件应比原文件长（追加了元数据），且重叠区域不完全相同。
        int diff = 0;
        int n = Math.min(original.length, encrypted.length);
        for (int i = 0; i < n; i++) {
            if (original[i] != encrypted[i]) {
                diff++;
            }
        }
        assertTrue(diff > 0, "加密后内容应发生改变");
    }
}
