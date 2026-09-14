package hbnu.project.ergoutreecrypt.filetypes;

import hbnu.project.ergoutreecrypt.encoding.RsCodecs;
import hbnu.project.ergoutreecrypt.exception.ErrorKind;
import hbnu.project.ergoutreecrypt.filetypes.FileInputGuard.Feature;
import hbnu.project.ergoutreecrypt.filetypes.FileInputGuard.GuardResult;
import hbnu.project.ergoutreecrypt.filetypes.FileInputGuard.Options;
import hbnu.project.ergoutreecrypt.filestego.FileStegoCodec;
import hbnu.project.ergoutreecrypt.filestego.api.Argon2Params;
import hbnu.project.ergoutreecrypt.filestego.api.FileStegoOptions;
import hbnu.project.ergoutreecrypt.i18n.Messages;
import hbnu.project.ergoutreecrypt.mediacrypt.MediaCryptCodec;
import hbnu.project.ergoutreecrypt.mediacrypt.MediaCryptOptions;
import hbnu.project.ergoutreecrypt.mediacrypt.MediaCryptProfile;
import hbnu.project.ergoutreecrypt.volume.EncryptRequest;
import hbnu.project.ergoutreecrypt.volume.Encryptor;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link FileInputGuard} 与 {@link OutputNaming} 的启动前预检测试。
 *
 * <p>覆盖各功能对「可接受输入 / 快速拒绝 + 引导」的判定：通用加解密、通用完整性校验、
 * 音视频格式保持加解密与校验、图像隐写、文件隐写。为保持测试快速，所有需要真实
 * 密钥派生的场景（卷加密、媒体加密、隐写嵌入）都显式覆写为低 Argon2 参数。
 *
 * @author ErgouTree
 * @since 2026/9/14
 */
final class FileInputGuardTest {

    /**
     * 测试用低内存 Argon2 参数（KiB），保证测试秒级完成。
     */
    private static final int TEST_MEMORY_KIB = 64 * 1024;

    /**
     * 测试用 Argon2 迭代次数。
     */
    private static final int TEST_PASSES = 1;

    /**
     * 测试用 Argon2 并行度。
     */
    private static final int TEST_THREADS = 1;

    /**
     * 测试用密码。
     */
    private static final String PASSWORD = "guard-test-password";

    // ================================================================
    // OutputNaming：命名约定
    // ================================================================

    @Test
    void outputNamingFollowsAgreedConventions() {
        assertEquals("song.mp4.ergou", OutputNaming.encryptOutputName("song.mp4"));
        assertEquals("song.enc.mp4", OutputNaming.fpeEncryptOutputName("song.mp4"));
        assertEquals("song.enc", OutputNaming.fpeEncryptOutputName("song"));
        assertEquals("song.dec.mp4", OutputNaming.fpeDecryptOutputName("song.enc.mp4"));
        assertEquals("noise.dec.mp4", OutputNaming.fpeDecryptOutputName("noise.mp4"));
        assertEquals("song.mp4", OutputNaming.stripFpeMarker("song.enc.mp4"));
        assertEquals("song", OutputNaming.stripFpeMarker("song.enc"));
        assertEquals("plain.txt", OutputNaming.stripFpeMarker("plain.txt"));
        assertEquals("photo_stego.png", OutputNaming.stegoOutputName("photo.png"));
        assertEquals("photo_stego", OutputNaming.stegoOutputName("photo"));
    }

    @Test
    void decryptOutputStripsVolumeSuffix() {
        assertEquals("secret.txt", OutputNaming.decryptOutputName("secret.txt.ergou"));
        assertEquals("secret.txt", OutputNaming.decryptOutputName("secret.txt.pcv"));
        assertEquals("secret.txt", OutputNaming.decryptOutputName("secret.txt.ERGOU"));
        assertEquals("archive.zip.decrypted", OutputNaming.decryptOutputName("archive.zip"));
    }

    @Test
    void outputPathsSitNextToInput(@TempDir final Path dir) {
        Path input = dir.resolve("song.mp3");
        assertEquals(dir.resolve("song.enc.mp3"), OutputNaming.fpeEncryptOutput(input));
        assertEquals(dir.resolve("song.dec.mp3"), OutputNaming.fpeDecryptOutput(dir.resolve("song.enc.mp3")));
        assertEquals(dir.resolve("song.mp3"), OutputNaming.decryptOutput(dir.resolve("song.mp3.ergou")));
    }

    // ================================================================
    // 通用加密 / 通用错误
    // ================================================================

    @Test
    void genericEncryptAcceptsAnyFileAndDirectory(@TempDir final Path dir) throws Exception {
        Path file = write(dir, "anything.bin", new byte[] {1, 2, 3});
        Path folder = Files.createDirectories(dir.resolve("sub"));
        Path alreadyEncrypted = write(dir, "double.ergou", new byte[] {9});

        assertAccepted(FileInputGuard.check(Feature.GENERIC_ENCRYPT, Options.none(), file));
        assertAccepted(FileInputGuard.check(Feature.GENERIC_ENCRYPT, Options.none(), folder));
        // 二次加密仅提示不拦截（软提示不在本类阻断）
        assertAccepted(FileInputGuard.check(Feature.GENERIC_ENCRYPT, Options.none(), alreadyEncrypted));
    }

    @Test
    void missingInputIsRejectedForEveryFeature(@TempDir final Path dir) {
        Path missing = dir.resolve("not-here.ergou");
        for (Feature feature : Feature.values()) {
            GuardResult result = FileInputGuard.check(feature, Options.none(), missing);
            assertTrue(result.rejected(), "缺失文件应被拒绝: " + feature);
            assertEquals(ErrorKind.INPUT_NOT_FOUND, result.kind(), "错误分类: " + feature);
        }
        GuardResult nullResult = FileInputGuard.check(Feature.GENERIC_DECRYPT, Options.none(), null);
        assertEquals(ErrorKind.INPUT_NOT_FOUND, nullResult.kind());
    }

    // ================================================================
    // 通用解密
    // ================================================================

    @Test
    void genericDecryptAcceptsRealVolumeAndSplitChunk(@TempDir final Path dir) throws Exception {
        Path volume = encryptVolume(dir, "doc.txt.ergou");
        assertAccepted(FileInputGuard.check(Feature.GENERIC_DECRYPT, Options.none(), volume));

        // 分卷碎片按命名规则直接放行（无需真实分卷）
        Path chunk = write(dir, "doc.txt.ergou.0", new byte[] {1, 2, 3});
        assertAccepted(FileInputGuard.check(Feature.GENERIC_DECRYPT, Options.none(), chunk));
    }

    @Test
    void genericDecryptAcceptsFolder(@TempDir final Path dir) throws Exception {
        Path folder = Files.createDirectories(dir.resolve("encrypted-folder"));
        assertAccepted(FileInputGuard.check(Feature.GENERIC_DECRYPT, Options.none(), folder));
    }

    @Test
    void genericDecryptRedirectsFormatPreservingCiphertext(@TempDir final Path dir) throws Exception {
        Path mediaCiphertext = write(dir, "song.enc.mp3", new byte[] {1, 2, 3, 4});
        GuardResult result = FileInputGuard.check(Feature.GENERIC_DECRYPT, Options.none(), mediaCiphertext);
        assertRejected(result, FileInputGuard.GUARD_FPE_DECRYPT);
        assertEquals(ErrorKind.UNSUPPORTED_FORMAT, result.kind());
    }

    @Test
    void genericDecryptRedirectsStegoCarrier(@TempDir final Path dir) throws Exception {
        Path stego = buildStegoPng(dir);
        GuardResult result = FileInputGuard.check(Feature.GENERIC_DECRYPT, Options.none(), stego);
        assertRejected(result, FileInputGuard.GUARD_STEGO_EXTRACT);
    }

    @Test
    void genericDecryptArchiveOnlyAcceptedWhenAutoUnzipOn(@TempDir final Path dir) throws Exception {
        Path archive = write(dir, "bundle.zip", new byte[] {1, 2, 3});

        GuardResult off = FileInputGuard.check(Feature.GENERIC_DECRYPT, Options.none(), archive);
        assertRejected(off, FileInputGuard.GUARD_NOT_ENCRYPTED);

        GuardResult on = FileInputGuard.check(Feature.GENERIC_DECRYPT,
                Options.builder().autoUnzip(true).build(), archive);
        assertAccepted(on);

        // 「解密后解压」针对加密归档，不能单独让明文压缩包变得可解密
        GuardResult decryptThenExtract = FileInputGuard.check(Feature.GENERIC_DECRYPT,
                Options.builder().decryptThenExtract(true).build(), archive);
        assertRejected(decryptThenExtract, FileInputGuard.GUARD_NOT_ENCRYPTED);
    }

    @Test
    void genericDecryptRejectsPlainFile(@TempDir final Path dir) throws Exception {
        Path plain = write(dir, "notes.txt", "hello".getBytes(StandardCharsets.UTF_8));
        GuardResult result = FileInputGuard.check(Feature.GENERIC_DECRYPT, Options.none(), plain);
        assertRejected(result, FileInputGuard.GUARD_NOT_ENCRYPTED);
        assertEquals(ErrorKind.UNSUPPORTED_FORMAT, result.kind());
    }

    @Test
    void genericDecryptRedirectsPlainMediaToFpeSwitch(@TempDir final Path dir) throws Exception {
        // 未加密的普通媒体：通用解密无能为力，应引导切换到「格式保持解密」
        Path plainMedia = write(dir, "song.mp3", "not encrypted".getBytes(StandardCharsets.UTF_8));
        GuardResult result = FileInputGuard.check(Feature.GENERIC_DECRYPT, Options.none(), plainMedia);
        assertRejected(result, FileInputGuard.GUARD_MEDIA_DECRYPT);
    }

    // ================================================================
    // 通用完整性校验
    // ================================================================

    @Test
    void verifyIntegrityAcceptsVolumeOnly(@TempDir final Path dir) throws Exception {
        Path volume = encryptVolume(dir, "check.txt.ergou");
        assertAccepted(FileInputGuard.check(Feature.VERIFY_INTEGRITY, Options.none(), volume));

        Path folder = Files.createDirectories(dir.resolve("dir"));
        assertRejected(FileInputGuard.check(Feature.VERIFY_INTEGRITY, Options.none(), folder),
                FileInputGuard.GUARD_REQUIRE_FILE);

        Path mediaCiphertext = write(dir, "clip.enc.mp4", new byte[] {1});
        assertRejected(FileInputGuard.check(Feature.VERIFY_INTEGRITY, Options.none(), mediaCiphertext),
                FileInputGuard.GUARD_FPE_VERIFY);

        Path plain = write(dir, "plain.bin", new byte[] {1});
        assertRejected(FileInputGuard.check(Feature.VERIFY_INTEGRITY, Options.none(), plain),
                FileInputGuard.GUARD_NOT_ENCRYPTED);
    }

    // ================================================================
    // 音视频格式保持
    // ================================================================

    @Test
    void fpeEncryptMatchesProfileToFormat(@TempDir final Path dir) throws Exception {
        Path wav = write(dir, "voice.wav", MediaFixtures.buildWav(new byte[2048]));

        assertAccepted(FileInputGuard.check(Feature.FPE_ENCRYPT, Options.none(), wav));
        assertAccepted(FileInputGuard.check(Feature.FPE_ENCRYPT,
                Options.builder().mediaProfile(MediaCryptProfile.W_FULL).build(), wav));

        // 档位与格式不匹配：明确拒绝并引导改选
        GuardResult mismatch = FileInputGuard.check(Feature.FPE_ENCRYPT,
                Options.builder().mediaProfile(MediaCryptProfile.M_BODY).build(), wav);
        assertRejected(mismatch, FileInputGuard.GUARD_PROFILE_MISMATCH);

        Path text = write(dir, "note.txt", new byte[] {1});
        assertRejected(FileInputGuard.check(Feature.FPE_ENCRYPT, Options.none(), text),
                FileInputGuard.KEY_AV_UNSUPPORTED);
    }

    @Test
    void fpeDecryptHonoursNoiseCheckOption(@TempDir final Path dir) throws Exception {
        Path plainWav = write(dir, "plain.wav", MediaFixtures.buildWav(new byte[2048]));
        Path cipherWav = dir.resolve("plain.enc.wav");
        encryptMedia(plainWav, cipherWav, true);

        // 开启噪音校验：明文媒体被拒绝，密文媒体放行
        assertRejected(FileInputGuard.check(Feature.FPE_DECRYPT,
                Options.builder().mediaNoiseCheck(true).build(), plainWav),
                FileInputGuard.KEY_AV_NOT_ENCRYPTED);
        assertAccepted(FileInputGuard.check(Feature.FPE_DECRYPT,
                Options.builder().mediaNoiseCheck(true).build(), cipherWav));

        // 关闭噪音校验：明文媒体也放行（按扩展名直接解密）
        assertAccepted(FileInputGuard.check(Feature.FPE_DECRYPT,
                Options.builder().mediaNoiseCheck(false).build(), plainWav));

        Path folder = Files.createDirectories(dir.resolve("media-dir"));
        assertRejected(FileInputGuard.check(Feature.FPE_DECRYPT, Options.none(), folder),
                FileInputGuard.GUARD_REQUIRE_FILE);
    }

    @Test
    void fpeDecryptAcceptsArchiveWhenDecompressFirst(@TempDir final Path dir) throws Exception {
        Path archive = write(dir, "pack.zip", new byte[] {1, 2, 3});
        assertRejected(FileInputGuard.check(Feature.FPE_DECRYPT, Options.none(), archive),
                FileInputGuard.KEY_AV_UNSUPPORTED);
        assertAccepted(FileInputGuard.check(Feature.FPE_DECRYPT,
                Options.builder().mediaDecompressFirst(true).build(), archive));
    }

    @Test
    void mediaVerifyRequiresStoredIntegrity(@TempDir final Path dir) throws Exception {
        Path withIntegrity = dir.resolve("with_mac.wav");
        encryptMedia(write(dir, "with_mac_src.wav", MediaFixtures.buildWav(new byte[2048])),
                withIntegrity, true);
        assertAccepted(FileInputGuard.check(Feature.MEDIA_VERIFY, Options.none(), withIntegrity));

        Path withoutIntegrity = dir.resolve("no_mac.wav");
        encryptMedia(write(dir, "no_mac_src.wav", MediaFixtures.buildWav(new byte[2048])),
                withoutIntegrity, false);
        assertRejected(FileInputGuard.check(Feature.MEDIA_VERIFY, Options.none(), withoutIntegrity),
                FileInputGuard.GUARD_INTEGRITY_MISSING);

        Path text = write(dir, "readme.txt", new byte[] {1});
        assertRejected(FileInputGuard.check(Feature.MEDIA_VERIFY, Options.none(), text),
                FileInputGuard.KEY_AV_UNSUPPORTED);
    }

    // ================================================================
    // 图像隐写
    // ================================================================

    @Test
    void imageStegoRequiresPngContainer(@TempDir final Path dir) throws Exception {
        Path png = MediaFixtures.createPng(dir, "photo.png");
        Path jpeg = write(dir, "photo.jpg", new byte[] {1, 2, 3});

        assertAccepted(FileInputGuard.check(Feature.IMAGE_STEGO_HIDE, Options.none(), png));
        assertAccepted(FileInputGuard.check(Feature.IMAGE_STEGO_EXTRACT, Options.none(), png));
        assertRejected(FileInputGuard.check(Feature.IMAGE_STEGO_HIDE, Options.none(), jpeg),
                FileInputGuard.GUARD_REQUIRE_PNG);
        assertRejected(FileInputGuard.check(Feature.IMAGE_STEGO_EXTRACT, Options.none(), jpeg),
                FileInputGuard.GUARD_REQUIRE_PNG);
    }

    // ================================================================
    // 文件隐写
    // ================================================================

    @Test
    void fileStegoHideChecksCarrierFormatAndCapacity(@TempDir final Path dir) throws Exception {
        Path pngCarrier = MediaFixtures.createPng(dir, "carrier.png");
        Path secret = write(dir, "secret.bin", new byte[1024]);

        assertAccepted(FileInputGuard.check(Feature.FILE_STEGO_HIDE,
                Options.builder().secretSizeBytes(Files.size(secret)).build(), pngCarrier));

        Path textCarrier = write(dir, "carrier.txt", new byte[] {1});
        assertRejected(FileInputGuard.check(Feature.FILE_STEGO_HIDE,
                Options.builder().secretSizeBytes(Files.size(secret)).build(), textCarrier),
                FileInputGuard.GUARD_UNSUPPORTED_CARRIER);

        // FLAC 载体容量约 16 MB，超出即拒绝
        Path flacCarrier = write(dir, "carrier.flac", new byte[] {1});
        GuardResult overflow = FileInputGuard.check(Feature.FILE_STEGO_HIDE,
                Options.builder().secretSizeBytes(20L * 1024 * 1024).build(), flacCarrier);
        assertRejected(overflow, FileInputGuard.KEY_STEGO_CAPACITY);
        assertEquals(ErrorKind.CAPACITY_INSUFFICIENT, overflow.kind());
        assertFalse(overflow.message().isBlank(), "容量不足应给出可展示文案");
    }

    @Test
    void fileStegoExtractRequiresActualStegoData(@TempDir final Path dir) throws Exception {
        Path stego = buildStegoPng(dir);
        assertAccepted(FileInputGuard.check(Feature.FILE_STEGO_EXTRACT, Options.none(), stego));

        Path cleanPng = MediaFixtures.createPng(dir, "clean.png");
        assertRejected(FileInputGuard.check(Feature.FILE_STEGO_EXTRACT, Options.none(), cleanPng),
                FileInputGuard.KEY_STEGO_DETECT_FAILED);

        Path text = write(dir, "plain.txt", new byte[] {1});
        assertRejected(FileInputGuard.check(Feature.FILE_STEGO_EXTRACT, Options.none(), text),
                FileInputGuard.KEY_STEGO_DETECT_FAILED);
    }

    // ================================================================
    // 文案解析
    // ================================================================

    @Test
    void guardMessageResolvesToRealText(@TempDir final Path dir) throws Exception {
        Path plain = write(dir, "plain.bin", new byte[] {1});
        GuardResult result = FileInputGuard.check(Feature.GENERIC_DECRYPT, Options.none(), plain);
        String message = result.message();
        assertFalse(message.isBlank(), "拒绝结果应给出文案");
        assertEquals(Messages.get(FileInputGuard.GUARD_NOT_ENCRYPTED), message);
        assertNotEquals("!" + FileInputGuard.GUARD_NOT_ENCRYPTED + "!", message,
                "i18n key 必须已补齐");

        assertTrue(FileInputGuard.check(Feature.GENERIC_ENCRYPT, Options.none(),
                write(dir, "ok.bin", new byte[] {1})).message().isEmpty(),
                "放行结果不应有文案");
    }

    // ================================================================
    // 夹具与断言
    // ================================================================

    /**
     * 断言预检放行。
     *
     * @param result 预检结果
     */
    private static void assertAccepted(final GuardResult result) {
        assertTrue(result.accepted(), () -> "预期放行，实际拒绝: " + result.guardKey());
    }

    /**
     * 断言预检以指定引导 key 拒绝。
     *
     * @param result      预检结果
     * @param expectedKey 预期的 i18n key
     */
    private static void assertRejected(final GuardResult result, final String expectedKey) {
        assertTrue(result.rejected(), "预期拒绝，实际放行");
        assertEquals(expectedKey, result.guardKey());
    }

    /**
     * 写入测试文件。
     *
     * @param dir  目录
     * @param name 文件名
     * @param data 内容
     * @return 文件路径
     * @throws Exception 写入失败
     */
    private static Path write(final Path dir, final String name, final byte[] data) throws Exception {
        Path path = dir.resolve(name);
        Files.write(path, data);
        return path;
    }

    /**
     * 用低 Argon2 参数生成一个真实的通用加密卷。
     *
     * @param dir  目录
     * @param name 输出文件名
     * @return 加密卷路径
     * @throws Exception 加密失败
     */
    private static Path encryptVolume(final Path dir, final String name) throws Exception {
        Path input = dir.resolve("payload.txt");
        if (!Files.exists(input)) {
            Files.writeString(input, "guard test payload", StandardCharsets.UTF_8);
        }
        Path output = dir.resolve(name);
        EncryptRequest request = new EncryptRequest();
        request.setInputFile(input.toString());
        request.setOutputFile(output.toString());
        request.setPassword(PASSWORD);
        request.setArgon2MemoryKib(TEST_MEMORY_KIB);
        request.setArgon2Passes(TEST_PASSES);
        request.setArgon2Threads(TEST_THREADS);
        request.setRsCodecs(new RsCodecs());
        Encryptor.encrypt(request);
        return output;
    }

    /**
     * 用低 Argon2 参数做一次真实的格式保持加密。
     *
     * @param input         明文媒体
     * @param output        密文媒体
     * @param storeIntegrity 是否存储完整性校验数据
     * @throws Exception 加密失败
     */
    private static void encryptMedia(final Path input, final Path output,
                                     final boolean storeIntegrity) throws Exception {
        MediaCryptOptions options = MediaCryptOptions.builder()
                .storeIntegrity(storeIntegrity)
                .argon2MemoryKib(TEST_MEMORY_KIB)
                .argon2Passes(TEST_PASSES)
                .argon2Threads(TEST_THREADS)
                .build();
        new MediaCryptCodec().encrypt(input, output, PASSWORD.getBytes(StandardCharsets.UTF_8),
                options);
    }

    /**
     * 用低 Argon2 参数生成一个真实的文件隐写载体（PNG）。
     *
     * @param dir 目录
     * @return 隐写载体路径
     * @throws Exception 嵌入失败
     */
    private static Path buildStegoPng(final Path dir) throws Exception {
        Path carrier = MediaFixtures.createPng(dir, "stego_carrier_src.png");
        Path secret = write(dir, "stego_secret.bin", new byte[512]);
        Path output = dir.resolve("stego_carrier.png");
        FileStegoOptions options = FileStegoOptions.builder()
                .argon2Params(new Argon2Params(TEST_MEMORY_KIB, TEST_PASSES, TEST_THREADS))
                .build();
        new FileStegoCodec().hide(carrier, secret, output,
                PASSWORD.getBytes(StandardCharsets.UTF_8), options);
        return output;
    }

    /**
     * 测试夹具：内存中构造最小合法的 WAV 与 PNG。
     */
    private static final class MediaFixtures {

        private MediaFixtures() {
        }

        /**
         * 构造一个合法的 16-bit PCM 单声道 WAV。
         *
         * @param pcmData data chunk 负载
         * @return WAV 字节
         */
        static byte[] buildWav(final byte[] pcmData) {
            int sampleRate = 44100;
            short channels = 1;
            short bitsPerSample = 16;
            int byteRate = sampleRate * channels * bitsPerSample / 8;
            short blockAlign = (short) (channels * bitsPerSample / 8);

            java.nio.ByteBuffer fmt = java.nio.ByteBuffer.allocate(16)
                    .order(java.nio.ByteOrder.LITTLE_ENDIAN);
            fmt.putShort((short) 1);
            fmt.putShort(channels);
            fmt.putInt(sampleRate);
            fmt.putInt(byteRate);
            fmt.putShort(blockAlign);
            fmt.putShort(bitsPerSample);

            java.io.ByteArrayOutputStream body = new java.io.ByteArrayOutputStream();
            writeChunk(body, "fmt ", fmt.array());
            writeChunk(body, "data", pcmData);
            byte[] bodyBytes = body.toByteArray();

            java.nio.ByteBuffer riff = java.nio.ByteBuffer.allocate(12 + bodyBytes.length)
                    .order(java.nio.ByteOrder.LITTLE_ENDIAN);
            riff.put("RIFF".getBytes(StandardCharsets.US_ASCII));
            riff.putInt(4 + bodyBytes.length);
            riff.put("WAVE".getBytes(StandardCharsets.US_ASCII));
            riff.put(bodyBytes);
            return riff.array();
        }

        /**
         * 生成一张小尺寸有效 PNG。
         *
         * @param dir  目录
         * @param name 文件名
         * @return PNG 路径
         * @throws Exception 写入失败
         */
        static Path createPng(final Path dir, final String name) throws Exception {
            BufferedImage image = new BufferedImage(32, 32, BufferedImage.TYPE_INT_RGB);
            Random random = new Random(42);
            for (int y = 0; y < 32; y++) {
                for (int x = 0; x < 32; x++) {
                    image.setRGB(x, y, random.nextInt());
                }
            }
            Path path = dir.resolve(name);
            ImageIO.write(image, "PNG", path.toFile());
            return path;
        }

        /**
         * 写入一个 RIFF 子块（奇数长度补齐）。
         *
         * @param out     输出流
         * @param id      块标识
         * @param payload 负载
         */
        private static void writeChunk(final java.io.ByteArrayOutputStream out, final String id,
                                       final byte[] payload) {
            try {
                out.write(id.getBytes(StandardCharsets.US_ASCII));
                java.nio.ByteBuffer size = java.nio.ByteBuffer.allocate(4)
                        .order(java.nio.ByteOrder.LITTLE_ENDIAN);
                size.putInt(payload.length);
                out.write(size.array());
                out.write(payload);
                if ((payload.length & 1) == 1) {
                    out.write(0);
                }
            } catch (java.io.IOException e) {
                throw new IllegalStateException(e);
            }
        }
    }
}
