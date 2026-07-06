package hbnu.project.ergoutreecrypt.stego;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Security;

/**
 * Chunk 结构隐写测试。
 *
 * @author ErgouTree
 */
class ChunkStegoTest {

    private static final byte[] PASSWORD = "chunk-test-pwd".getBytes(StandardCharsets.UTF_8);
    private final ImageStegoCodec codec = new ImageStegoCodec();

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }
    }

    private static Path createSmallPng(final Path dir, final String name) throws Exception {
        BufferedImage img = new BufferedImage(10, 10, BufferedImage.TYPE_INT_RGB);
        Path p = dir.resolve(name);
        ImageIO.write(img, "PNG", p.toFile());
        return p;
    }

    // ---- ChunkTrailer ----

    @Test
    void trailerRoundtrip() throws Exception {
        byte[] salt = new byte[16];
        byte[] hkdfSalt = new byte[32];
        byte[] nonce = new byte[24];
        for (int i = 0; i < 16; i++) salt[i] = (byte) i;
        for (int i = 0; i < 32; i++) hkdfSalt[i] = (byte) (i + 50);
        for (int i = 0; i < 24; i++) nonce[i] = (byte) (i + 100);

        ChunkTrailer t = new ChunkTrailer(12345L, "test.bin", salt, hkdfSalt, nonce,
                (byte) 2, null); // hasMac but no actual MAC data

        byte[] serialized = t.toBytes();
        ChunkTrailer restored = ChunkTrailer.fromBytes(serialized);

        assertEquals(12345L, restored.encryptedSize);
        assertEquals("test.bin", restored.fileName);
        assertArrayEquals(salt, restored.salt);
        assertArrayEquals(hkdfSalt, restored.hkdfSalt);
        assertArrayEquals(nonce, restored.nonce);
        assertTrue(restored.hasMac());
        assertFalse(restored.isParanoid());
    }

    @Test
    void trailerWithMac() throws Exception {
        byte[] mac = new byte[64];
        for (int i = 0; i < 64; i++) mac[i] = (byte) (i * 3);

        ChunkTrailer t = new ChunkTrailer(999L, "secret.dat",
                new byte[16], new byte[32], new byte[24], (byte) (1 | 2), mac);

        byte[] serialized = t.toBytes();
        ChunkTrailer restored = ChunkTrailer.fromBytes(serialized);

        assertTrue(restored.isParanoid());
        assertTrue(restored.hasMac());
        assertArrayEquals(mac, restored.payloadMac);
    }

    // ---- PngChunkStego engine ----

    @Test
    void embedAndExtractRaw(@TempDir Path dir) throws Exception {
        Path src = createSmallPng(dir, "src.png");
        Path stego = dir.resolve("stego.png");

        byte[] payload = "Hello Chunk Steganography!".getBytes(StandardCharsets.UTF_8);
        ChunkTrailer trailer = new ChunkTrailer(payload.length, "msg.txt",
                new byte[16], new byte[32], new byte[24], (byte) 0, null);

        PngChunkStego.embed(src, stego, payload, trailer);
        assertTrue(Files.exists(stego));
        // 隐写后的图片仍能被 ImageIO 正常读取
        BufferedImage result = ImageIO.read(stego.toFile());
        assertNotNull(result);
        assertEquals(10, result.getWidth());
        assertEquals(10, result.getHeight());

        // 提取
        PngChunkStego.ChunkExtractResult extracted = PngChunkStego.extract(stego);
        assertNotNull(extracted);
        assertArrayEquals(payload, extracted.encryptedPayload());
        assertEquals("msg.txt", extracted.trailer().fileName);
        assertEquals(payload.length, extracted.trailer().encryptedSize);
    }

    @Test
    void isChunkStegoDetection(@TempDir Path dir) throws Exception {
        Path src = createSmallPng(dir, "src.png");
        assertFalse(PngChunkStego.isChunkStego(src));

        Path stego = dir.resolve("stego.png");
        ChunkTrailer trailer = new ChunkTrailer(5, "x", new byte[16], new byte[32],
                new byte[24], (byte) 0, null);
        PngChunkStego.embed(src, stego, "hello".getBytes(StandardCharsets.UTF_8), trailer);
        assertTrue(PngChunkStego.isChunkStego(stego));
    }

    @Test
    void embedAndExtractLargePayload(@TempDir Path dir) throws Exception {
        // 测试大于像素容量的文件（用 10×10 小图嵌入 100KB 数据）
        Path src = createSmallPng(dir, "src.png");
        Path stego = dir.resolve("stego.png");

        byte[] largePayload = new byte[100_000];
        for (int i = 0; i < largePayload.length; i++) largePayload[i] = (byte) (i & 0xFF);

        ChunkTrailer trailer = new ChunkTrailer(largePayload.length, "large.bin",
                new byte[16], new byte[32], new byte[24], (byte) 0, null);

        PngChunkStego.embed(src, stego, largePayload, trailer);

        PngChunkStego.ChunkExtractResult extracted = PngChunkStego.extract(stego);
        assertArrayEquals(largePayload, extracted.encryptedPayload());
    }

    // ---- ImageStegoCodec 端到端 ----

    @Test
    void textFileRoundtrip(@TempDir Path dir) throws Exception {
        Path imagePath = createSmallPng(dir, "image.png");

        byte[] secret = "文件内容通过 Chunk 隐写保护。".getBytes(StandardCharsets.UTF_8);
        Path secretPath = dir.resolve("secret.txt");
        Files.write(secretPath, secret);

        Path stegoPath = dir.resolve("stego.png");
        Path outDir = Files.createDirectory(dir.resolve("extracted"));

        StegoOptions opts = StegoOptions.builder().storeMac(true).build();
        codec.hideChunk(imagePath, secretPath, stegoPath, PASSWORD, opts);

        // 隐写图片与原图视觉完全一致（未修改像素）
        BufferedImage stegoImg = ImageIO.read(stegoPath.toFile());
        assertNotNull(stegoImg);

        Path extracted = codec.extractChunk(stegoPath, outDir, PASSWORD);
        assertArrayEquals(secret, Files.readAllBytes(extracted));
    }

    @Test
    void wrongPasswordDetected(@TempDir Path dir) throws Exception {
        Path imagePath = createSmallPng(dir, "image.png");
        Path secretPath = dir.resolve("s.txt");
        Files.write(secretPath, "secret".getBytes(StandardCharsets.UTF_8));

        Path stegoPath = dir.resolve("stego.png");
        Path outDir = Files.createDirectory(dir.resolve("extracted"));

        codec.hideChunk(imagePath, secretPath, stegoPath, PASSWORD,
                StegoOptions.builder().storeMac(true).build());

        byte[] wrong = "wrong".getBytes(StandardCharsets.UTF_8);
        assertThrows(ImageStegoException.class,
                () -> codec.extractChunk(stegoPath, outDir, wrong));
    }

    @Test
    void noPasswordRoundtrip(@TempDir Path dir) throws Exception {
        Path imagePath = createSmallPng(dir, "image.png");
        Path secretPath = dir.resolve("s.txt");
        Files.write(secretPath, "no password".getBytes(StandardCharsets.UTF_8));

        Path stegoPath = dir.resolve("stego.png");
        Path outDir = Files.createDirectory(dir.resolve("extracted"));

        codec.hideChunk(imagePath, secretPath, stegoPath, new byte[0],
                StegoOptions.builder().storeMac(false).build());

        Path extracted = codec.extractChunk(stegoPath, outDir, new byte[0]);
        assertArrayEquals("no password".getBytes(StandardCharsets.UTF_8),
                Files.readAllBytes(extracted));
    }
}
