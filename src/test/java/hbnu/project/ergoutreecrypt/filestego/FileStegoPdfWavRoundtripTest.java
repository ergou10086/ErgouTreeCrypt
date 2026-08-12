package hbnu.project.ergoutreecrypt.filestego;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import hbnu.project.ergoutreecrypt.filestego.api.FileStegoOptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.security.Security;

/**
 * 文件隐写 PDF / WAV 载体端到端往返测试（M1.3 / M1.4）。
 *
 * <p>覆盖 PDF（%%EOF 后 Base64 注释块）与 WAV（追加 STEG chunk）在
 * normal / paranoid / stealth 三种模式下的 hide → extract 数据一致性、
 * 检测能力与容器结构完整性；并验证任意二进制内容（含 0x00、高位字节）都能被正确还原。
 *
 * @author ErgouTree
 */
class FileStegoPdfWavRoundtripTest {

    private static final byte[] PASSWORD = "pdf-wav-test-pwd".getBytes(StandardCharsets.UTF_8);

    private final FileStegoCodec codec = new FileStegoCodec();

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }
    }

    // ---- 载体与秘密文件构造 ----

    /**
     * 生成一个最小的合法 PDF（含 xref/trailer/%%EOF）。
     */
    private static Path createPdf(final Path dir, final String name) throws Exception {
        String pdf = "%PDF-1.4\n"
                + "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
                + "2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
                + "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n"
                + "xref\n0 4\n0000000000 65535 f \n"
                + "0000000009 00000 n \n0000000058 00000 n \n0000000115 00000 n \n"
                + "trailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n190\n%%EOF\n";
        Path p = dir.resolve(name);
        Files.write(p, pdf.getBytes(StandardCharsets.US_ASCII));
        return p;
    }

    /**
     * 生成一个最小的合法 16-bit 单声道 PCM WAV。
     *
     * @param dir     目录
     * @param name    文件名
     * @param samples 采样点数
     */
    private static Path createWav(final Path dir, final String name, final int samples)
            throws Exception {
        int dataBytes = samples * 2;
        int riffSize = 4 + (8 + 16) + (8 + dataBytes);
        ByteBuffer bb = ByteBuffer.allocate(8 + riffSize).order(ByteOrder.LITTLE_ENDIAN);
        bb.put("RIFF".getBytes(StandardCharsets.US_ASCII));
        bb.putInt(riffSize);
        bb.put("WAVE".getBytes(StandardCharsets.US_ASCII));
        // fmt  chunk
        bb.put("fmt ".getBytes(StandardCharsets.US_ASCII));
        bb.putInt(16);
        bb.putShort((short) 1);      // PCM
        bb.putShort((short) 1);      // mono
        bb.putInt(44100);            // sample rate
        bb.putInt(44100 * 2);        // byte rate
        bb.putShort((short) 2);      // block align
        bb.putShort((short) 16);     // bits per sample
        // data chunk
        bb.put("data".getBytes(StandardCharsets.US_ASCII));
        bb.putInt(dataBytes);
        SecureRandom r = new SecureRandom();
        byte[] pcm = new byte[dataBytes];
        r.nextBytes(pcm);
        bb.put(pcm);
        Path p = dir.resolve(name);
        Files.write(p, bb.array());
        return p;
    }

    /**
     * 生成指定大小的随机秘密文件。
     */
    private static Path createSecret(final Path dir, final String name, final int size)
            throws Exception {
        byte[] data = new byte[size];
        new SecureRandom().nextBytes(data);
        Path p = dir.resolve(name);
        Files.write(p, data);
        return p;
    }

    // ---- PDF ----

    @Test
    void pdfRoundtripNormal(@TempDir final Path dir) throws Exception {
        runPdfRoundtrip(dir, false, false);
    }

    @Test
    void pdfRoundtripParanoid(@TempDir final Path dir) throws Exception {
        runPdfRoundtrip(dir, true, false);
    }

    @Test
    void pdfRoundtripStealth(@TempDir final Path dir) throws Exception {
        runPdfRoundtrip(dir, false, true);
    }

    /**
     * PDF 往返核心流程。
     */
    private void runPdfRoundtrip(final Path dir, final boolean paranoid, final boolean stealth)
            throws Exception {
        Path carrier = createPdf(dir, "carrier.pdf");
        Path secret = createSecret(dir, "secret.bin", 48 * 1024);
        byte[] original = Files.readAllBytes(secret);
        Path stego = dir.resolve("stego.pdf");

        FileStegoOptions options = FileStegoOptions.builder()
                .paranoid(paranoid)
                .stealth(stealth)
                .build();

        codec.hide(carrier, secret, stego, PASSWORD, options);

        assertTrue(codec.isStegoFile(stego), "应能检测到 PDF 隐写数据");
        // 原 PDF 结构（%%EOF）应保留在追加块之前
        String content = Files.readString(stego, StandardCharsets.ISO_8859_1);
        assertTrue(content.contains("%%EOF"), "隐写后应仍保留原 PDF 的 %%EOF");
        assertTrue(content.contains("%STEG-BEGIN"), "应包含隐写起始标记");

        Path outDir = dir.resolve("out");
        Path extracted = codec.extract(stego, outDir, PASSWORD);
        byte[] restored = Files.readAllBytes(extracted);

        assertEquals("secret.bin", extracted.getFileName().toString());
        assertArrayEquals(original, restored, "PDF 还原内容应与原文一致");
    }

    // ---- WAV ----

    @Test
    void wavRoundtripNormal(@TempDir final Path dir) throws Exception {
        runWavRoundtrip(dir, false, false, 1000);
    }

    @Test
    void wavRoundtripParanoid(@TempDir final Path dir) throws Exception {
        runWavRoundtrip(dir, true, false, 1000);
    }

    @Test
    void wavRoundtripStealth(@TempDir final Path dir) throws Exception {
        runWavRoundtrip(dir, false, true, 1000);
    }

    /**
     * WAV 往返核心流程。
     */
    private void runWavRoundtrip(final Path dir, final boolean paranoid, final boolean stealth,
                                 final int samples) throws Exception {
        Path carrier = createWav(dir, "carrier.wav", samples);
        byte[] carrierBefore = Files.readAllBytes(carrier);
        Path secret = createSecret(dir, "payload.dat", 32 * 1024);
        byte[] original = Files.readAllBytes(secret);
        Path stego = dir.resolve("stego.wav");

        FileStegoOptions options = FileStegoOptions.builder()
                .paranoid(paranoid)
                .stealth(stealth)
                .build();

        codec.hide(carrier, secret, stego, PASSWORD, options);

        assertTrue(codec.isStegoFile(stego), "应能检测到 WAV 隐写数据");
        // RIFF size 字段应被更新为覆盖新增 STEG chunk
        assertTrue(riffSizeConsistent(stego), "RIFF size 字段应与文件实际长度一致");
        // 原 fmt/data chunk 内容应保持不变（隐写只追加，不改动原音频）
        byte[] stegoBytes = Files.readAllBytes(stego);
        assertArrayEquals(
                java.util.Arrays.copyOfRange(carrierBefore, 12, carrierBefore.length),
                java.util.Arrays.copyOfRange(stegoBytes, 12, carrierBefore.length),
                "原 WAV chunk 数据不应被改动");

        Path outDir = dir.resolve("out");
        Path extracted = codec.extract(stego, outDir, PASSWORD);
        byte[] restored = Files.readAllBytes(extracted);

        assertEquals("payload.dat", extracted.getFileName().toString());
        assertArrayEquals(original, restored, "WAV 还原内容应与原文一致");
    }

    /**
     * 校验 WAV 的 RIFF size 字段 == 文件长度 - 8。
     */
    private static boolean riffSizeConsistent(final Path wav) throws Exception {
        byte[] bytes = Files.readAllBytes(wav);
        long declared = (bytes[4] & 0xFFL)
                | ((bytes[5] & 0xFFL) << 8)
                | ((bytes[6] & 0xFFL) << 16)
                | ((bytes[7] & 0xFFL) << 24);
        return declared == bytes.length - 8L;
    }

    // ---- 边界：奇数长度 payload 的 WAV chunk 对齐 ----

    @Test
    void wavOddLengthPayloadRoundtrip(@TempDir final Path dir) throws Exception {
        Path carrier = createWav(dir, "carrier.wav", 501);
        // 选一个能触发 combined 奇数长度的秘密大小（借助随机内容，验证对齐鲁棒性）
        Path secret = createSecret(dir, "odd.bin", 1023);
        byte[] original = Files.readAllBytes(secret);
        Path stego = dir.resolve("stego.wav");

        codec.hide(carrier, secret, stego, PASSWORD, FileStegoOptions.defaults());

        assertTrue(riffSizeConsistent(stego), "奇数 payload 下 RIFF size 仍应一致");
        Path extracted = codec.extract(stego, dir.resolve("out"), PASSWORD);
        assertArrayEquals(original, Files.readAllBytes(extracted), "奇数长度 payload 应正确还原");
    }

    // ---- 负向：干净文件不应被误判 ----

    @Test
    void cleanCarrierNotDetected(@TempDir final Path dir) throws Exception {
        Path pdf = createPdf(dir, "clean.pdf");
        Path wav = createWav(dir, "clean.wav", 500);
        assertFalse(codec.isStegoFile(pdf), "干净 PDF 不应被判为隐写");
        assertFalse(codec.isStegoFile(wav), "干净 WAV 不应被判为隐写");
    }
}
