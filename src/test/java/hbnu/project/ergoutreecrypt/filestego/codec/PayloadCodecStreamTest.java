package hbnu.project.ergoutreecrypt.filestego.codec;

import hbnu.project.ergoutreecrypt.filestego.api.Argon2Params;
import hbnu.project.ergoutreecrypt.filestego.api.PayloadException;
import hbnu.project.ergoutreecrypt.filestego.api.StegoEncodeOptions;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * PayloadCodec 流式编解码（encodeToFile / decodeToFile）测试。
 *
 * <p>重点验证：流式与 byte[] 路径字节恒等、流式往返正确、
 * MAC 失败删除输出、密码错误不产生输出、Argon2 覆写往返。
 *
 * @author ErgouTree
 * @since 2026/8/14
 */
class PayloadCodecStreamTest {

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }
    }

    private static final byte[] TEST_SALT = fillBytes(16, 1);
    private static final byte[] TEST_HKDF_SALT = fillBytes(32, 50);
    private static final byte[] TEST_NONCE = fillBytes(24, 100);
    private static final byte[] TEST_PASSWORD = "test-stream-pwd".getBytes(StandardCharsets.UTF_8);

    /**
     * 低内存 Argon2 覆写（64 MiB / 2 passes / 2 threads），加速测试。
     */
    private static final Argon2Params LOW_MEM = new Argon2Params(64 * 1024, 2, 2);

    /**
     * 生成填充字节。
     */
    private static byte[] fillBytes(final int len, final int seed) {
        byte[] b = new byte[len];
        for (int i = 0; i < len; i++) {
            b[i] = (byte) (seed + i);
        }
        return b;
    }

    /**
     * 生成 2 MiB 伪随机明文（跨多个 1 MiB 流式分块）。
     */
    private static byte[] plainData() {
        byte[] b = new byte[2 * 1024 * 1024 + 777];
        for (int i = 0; i < b.length; i++) {
            b[i] = (byte) ((i * 31 + 7) & 0xFF);
        }
        return b;
    }

    /**
     * 流式编码与 byte[] 编码对相同输入产出字节完全一致的 Payload（普通模式）。
     */
    @Test
    void encodeToFileByteIdenticalNormal(@TempDir final Path dir) throws Exception {
        byte[] plaintext = plainData();
        StegoEncodeOptions opts = StegoEncodeOptions.builder()
                .hasIntegrity(true)
                .hasHeaderMac(true)
                .build();
        byte[] expected = PayloadCodec.encode(plaintext, "data.bin", TEST_PASSWORD,
                TEST_SALT, TEST_HKDF_SALT, TEST_NONCE, null, opts);

        Path plain = dir.resolve("plain.bin");
        Files.write(plain, plaintext);
        Path payloadFile = dir.resolve("payload.stg2");
        PayloadCodec.encodeToFile(plain, payloadFile, "data.bin", TEST_PASSWORD,
                TEST_SALT, TEST_HKDF_SALT, TEST_NONCE, null, opts);

        assertArrayEquals(expected, Files.readAllBytes(payloadFile),
                "流式编码应与 byte[] 编码字节一致");
    }

    /**
     * 流式编码与 byte[] 编码字节恒等（paranoid + Argon2 覆写）。
     */
    @Test
    void encodeToFileByteIdenticalParanoidWithOverride(@TempDir final Path dir) throws Exception {
        byte[] plaintext = plainData();
        byte[] serpentIv = fillBytes(16, 200);
        StegoEncodeOptions opts = StegoEncodeOptions.builder()
                .paranoid(true)
                .hasIntegrity(true)
                .hasHeaderMac(true)
                .argon2Params(LOW_MEM)
                .build();
        byte[] expected = PayloadCodec.encode(plaintext, "video.mp4", TEST_PASSWORD,
                TEST_SALT, TEST_HKDF_SALT, TEST_NONCE, serpentIv, opts);

        Path plain = dir.resolve("plain.bin");
        Files.write(plain, plaintext);
        Path payloadFile = dir.resolve("payload.stg2");
        PayloadCodec.encodeToFile(plain, payloadFile, "video.mp4", TEST_PASSWORD,
                TEST_SALT, TEST_HKDF_SALT, TEST_NONCE, serpentIv, opts);

        assertArrayEquals(expected, Files.readAllBytes(payloadFile),
                "paranoid 流式编码应与 byte[] 编码字节一致");
    }

    /**
     * 流式解码与 byte[] 解码对相同 Payload 产出完全一致的明文。
     */
    @Test
    void decodeToFileMatchesByteArrayDecode(@TempDir final Path dir) throws Exception {
        byte[] plaintext = plainData();
        byte[] serpentIv = fillBytes(16, 200);
        StegoEncodeOptions opts = StegoEncodeOptions.builder()
                .paranoid(true)
                .hasIntegrity(true)
                .hasHeaderMac(true)
                .argon2Params(LOW_MEM)
                .build();
        byte[] payload = PayloadCodec.encode(plaintext, "secret.bin", TEST_PASSWORD,
                TEST_SALT, TEST_HKDF_SALT, TEST_NONCE, serpentIv, opts);

        PayloadCodec.DecodeResult expected = PayloadCodec.decode(payload, TEST_PASSWORD,
                TEST_SALT, TEST_HKDF_SALT, TEST_NONCE, serpentIv, true, LOW_MEM);

        Path payloadFile = dir.resolve("payload.stg2");
        Files.write(payloadFile, payload);
        Path plainOut = dir.resolve("plain.out");
        PayloadCodec.PayloadHeader header = PayloadCodec.decodeToFile(payloadFile, plainOut,
                TEST_PASSWORD, TEST_SALT, TEST_HKDF_SALT, TEST_NONCE, serpentIv, true, LOW_MEM);

        assertArrayEquals(expected.plaintext(), Files.readAllBytes(plainOut),
                "流式解码应与 byte[] 解码明文一致");
        assertEquals("secret.bin", header.origName());
    }

    /**
     * Payload MAC 篡改：流式解码必须删除输出文件并抛出异常。
     */
    @Test
    void decodeToFileTamperedMacDeletesOutput(@TempDir final Path dir) throws Exception {
        byte[] plaintext = plainData();
        StegoEncodeOptions opts = StegoEncodeOptions.builder()
                .hasIntegrity(true)
                .hasHeaderMac(true)
                .argon2Params(LOW_MEM)
                .build();
        byte[] payload = PayloadCodec.encode(plaintext, "data.bin", TEST_PASSWORD,
                TEST_SALT, TEST_HKDF_SALT, TEST_NONCE, null, opts);
        // 篡改密文中间一个字节（Payload MAC 必然失败）
        payload[payload.length / 2] ^= 0x01;

        Path payloadFile = dir.resolve("payload.stg2");
        Files.write(payloadFile, payload);
        Path plainOut = dir.resolve("plain.out");

        assertThrows(PayloadException.class, () -> PayloadCodec.decodeToFile(payloadFile,
                plainOut, TEST_PASSWORD, TEST_SALT, TEST_HKDF_SALT, TEST_NONCE,
                null, false, LOW_MEM));
        assertFalse(Files.exists(plainOut), "MAC 校验失败后输出文件应被删除");
    }

    /**
     * 密码错误：Header MAC 快速失败，且不产生任何输出文件。
     */
    @Test
    void decodeToFileWrongPasswordNoOutput(@TempDir final Path dir) throws Exception {
        byte[] plaintext = plainData();
        StegoEncodeOptions opts = StegoEncodeOptions.builder()
                .hasIntegrity(true)
                .hasHeaderMac(true)
                .argon2Params(LOW_MEM)
                .build();
        byte[] payload = PayloadCodec.encode(plaintext, "data.bin", TEST_PASSWORD,
                TEST_SALT, TEST_HKDF_SALT, TEST_NONCE, null, opts);

        Path payloadFile = dir.resolve("payload.stg2");
        Files.write(payloadFile, payload);
        Path plainOut = dir.resolve("plain.out");

        assertThrows(PayloadException.class, () -> PayloadCodec.decodeToFile(payloadFile,
                plainOut, "wrong-password".getBytes(StandardCharsets.UTF_8),
                TEST_SALT, TEST_HKDF_SALT, TEST_NONCE, null, false, LOW_MEM));
        assertFalse(Files.exists(plainOut), "密码错误时不应产生输出文件");
    }

    /**
     * 空文件流式往返：密文为空但布局完整（header + MAC）。
     */
    @Test
    void streamRoundtripEmptyFile(@TempDir final Path dir) throws Exception {
        StegoEncodeOptions opts = StegoEncodeOptions.builder()
                .hasIntegrity(true)
                .hasHeaderMac(true)
                .argon2Params(LOW_MEM)
                .build();
        Path plain = dir.resolve("empty.dat");
        Files.write(plain, new byte[0]);
        Path payloadFile = dir.resolve("payload.stg2");
        PayloadCodec.encodeToFile(plain, payloadFile, "empty.dat", TEST_PASSWORD,
                TEST_SALT, TEST_HKDF_SALT, TEST_NONCE, null, opts);

        Path plainOut = dir.resolve("empty.out");
        PayloadCodec.PayloadHeader header = PayloadCodec.decodeToFile(payloadFile, plainOut,
                TEST_PASSWORD, TEST_SALT, TEST_HKDF_SALT, TEST_NONCE, null, false, LOW_MEM);

        assertEquals(0, Files.size(plainOut));
        assertEquals("empty.dat", header.origName());
        assertTrue(Files.exists(plainOut));
    }
}
