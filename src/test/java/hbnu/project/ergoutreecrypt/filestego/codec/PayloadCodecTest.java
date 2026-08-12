package hbnu.project.ergoutreecrypt.filestego.codec;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import hbnu.project.ergoutreecrypt.filestego.api.PayloadException;
import hbnu.project.ergoutreecrypt.filestego.api.StegoEncodeOptions;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.Security;

/**
 * PayloadCodec STEG-V2 编解码测试。
 *
 * @author ErgouTree
 */
class PayloadCodecTest {

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }
    }

    // ---- 加密参数占位值 ----
    private static final byte[] TEST_SALT = fillBytes(16, 1);
    private static final byte[] TEST_HKDF_SALT = fillBytes(32, 50);
    private static final byte[] TEST_NONCE = fillBytes(24, 100);
    private static final byte[] TEST_PASSWORD = "test-payload-pwd".getBytes(StandardCharsets.UTF_8);

    // ---- 基础往返测试 ----

    @Test
    void roundtripBasic() throws Exception {
        byte[] plaintext = "Hello STEG-V2 Payload!".getBytes(StandardCharsets.UTF_8);

        StegoEncodeOptions opts = StegoEncodeOptions.builder()
                .hasIntegrity(true)
                .hasHeaderMac(true)
                .build();

        byte[] payload = PayloadCodec.encode(plaintext, "test.txt", TEST_PASSWORD,
                TEST_SALT, TEST_HKDF_SALT, TEST_NONCE, null, opts);

        assertNotNull(payload);
        assertTrue(payload.length > 0);
        assertTrue(PayloadCodec.isStegV2(payload));

        PayloadCodec.DecodeResult result = PayloadCodec.decode(payload, TEST_PASSWORD,
                TEST_SALT, TEST_HKDF_SALT, TEST_NONCE, null, false);

        assertArrayEquals(plaintext, result.plaintext());
        assertEquals("test.txt", result.header().origName());
        assertEquals(plaintext.length, result.header().origSize());
    }

    @Test
    void roundtripLargeData() throws Exception {
        // 1 MB 测试数据
        byte[] plaintext = new byte[1_000_000];
        for (int i = 0; i < plaintext.length; i++) {
            plaintext[i] = (byte) (i & 0xFF);
        }

        StegoEncodeOptions opts = StegoEncodeOptions.builder()
                .hasIntegrity(true)
                .hasHeaderMac(true)
                .build();

        byte[] payload = PayloadCodec.encode(plaintext, "large.bin", TEST_PASSWORD,
                TEST_SALT, TEST_HKDF_SALT, TEST_NONCE, null, opts);

        PayloadCodec.DecodeResult result = PayloadCodec.decode(payload, TEST_PASSWORD,
                TEST_SALT, TEST_HKDF_SALT, TEST_NONCE, null, false);

        assertArrayEquals(plaintext, result.plaintext());
        assertEquals("large.bin", result.header().origName());
        assertEquals(1_000_000L, result.header().origSize());
    }

    @Test
    void roundtripUnicodeFileName() throws Exception {
        byte[] plaintext = "data".getBytes(StandardCharsets.UTF_8);

        StegoEncodeOptions opts = StegoEncodeOptions.builder()
                .hasIntegrity(true)
                .hasHeaderMac(true)
                .build();

        byte[] payload = PayloadCodec.encode(plaintext, "中文文件名.txt", TEST_PASSWORD,
                TEST_SALT, TEST_HKDF_SALT, TEST_NONCE, null, opts);

        PayloadCodec.DecodeResult result = PayloadCodec.decode(payload, TEST_PASSWORD,
                TEST_SALT, TEST_HKDF_SALT, TEST_NONCE, null, false);

        assertEquals("中文文件名.txt", result.header().origName());
    }

    @Test
    void roundtripEmptyFile() throws Exception {
        byte[] plaintext = new byte[0];

        StegoEncodeOptions opts = StegoEncodeOptions.builder()
                .hasIntegrity(true)
                .hasHeaderMac(true)
                .build();

        byte[] payload = PayloadCodec.encode(plaintext, "empty.dat", TEST_PASSWORD,
                TEST_SALT, TEST_HKDF_SALT, TEST_NONCE, null, opts);

        PayloadCodec.DecodeResult result = PayloadCodec.decode(payload, TEST_PASSWORD,
                TEST_SALT, TEST_HKDF_SALT, TEST_NONCE, null, false);

        assertArrayEquals(plaintext, result.plaintext());
        assertEquals(0L, result.header().origSize());
    }

    // ---- Header 只读 ----

    @Test
    void readHeaderOnly() throws Exception {
        byte[] plaintext = "read header test".getBytes(StandardCharsets.UTF_8);

        StegoEncodeOptions opts = StegoEncodeOptions.builder()
                .hasIntegrity(true)
                .hasHeaderMac(true)
                .build();

        byte[] payload = PayloadCodec.encode(plaintext, "header test.json", TEST_PASSWORD,
                TEST_SALT, TEST_HKDF_SALT, TEST_NONCE, null, opts);

        PayloadCodec.PayloadHeader header = PayloadCodec.readHeader(payload);

        assertEquals("header test.json", header.origName());
        assertEquals(plaintext.length, header.origSize());
        assertEquals("application/json", header.mimeType());
        assertEquals(1, header.version());
    }

    // ---- 无完整性校验 ----

    @Test
    void roundtripNoIntegrity() throws Exception {
        byte[] plaintext = "no integrity check".getBytes(StandardCharsets.UTF_8);

        StegoEncodeOptions opts = StegoEncodeOptions.builder()
                .hasIntegrity(false)
                .hasHeaderMac(false)
                .build();

        byte[] payload = PayloadCodec.encode(plaintext, "no mac.dat", TEST_PASSWORD,
                TEST_SALT, TEST_HKDF_SALT, TEST_NONCE, null, opts);

        // payload 应该更短（无 MAC 字段）
        PayloadCodec.DecodeResult result = PayloadCodec.decode(payload, TEST_PASSWORD,
                TEST_SALT, TEST_HKDF_SALT, TEST_NONCE, null, false);

        assertArrayEquals(plaintext, result.plaintext());
    }

    // ---- 魔数检测 ----

    @Test
    void isStegV2Positive() throws Exception {
        byte[] plaintext = "test".getBytes(StandardCharsets.UTF_8);
        byte[] payload = PayloadCodec.encode(plaintext, "f", TEST_PASSWORD,
                TEST_SALT, TEST_HKDF_SALT, TEST_NONCE, null,
                StegoEncodeOptions.defaults());

        assertTrue(PayloadCodec.isStegV2(payload));
    }

    @Test
    void isStegV2Negative() {
        byte[] garbage = "not a steg payload".getBytes(StandardCharsets.UTF_8);
        assertFalse(PayloadCodec.isStegV2(garbage));
    }

    @Test
    void isStegV2TooShort() {
        byte[] shortData = new byte[]{0x53, 0x54}; // Only "ST"
        assertFalse(PayloadCodec.isStegV2(shortData));
    }

    @Test
    void isStegV2Empty() {
        assertFalse(PayloadCodec.isStegV2(new byte[0]));
    }

    // ---- 异常测试 ----

    @Test
    void badMagicThrows() throws Exception {
        byte[] garbage = new byte[200];
        // FIXME: garbage bytes won't match STG2 magic
        java.security.SecureRandom rng = new java.security.SecureRandom();
        rng.nextBytes(garbage);
        // Ensure first bytes are NOT STG2
        garbage[0] = 0x00;
        garbage[1] = 0x00;
        garbage[2] = 0x00;
        garbage[3] = 0x00;

        byte[] finalGarbage = garbage;
        assertThrows(PayloadException.class, () ->
                PayloadCodec.decode(finalGarbage, TEST_PASSWORD,
                        TEST_SALT, TEST_HKDF_SALT, TEST_NONCE, null, false));
    }

    @Test
    void tooShortPayloadThrows() {
        byte[] shortData = new byte[5];
        assertThrows(PayloadException.class, () ->
                PayloadCodec.decode(shortData, TEST_PASSWORD,
                        TEST_SALT, TEST_HKDF_SALT, TEST_NONCE, null, false));
    }

    @Test
    void wrongPasswordDetected() throws Exception {
        byte[] plaintext = "secret data".getBytes(StandardCharsets.UTF_8);

        StegoEncodeOptions opts = StegoEncodeOptions.builder()
                .hasIntegrity(true)
                .hasHeaderMac(true)
                .build();

        byte[] payload = PayloadCodec.encode(plaintext, "secret.txt", TEST_PASSWORD,
                TEST_SALT, TEST_HKDF_SALT, TEST_NONCE, null, opts);

        byte[] wrongPassword = "wrong-password".getBytes(StandardCharsets.UTF_8);

        assertThrows(PayloadException.class, () ->
                PayloadCodec.decode(payload, wrongPassword,
                        TEST_SALT, TEST_HKDF_SALT, TEST_NONCE, null, false));
    }

    @Test
    void wrongSaltDetected() throws Exception {
        byte[] plaintext = "salt test".getBytes(StandardCharsets.UTF_8);

        StegoEncodeOptions opts = StegoEncodeOptions.builder()
                .hasIntegrity(true)
                .hasHeaderMac(true)
                .build();

        byte[] payload = PayloadCodec.encode(plaintext, "f", TEST_PASSWORD,
                TEST_SALT, TEST_HKDF_SALT, TEST_NONCE, null, opts);

        byte[] wrongSalt = fillBytes(16, 99);

        assertThrows(PayloadException.class, () ->
                PayloadCodec.decode(payload, TEST_PASSWORD,
                        wrongSalt, TEST_HKDF_SALT, TEST_NONCE, null, false));
    }

    @Test
    void tamperedCiphertextDetected() throws Exception {
        byte[] plaintext = "tamper test data".getBytes(StandardCharsets.UTF_8);

        StegoEncodeOptions opts = StegoEncodeOptions.builder()
                .hasIntegrity(true)
                .hasHeaderMac(true)
                .build();

        byte[] payload = PayloadCodec.encode(plaintext, "f", TEST_PASSWORD,
                TEST_SALT, TEST_HKDF_SALT, TEST_NONCE, null, opts);

        // 篡改密文区域中间的一个字节
        int tamperIdx = payload.length / 2;
        payload[tamperIdx] ^= 0x01;

        byte[] finalPayload = payload;
        assertThrows(PayloadException.class, () ->
                PayloadCodec.decode(finalPayload, TEST_PASSWORD,
                        TEST_SALT, TEST_HKDF_SALT, TEST_NONCE, null, false));
    }

    // ---- 无密码模式 ----

    @Test
    void roundtripNoPassword() throws Exception {
        byte[] plaintext = "no password needed".getBytes(StandardCharsets.UTF_8);

        StegoEncodeOptions opts = StegoEncodeOptions.builder()
                .hasIntegrity(true)
                .hasHeaderMac(true)
                .build();

        byte[] payload = PayloadCodec.encode(plaintext, "public.txt", new byte[0],
                TEST_SALT, TEST_HKDF_SALT, TEST_NONCE, null, opts);

        // 用空密码提取
        PayloadCodec.DecodeResult result = PayloadCodec.decode(payload, new byte[0],
                TEST_SALT, TEST_HKDF_SALT, TEST_NONCE, null, false);

        assertArrayEquals(plaintext, result.plaintext());
        assertEquals("public.txt", result.header().origName());
    }

    // ---- 仅 Header MAC 无 Payload MAC ----

    @Test
    void headerMacOnly() throws Exception {
        byte[] plaintext = "header mac only".getBytes(StandardCharsets.UTF_8);

        StegoEncodeOptions opts = StegoEncodeOptions.builder()
                .hasIntegrity(false)
                .hasHeaderMac(true)
                .build();

        byte[] payload = PayloadCodec.encode(plaintext, "f", TEST_PASSWORD,
                TEST_SALT, TEST_HKDF_SALT, TEST_NONCE, null, opts);

        // 错误密码会因 Header MAC 失败而检测到
        byte[] wrongPwd = "wrong".getBytes(StandardCharsets.UTF_8);
        assertThrows(PayloadException.class, () ->
                PayloadCodec.decode(payload, wrongPwd,
                        TEST_SALT, TEST_HKDF_SALT, TEST_NONCE, null, false));

        // 正确密码解密成功
        PayloadCodec.DecodeResult result = PayloadCodec.decode(payload, TEST_PASSWORD,
                TEST_SALT, TEST_HKDF_SALT, TEST_NONCE, null, false);
        assertArrayEquals(plaintext, result.plaintext());
    }

    // ---- Header 大小计算 ----

    @Test
    void headerSizeCorrect() {
        // 元数据 JSON 长度取决于文件名
        int jsonLen = "{\"origName\":\"test.txt\",\"origSize\":100}".getBytes(StandardCharsets.UTF_8).length;
        int headerSize = PayloadCodec.computeHeaderSize(jsonLen, true);
        // HEADER_FIXED_SIZE(10) + jsonLen + MAC_SIZE(64) = 74 + jsonLen
        assertEquals(10 + jsonLen + 64, headerSize);
    }

    // ---- 辅助方法 ----

    private static byte[] fillBytes(final int length, final int startValue) {
        byte[] b = new byte[length];
        for (int i = 0; i < length; i++) {
            b[i] = (byte) (startValue + i);
        }
        return b;
    }
}
