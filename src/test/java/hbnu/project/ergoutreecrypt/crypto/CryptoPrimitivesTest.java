package hbnu.project.ergoutreecrypt.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import java.nio.charset.StandardCharsets;
import java.security.Security;

import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * 密码学原语的健全性与确定性测试（M1）。
 *
 * <p>这些测试不依赖 Go 端导出向量，但能：
 * <ul>
 *   <li>确保实现确定（同输入同输出），便于后续与 Go golden 向量比对；</li>
 *   <li>覆盖 SerpentCtr / MacFactory / HKDF / SubkeyReader / CipherSuite 的基本契约。</li>
 * </ul>
 * 后续 M5 会加入从 Go 导出的端到端 golden 向量做最终字节对齐。
 */
class CryptoPrimitivesTest {

    @BeforeAll
    static void setup() {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }
    }

    @Test
    void argon2Deterministic() {
        byte[] pw = "correct horse battery staple".getBytes(StandardCharsets.UTF_8);
        byte[] salt = Hex.decode("000102030405060708090a0b0c0d0e0f");

        // 使用偏执模式参数会非常慢（8 passes / 1 GiB），此处仅验证普通模式的确定性。
        byte[] k1 = Argon2Kdf.deriveKey(pw, salt, false);
        byte[] k2 = Argon2Kdf.deriveKey(pw, salt, false);

        assertEquals(32, k1.length);
        assertArrayEquals(k1, k2, "Argon2 应对相同输入产生相同输出");
    }

    @Test
    void serpentCtrInvolution() {
        byte[] key = new byte[32];
        byte[] iv = new byte[16];
        for (int i = 0; i < 32; i++) {
            key[i] = (byte) (i * 3);
        }
        for (int i = 0; i < 16; i++) {
            iv[i] = (byte) (i + 7);
        }
        byte[] plain = "Serpent-CTR round trip 测试".getBytes(StandardCharsets.UTF_8);

        byte[] ct = new byte[plain.length];
        new SerpentCtr(key, iv).process(ct, plain, plain.length);
        assertFalse(java.util.Arrays.equals(plain, ct), "密文不应等于明文");

        byte[] back = new byte[plain.length];
        new SerpentCtr(key, iv).process(back, ct, ct.length);
        assertArrayEquals(plain, back);
    }

    @Test
    void blake2bMacIsKeyedAndDeterministic() {
        byte[] subkey = new byte[32];
        for (int i = 0; i < 32; i++) {
            subkey[i] = (byte) i;
        }
        byte[] data = "payload".getBytes(StandardCharsets.UTF_8);

        Mac m1 = MacFactory.create(subkey, false);
        m1.update(data, data.length);
        byte[] t1 = m1.doFinal();

        Mac m2 = MacFactory.create(subkey, false);
        m2.update(data, data.length);
        byte[] t2 = m2.doFinal();

        assertEquals(64, t1.length, "BLAKE2b-512 应输出 64 字节");
        assertArrayEquals(t1, t2);
    }

    @Test
    void hmacSha3MacSize() {
        byte[] subkey = new byte[32];
        Mac m = MacFactory.create(subkey, true);
        byte[] data = "payload".getBytes(StandardCharsets.UTF_8);
        m.update(data, data.length);
        assertEquals(64, m.doFinal().length, "HMAC-SHA3-512 应输出 64 字节");
    }

    @Test
    void hkdfSubkeyReaderOrderAndSizes() {
        byte[] key = new byte[32];
        byte[] salt = new byte[32];
        for (int i = 0; i < 32; i++) {
            key[i] = (byte) i;
            salt[i] = (byte) (31 - i);
        }

        SubkeyReader r = new SubkeyReader(new HkdfStream(key, salt));
        byte[] header = r.headerSubkey();
        byte[] mac = r.macSubkey();
        byte[] serpent = r.serpentKey();

        assertEquals(64, header.length);
        assertEquals(32, mac.length);
        assertEquals(32, serpent.length);
        assertNotEquals(Hex.toHexString(mac), Hex.toHexString(serpent));

        // 同样的 key/salt 应得到完全相同的流（确定性）。
        SubkeyReader r2 = new SubkeyReader(new HkdfStream(key, salt));
        assertArrayEquals(header, r2.headerSubkey());
        assertArrayEquals(mac, r2.macSubkey());
        assertArrayEquals(serpent, r2.serpentKey());
    }

    @Test
    void cipherSuiteNormalRoundTrip() {
        byte[] key = new byte[32];
        byte[] nonce = new byte[24];
        for (int i = 0; i < 32; i++) {
            key[i] = (byte) (i + 1);
        }
        for (int i = 0; i < 24; i++) {
            nonce[i] = (byte) (i + 2);
        }
        byte[] hkdfKey = new byte[32];
        byte[] hkdfSalt = new byte[32];

        byte[] plain = new byte[1000];
        for (int i = 0; i < plain.length; i++) {
            plain[i] = (byte) (i % 251);
        }

        // 加密
        HkdfStream encStream = new HkdfStream(hkdfKey, hkdfSalt);
        Mac encMac = MacFactory.create(new byte[32], false);
        byte[] ct = new byte[plain.length];
        byte[] encTag;
        try (CipherSuite enc = new CipherSuite(key, nonce, new byte[32], new byte[16],
                encMac, encStream, false)) {
            enc.encrypt(ct, plain, plain.length);
            encTag = enc.sum();
        }
        assertFalse(java.util.Arrays.equals(plain, ct));

        // 解密
        HkdfStream decStream = new HkdfStream(hkdfKey, hkdfSalt);
        Mac decMac = MacFactory.create(new byte[32], false);
        byte[] back = new byte[plain.length];
        byte[] decTag;
        try (CipherSuite dec = new CipherSuite(key, nonce, new byte[32], new byte[16],
                decMac, decStream, false)) {
            dec.decrypt(back, ct, ct.length);
            decTag = dec.sum();
        }

        assertArrayEquals(plain, back, "普通模式 CipherSuite 往返应还原明文");
        assertArrayEquals(encTag, decTag, "加解密两端 MAC 应一致");
    }

    @Test
    void cipherSuiteParanoidRoundTrip() {
        byte[] key = new byte[32];
        byte[] nonce = new byte[24];
        byte[] serpentKey = new byte[32];
        byte[] serpentIv = new byte[16];
        for (int i = 0; i < 32; i++) {
            key[i] = (byte) (i + 1);
            serpentKey[i] = (byte) (i + 5);
        }
        for (int i = 0; i < 24; i++) {
            nonce[i] = (byte) (i + 2);
        }
        for (int i = 0; i < 16; i++) {
            serpentIv[i] = (byte) (i + 9);
        }

        byte[] plain = "偏执模式：Serpent-CTR → XChaCha20 → MAC".getBytes(StandardCharsets.UTF_8);

        Mac encMac = MacFactory.create(new byte[32], true);
        byte[] ct = new byte[plain.length];
        try (CipherSuite enc = new CipherSuite(key, nonce, serpentKey, serpentIv,
                encMac, new HkdfStream(new byte[32], new byte[32]), true)) {
            enc.encrypt(ct, plain, plain.length);
        }

        Mac decMac = MacFactory.create(new byte[32], true);
        byte[] back = new byte[plain.length];
        try (CipherSuite dec = new CipherSuite(key, nonce, serpentKey, serpentIv,
                decMac, new HkdfStream(new byte[32], new byte[32]), true)) {
            dec.decrypt(back, ct, ct.length);
        }

        assertArrayEquals(plain, back, "偏执模式 CipherSuite 往返应还原明文");
    }
}
