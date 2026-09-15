package hbnu.project.ergoutreecrypt.imagecrypt;

import hbnu.project.ergoutreecrypt.crypto.Mac;
import hbnu.project.ergoutreecrypt.crypto.XChaCha20;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.text.Normalizer;
import java.util.Arrays;

import static hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptTestSupport.hex;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * EGTC-IMG v1 的永久黄金向量。
 *
 * <h3>这些断言代表什么</h3>
 * <p>每一条十六进制常量都是 v1 协议的跨语言契约：把同一张协议表实现在 Kotlin、C 或
 * Rust 中，只要按 {@link ImageCryptProtocol} 的偏移与算法参数计算，就应当得到完全相同的
 * 字节。任何一条断言失败都说明 v1 契约被破坏，需要提升协议版本，<b>而不是</b>更新这里的
 * 常量。
 *
 * <h3>为什么只冻结"逻辑字节"</h3>
 * <p>这里冻结的是反滤波后的 EGTC-IMG 帧（协议头、密文、认证标签）与密码学中间值，
 * <b>不</b>包括外层 PNG 的 zlib 压缩字节。不同 JVM 与 Android 实现可以生成字节不同但
 * 像素相同的合法 PNG，因此跨端判断必须比较帧与恢复结果，而不是比较整张密文 PNG 的 SHA-256。
 *
 * <h3>覆盖范围</h3>
 * <ul>
 *   <li>公开恢复：随机主密钥 → HKDF → XChaCha20 → keyConfirm → 认证标签；</li>
 *   <li>密码保护：ASCII 口令，固定 Argon2id 互操作档；</li>
 *   <li>组合字符口令：NFC 与 NFD 输入必须导出同一把密钥。</li>
 * </ul>
 *
 * @author ErgouTree
 * @since 2026/9/15
 */
final class ImageCryptGoldenVectorTest {

    /**
     * 组合字符口令的 NFC 形式（caf + U+00E9 + 连字符 + 两个汉字）。
     */
    private static final String COMPOSED_PASSWORD = "café-中文";

    /**
     * 公开恢复向量的确定性随机种子。
     */
    private static final long PUBLIC_SEED = 0x5EEDL;

    /** 公开恢复向量：确定性随机源给出的随机主密钥。 */
    private static final String V_PUBLIC_MASTER_KEY =
            "c64f14afd84b9a2e620777ca7d4bfaeb6da1a0cb53281510938c23a5d3d938ed";

    /** 公开恢复向量：确定性随机源给出的 HKDF salt。 */
    private static final String V_PUBLIC_HKDF_SALT =
            "5a85309a082dd6dee34e92aba610c56fe7a5a7ef55a7685ab28070c91162d3e2";

    /** 公开恢复向量：确定性随机源给出的 XChaCha20 nonce。 */
    private static final String V_PUBLIC_NONCE =
            "4aae9dfc442c801db11bedd1c711d0f2c923f986a0c13b8e";

    /** 公开恢复向量：HKDF 域分离得到的加密子密钥。 */
    private static final String V_PUBLIC_ENC_KEY =
            "d7dfe9b079f6adab92c9b6fb0cb92c4313fd6d01e95379a1e7293d337a7db58c";

    /** 公开恢复向量：HKDF 域分离得到的 MAC 子密钥。 */
    private static final String V_PUBLIC_MAC_KEY =
            "dda479ee04dc66b883c04ca9a68eede08eacacc58bcf7a6156ad3fdc8f1714a3";

    /** 公开恢复向量：keyConfirm。 */
    private static final String V_PUBLIC_KEY_CONFIRM = "0e4cee8baf1255b0a78873e15cc542bc";

    /** 公开恢复向量：完整 184 字节协议头。 */
    private static final String V_PUBLIC_HEADER =
            "454754432d494d4701000101000300b800000040000000400000000000000055000000000000005500000500000002d0000000000000000000000000000000000000000000000000000000005a85309a082dd6dee34e92aba610c56fe7a5a7ef55a7685ab28070c91162d3e24aae9dfc442c801db11bedd1c711d0f2c923f986a0c13b8ec64f14afd84b9a2e620777ca7d4bfaeb6da1a0cb53281510938c23a5d3d938ed0e4cee8baf1255b0a78873e15cc542bca0530c30";

    /** 公开恢复向量：XChaCha20 密文。 */
    private static final String V_PUBLIC_CIPHERTEXT =
            "2bf08e9cfc385852c4b9a715c9e38322a913685857ebe82cac29bae8e4679e1e45a0901f2e5c44cbd257d782a2ce08308d3cf934d2cfd11af0b9bb42f697b83a2f2e5f91b0312b794f9cbf0388f74f4b30ac2172d0";

    /** 公开恢复向量：keyed BLAKE2b-512 认证标签。 */
    private static final String V_PUBLIC_AUTH_TAG =
            "6d5a64f713919265fe731da6de8b95871c80a48b4fd0d91281c7adbf3482f4f88564ca3195c3db89008118e8e161bdc2ff99459c494ba83bf380cb33a78ee655";

    /** 密码保护向量：ASCII 口令的规范化字节。 */
    private static final String V_PASSWORD_ASCII_BYTES =
            "636f727265637420686f727365206261747465727920737461706c65";

    /** 密码保护向量：组合字符口令的 NFC 规范化字节。 */
    private static final String V_PASSWORD_UNICODE_BYTES = "636166c3a92de4b8ade69687";

    /** 密码保护向量：Argon2id salt。 */
    private static final String V_PASSWORD_ARGON2_SALT = "000102030405060708090a0b0c0d0e0f";

    /** 密码保护向量：HKDF salt。 */
    private static final String V_PASSWORD_HKDF_SALT =
            "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf";

    /** 密码保护向量：XChaCha20 nonce。 */
    private static final String V_PASSWORD_NONCE =
            "101112131415161718191a1b1c1d1e1f2021222324252627";

    /** 密码保护向量：HKDF 域分离得到的加密子密钥。 */
    private static final String V_PASSWORD_ENC_KEY =
            "88c045f540728f2d3bdb37bde1b424873cf50a4955209b214100c27534da704b";

    /** 密码保护向量：HKDF 域分离得到的 MAC 子密钥。 */
    private static final String V_PASSWORD_MAC_KEY =
            "356b36c33af407b49ec53111fed5ab1f4ec5b69bd46e01df463e833b53846f3b";

    /** 密码保护向量：keyConfirm。 */
    private static final String V_PASSWORD_KEY_CONFIRM = "0ab4679acb562a51112b7832a19fcdc8";

    /** 密码保护向量：完整 184 字节协议头。 */
    private static final String V_PASSWORD_HEADER =
            "454754432d494d4701010101010300b80000004000000040000000000000004d000000000000004d00000500000002d0000100000000000300040000000102030405060708090a0b0c0d0e0fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf101112131415161718191a1b1c1d1e1f202122232425262700000000000000000000000000000000000000000000000000000000000000000ab4679acb562a51112b7832a19fcdc84b09a405";

    /** 密码保护向量：XChaCha20 密文。 */
    private static final String V_PASSWORD_CIPHERTEXT =
            "8ac5272ae0e3203726526f014db2e8126c1048e62918cd2a3073a53ac894dbb2f842106ce645bcf77cfefee1089398a1e59137c39c2651a711580d31d45f1f453a19095ccdde4c314f3bd62579";

    /** 密码保护向量：keyed BLAKE2b-512 认证标签。 */
    private static final String V_PASSWORD_AUTH_TAG =
            "d5cf11c11815fa4e563b3a2119467aca12a97817511777d3d0d2772f6e95f2e81c91bb7f10e8965640a9648296f78117c37c4ef6c7ecce3adbd4baebe1d98996";

    /** 组合字符口令（ASCII 口令之外的另一条分支）导出的加密子密钥。 */
    private static final String V_UNICODE_ENC_KEY =
            "0c1494963a407815f1586a7aa67341254ac356ab2f63cb744a6f117e2cc3a6d3";

    // ================================================================
    // 公开恢复
    // ================================================================

    @Test
    void publicRecoveryVectorIsFrozen() throws Exception {
        DeterministicRandomSource random = new DeterministicRandomSource(PUBLIC_SEED);
        byte[] masterKey = random.nextBytes(ImageCryptProtocol.MASTER_KEY_LENGTH);
        byte[] hkdfSalt = random.nextBytes(ImageCryptProtocol.HKDF_SALT_LENGTH);
        byte[] nonce = random.nextBytes(ImageCryptProtocol.NONCE_LENGTH);

        assertEquals(V_PUBLIC_MASTER_KEY, hex(masterKey), "随机源本身必须可复现");
        assertEquals(V_PUBLIC_HKDF_SALT, hex(hkdfSalt));
        assertEquals(V_PUBLIC_NONCE, hex(nonce));

        byte[] plain = publicPlaintext();
        ImageCryptFrame frame = ImageCryptFrame.newPublicFrame(64, 64, plain.length,
                1280, 720, hkdfSalt, nonce, masterKey);

        try (ImageKeySchedule schedule = ImageKeySchedule.fromPublicMasterKey(masterKey, hkdfSalt)) {
            assertEquals(V_PUBLIC_ENC_KEY, hex(schedule.encKey()));
            assertEquals(V_PUBLIC_MAC_KEY, hex(schedule.macKey()));

            frame = frame.withKeyConfirm(schedule.computeKeyConfirm(frame.keyConfirmPrefixBytes()));
            assertEquals(V_PUBLIC_KEY_CONFIRM, hex(frame.keyConfirm()));

            byte[] header = frame.toBytes();
            assertEquals(V_PUBLIC_HEADER, hex(header));
            assertArrayEquals(header, ImageCryptFrame.fromBytes(header).toBytes(),
                    "协议头必须能无损往返");

            XChaCha20 cipher = new XChaCha20(schedule.encKey(), nonce);
            byte[] ciphertext = new byte[plain.length];
            cipher.process(ciphertext, plain, plain.length);
            assertEquals(V_PUBLIC_CIPHERTEXT, hex(ciphertext));
            assertEquals(V_PUBLIC_AUTH_TAG, hex(authTag(schedule, frame, ciphertext)));
        }
    }

    // ================================================================
    // 密码保护
    // ================================================================

    @Test
    void passwordVectorIsFrozen() throws Exception {
        byte[] asciiPassword = ImageCryptPassword.encodeForV1("correct horse battery staple");
        assertEquals(V_PASSWORD_ASCII_BYTES, hex(asciiPassword));

        byte[] argon2Salt = hex(V_PASSWORD_ARGON2_SALT);
        byte[] hkdfSalt = hex(V_PASSWORD_HKDF_SALT);
        byte[] nonce = hex(V_PASSWORD_NONCE);
        byte[] plain = passwordPlaintext();

        ImageCryptFrame frame = ImageCryptFrame.newPasswordFrame(64, 64, plain.length,
                1280, 720, argon2Salt, hkdfSalt, nonce);

        try (ImageKeySchedule schedule = ImageKeySchedule.fromPassword(
                asciiPassword, argon2Salt, hkdfSalt, null)) {
            assertEquals(V_PASSWORD_ENC_KEY, hex(schedule.encKey()));
            assertEquals(V_PASSWORD_MAC_KEY, hex(schedule.macKey()));

            frame = frame.withKeyConfirm(schedule.computeKeyConfirm(frame.keyConfirmPrefixBytes()));
            assertEquals(V_PASSWORD_KEY_CONFIRM, hex(frame.keyConfirm()));

            byte[] header = frame.toBytes();
            assertEquals(V_PASSWORD_HEADER, hex(header));
            assertArrayEquals(header, ImageCryptFrame.fromBytes(header).toBytes());

            XChaCha20 cipher = new XChaCha20(schedule.encKey(), nonce);
            byte[] ciphertext = new byte[plain.length];
            cipher.process(ciphertext, plain, plain.length);
            assertEquals(V_PASSWORD_CIPHERTEXT, hex(ciphertext));
            assertEquals(V_PASSWORD_AUTH_TAG, hex(authTag(schedule, frame, ciphertext)));
        }
    }

    @Test
    void composedAndDecomposedPasswordsDeriveTheSameKey() throws Exception {
        byte[] nfc = ImageCryptPassword.encodeForV1(COMPOSED_PASSWORD);
        byte[] nfd = ImageCryptPassword.encodeForV1(
                Normalizer.normalize(COMPOSED_PASSWORD, Normalizer.Form.NFD));
        assertEquals(V_PASSWORD_UNICODE_BYTES, hex(nfc));
        assertArrayEquals(nfc, nfd, "NFC 与 NFD 输入必须规范化为同一串字节");

        byte[] argon2Salt = hex(V_PASSWORD_ARGON2_SALT);
        byte[] hkdfSalt = hex(V_PASSWORD_HKDF_SALT);
        try (ImageKeySchedule schedule = ImageKeySchedule.fromPassword(nfd, argon2Salt, hkdfSalt, null)) {
            assertEquals(V_UNICODE_ENC_KEY, hex(schedule.encKey()));
        }
    }

    @Test
    void passwordVectorKeyConfirmRejectsOtherPasswords() throws Exception {
        byte[] argon2Salt = hex(V_PASSWORD_ARGON2_SALT);
        byte[] hkdfSalt = hex(V_PASSWORD_HKDF_SALT);
        ImageCryptFrame header = ImageCryptFrame.fromBytes(hex(V_PASSWORD_HEADER));
        byte[] expected = hex(V_PASSWORD_KEY_CONFIRM);

        byte[] wrong = ImageCryptPassword.encodeForV1("correct horse battery staple!");
        try (ImageKeySchedule schedule = ImageKeySchedule.fromPassword(wrong, argon2Salt, hkdfSalt, null)) {
            assertFalse(schedule.verifyKeyConfirm(header.keyConfirmPrefixBytes(), expected));
        }
    }

    // ================================================================
    // 随机性要求
    // ================================================================

    @Test
    void repeatedEncryptionYieldsDistinctSaltsNoncesAndCiphertext() throws Exception {
        ImageCryptRandomSource random = ImageCryptRandomSource.secure();
        byte[] plain = publicPlaintext();

        byte[] firstNonce;
        byte[] firstCiphertext;
        byte[] secondNonce;
        byte[] secondCiphertext;

        try (ImageKeySchedule first = ImageKeySchedule.fromPublicMasterKey(
                random.nextBytes(ImageCryptProtocol.MASTER_KEY_LENGTH),
                random.nextBytes(ImageCryptProtocol.HKDF_SALT_LENGTH))) {
            firstNonce = random.nextBytes(ImageCryptProtocol.NONCE_LENGTH);
            firstCiphertext = encrypt(first, firstNonce, plain);
        }
        try (ImageKeySchedule second = ImageKeySchedule.fromPublicMasterKey(
                random.nextBytes(ImageCryptProtocol.MASTER_KEY_LENGTH),
                random.nextBytes(ImageCryptProtocol.HKDF_SALT_LENGTH))) {
            secondNonce = random.nextBytes(ImageCryptProtocol.NONCE_LENGTH);
            secondCiphertext = encrypt(second, secondNonce, plain);
        }

        assertFalse(Arrays.equals(firstNonce, secondNonce), "每文件必须使用独立 nonce");
        assertFalse(Arrays.equals(firstCiphertext, secondCiphertext),
                "相同明文的多次加密不得产生相同密文");
    }

    // ================================================================
    // 夹具
    // ================================================================

    /**
     * 构造公开恢复向量使用的明文（InnerManifest 描述区 + 载荷）。
     *
     * @return 明文片段
     * @throws ImageCryptException 清单构造失败
     */
    private static byte[] publicPlaintext() throws ImageCryptException {
        byte[] payload = "EGTC-IMG v1 golden payload é中文".getBytes(StandardCharsets.UTF_8);
        return concat(InnerManifest.create(ImageFormat.PNG, payload.length,
                "golden.png", "image/png", "png", false).toBytes(), payload);
    }

    /**
     * 构造密码保护向量使用的明文。
     *
     * @return 明文片段
     * @throws ImageCryptException 清单构造失败
     */
    private static byte[] passwordPlaintext() throws ImageCryptException {
        byte[] payload = "password protected payload".getBytes(StandardCharsets.UTF_8);
        return concat(InnerManifest.create(ImageFormat.JPEG, payload.length,
                "secret.jpg", "image/jpeg", "jpg", false).toBytes(), payload);
    }

    /**
     * 计算完整认证标签。
     *
     * @param schedule   密钥编排
     * @param frame      协议头
     * @param ciphertext 密文
     * @return 64 字节标签
     * @throws Exception MAC 构造失败
     */
    private static byte[] authTag(final ImageKeySchedule schedule, final ImageCryptFrame frame,
                                  final byte[] ciphertext) throws Exception {
        Mac mac = schedule.beginAuthTag(frame.authenticationPrefixBytes(), ciphertext.length);
        try {
            mac.update(ciphertext, ciphertext.length);
            return mac.doFinal();
        } finally {
            mac.close();
        }
    }

    /**
     * 用给定 nonce 加密明文。
     *
     * @param schedule 密钥编排
     * @param nonce    XChaCha20 nonce
     * @param plain    明文
     * @return 密文
     */
    private static byte[] encrypt(final ImageKeySchedule schedule, final byte[] nonce,
                                  final byte[] plain) {
        byte[] out = new byte[plain.length];
        new XChaCha20(schedule.encKey(), nonce).process(out, plain, plain.length);
        return out;
    }

    /**
     * 拼接两个数组。
     *
     * @param a 前段
     * @param b 后段
     * @return 拼接结果
     */
    private static byte[] concat(final byte[] a, final byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    /**
     * 断言十六进制常量长度正确（防止粘贴时漏字符）。
     */
    @Test
    void frozenHexConstantsHaveExpectedLengths() {
        assertEquals(184 * 2, V_PUBLIC_HEADER.length(), "公开模式协议头应为 184 字节");
        assertEquals(184 * 2, V_PASSWORD_HEADER.length(), "密码模式协议头应为 184 字节");
        assertEquals(64 * 2, V_PUBLIC_AUTH_TAG.length());
        assertEquals(64 * 2, V_PASSWORD_AUTH_TAG.length());
        assertEquals(16 * 2, V_PUBLIC_KEY_CONFIRM.length());
        assertTrue(V_PUBLIC_HEADER.startsWith("454754432d494d47"), "协议头必须以 EGTC-IMG 开头");
    }
}
