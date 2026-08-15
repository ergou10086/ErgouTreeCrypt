package hbnu.project.ergoutreecrypt.classical.modern;

import hbnu.project.ergoutreecrypt.classical.CipherRegistry;
import hbnu.project.ergoutreecrypt.classical.ClassicalCipher;
import org.bouncycastle.crypto.params.DESParameters;
import org.junit.jupiter.api.Test;

import java.util.Base64;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 现代字符串密码算法测试。
 *
 * <p>覆盖注册顺序、加解密往返、随机性、确定性接缝、错误密码与非法格式拒绝等场景。
 * 注意：错误密码用例只断言异常类型——Android shared-test 无资源文件，消息文案不可断言。
 *
 * @author ErgouTree
 */
class ModernCipherTest {

    /**
     * 七个现代密码的注册顺序（应位于所有古典密码之前）。
     */
    private static final List<String> MODERN_IDS = List.of(
            "aes", "chacha20", "sm4", "blowfish", "twofish", "des", "triple-des");

    /**
     * 含中文与 emoji 的往返测试文本。
     */
    private static final String PLAINTEXT = "Hello 世界 🌍 ErgouTree 测试 !";

    /**
     * 往返测试口令。
     */
    private static final String PASSWORD = "p@ssw0rd-测试";

    /**
     * 固定盐（16 字节）。
     */
    private static final byte[] FIXED_SALT = patternBytes(16, (byte) 1);

    /**
     * 构造七个现代密码实例。
     *
     * @return 现代密码实例列表
     */
    private static List<AbstractModernCipher> ciphers() {
        return List.of(
                new AesCipher(),
                new ChaCha20Cipher(),
                new Sm4Cipher(),
                new BlowfishCipher(),
                new TwofishCipher(),
                new DesCipher(),
                new TripleDesCipher());
    }

    /**
     * 生成以起始字节递增的定长字节数组。
     *
     * @param length 字节数
     * @param start  起始字节
     * @return 递增字节数组
     */
    private static byte[] patternBytes(final int length, final byte start) {
        byte[] b = new byte[length];
        for (int i = 0; i < length; i++) {
            b[i] = (byte) (start + i);
        }
        return b;
    }

    /**
     * 生成仅含 password 参数的参数表。
     *
     * @param password 口令
     * @return 参数表
     */
    private static Map<String, String> passwordParams(final String password) {
        return Map.of("password", password);
    }

    /**
     * 校验注册顺序与默认算法：七个现代密码位于列表前部，AES 为默认项。
     */
    @Test
    void registryOrderAndDefault() {
        List<String> ids = CipherRegistry.getAll().stream()
                .map(hbnu.project.ergoutreecrypt.classical.CipherInfo::id)
                .toList();
        assertEquals(MODERN_IDS, ids.subList(0, MODERN_IDS.size()));
        assertEquals("aes", CipherRegistry.getDefault().getInfo().id());
        assertEquals(17, ids.size());
    }

    /**
     * 七个算法均能完成加密→解密往返，且密文与明文不同。
     */
    @Test
    void roundTripAllCiphers() {
        Map<String, String> params = passwordParams(PASSWORD);
        for (ClassicalCipher cipher : ciphers()) {
            String ciphertext = cipher.encrypt(PLAINTEXT, params);
            assertNotEquals(PLAINTEXT, ciphertext,
                    cipher.getInfo().id() + " 密文不应与明文相同");
            assertEquals(PLAINTEXT, cipher.decrypt(ciphertext, params),
                    cipher.getInfo().id() + " 往返结果应还原原文");
        }
    }

    /**
     * 随机盐与随机 IV 保证相同输入两次加密结果不同，且均能正确解密。
     */
    @Test
    void randomSaltIvMakeOutputsDiffer() {
        Map<String, String> params = passwordParams(PASSWORD);
        for (ClassicalCipher cipher : ciphers()) {
            String first = cipher.encrypt(PLAINTEXT, params);
            String second = cipher.encrypt(PLAINTEXT, params);
            assertNotEquals(first, second,
                    cipher.getInfo().id() + " 随机盐/IV 下两次加密结果应不同");
            assertEquals(PLAINTEXT, cipher.decrypt(first, params));
            assertEquals(PLAINTEXT, cipher.decrypt(second, params));
        }
    }

    /**
     * 确定性接缝：固定盐与 IV 时两次加密输出完全一致，且可经公开接口解密还原。
     */
    @Test
    void deterministicWithFixedSaltIv() {
        for (AbstractModernCipher cipher : ciphers()) {
            byte[] iv = patternBytes(cipher.ivSize(), (byte) 0x20);
            String first = cipher.encryptWith(PLAINTEXT, PASSWORD, FIXED_SALT, iv);
            String second = cipher.encryptWith(PLAINTEXT, PASSWORD, FIXED_SALT, iv);
            assertEquals(first, second,
                    cipher.getInfo().id() + " 固定盐/IV 下两次加密结果应一致");
            assertEquals(PLAINTEXT, cipher.decrypt(first, passwordParams(PASSWORD)),
                    cipher.getInfo().id() + " 确定性密文应可解密还原");
        }
    }

    /**
     * 错误密码：除 ChaCha20 外均应抛出 IllegalArgumentException（GCM 标签或 PKCS7 填充校验失败）。
     */
    @Test
    void wrongPasswordRejected() {
        Map<String, String> params = passwordParams(PASSWORD);
        Map<String, String> wrongParams = passwordParams("wrong-password");
        for (AbstractModernCipher cipher : ciphers()) {
            if ("chacha20".equals(cipher.getInfo().id())) {
                continue;
            }
            String ciphertext = cipher.encrypt(PLAINTEXT, params);
            assertThrows(IllegalArgumentException.class,
                    () -> cipher.decrypt(ciphertext, wrongParams),
                    cipher.getInfo().id() + " 错误密码应被拒绝");
        }
    }

    /**
     * ChaCha20 无认证：错误密码要么被严格 UTF-8 解码捕获而抛异常，
     * 要么（小概率恰好为合法 UTF-8）静默产出乱码，但绝不还原原文。
     */
    @Test
    void chacha20WrongPasswordYieldsGarbageOrError() {
        ChaCha20Cipher cipher = new ChaCha20Cipher();
        String ciphertext = cipher.encrypt(PLAINTEXT, passwordParams(PASSWORD));
        try {
            String result = cipher.decrypt(ciphertext, passwordParams("wrong-password"));
            assertNotEquals(PLAINTEXT, result);
        } catch (IllegalArgumentException e) {
            // 随机字节大概率不是合法 UTF-8，被严格解码捕获——同样体现无认证模式的局限
        }
    }

    /**
     * 非法 Base64 文本应被拒绝。
     */
    @Test
    void malformedBase64Rejected() {
        for (AbstractModernCipher cipher : ciphers()) {
            assertThrows(IllegalArgumentException.class,
                    () -> cipher.decrypt("###not-base64###", passwordParams(PASSWORD)),
                    cipher.getInfo().id() + " 非法 Base64 应被拒绝");
        }
    }

    /**
     * 非法帧（魔数错误）应被拒绝。
     */
    @Test
    void malformedFrameRejected() {
        byte[] junk = patternBytes(40, (byte) 0x11);
        String encoded = Base64.getEncoder().encodeToString(junk);
        for (AbstractModernCipher cipher : ciphers()) {
            assertThrows(IllegalArgumentException.class,
                    () -> cipher.decrypt(encoded, passwordParams(PASSWORD)),
                    cipher.getInfo().id() + " 非法帧应被拒绝");
        }
    }

    /**
     * 跨算法粘贴：AES 输出的密文喂给 SM4 解密应被算法 id 校验拒绝。
     */
    @Test
    void crossAlgorithmCiphertextRejected() {
        AesCipher aes = new AesCipher();
        Sm4Cipher sm4 = new Sm4Cipher();
        String aesOutput = aes.encryptWith(PLAINTEXT, PASSWORD,
                FIXED_SALT, patternBytes(aes.ivSize(), (byte) 0x20));
        assertThrows(IllegalArgumentException.class,
                () -> sm4.decrypt(aesOutput, passwordParams(PASSWORD)));
    }

    /**
     * 空输入返回空串，空密码拒绝加密。
     */
    @Test
    void emptyInputAndPasswordRules() {
        for (AbstractModernCipher cipher : ciphers()) {
            assertEquals("", cipher.encrypt("", passwordParams(PASSWORD)));
            assertEquals("", cipher.decrypt("", passwordParams(PASSWORD)));
            assertThrows(IllegalArgumentException.class,
                    () -> cipher.encrypt("x", Map.of()));
            assertThrows(IllegalArgumentException.class,
                    () -> cipher.decrypt("eDc=", passwordParams("")));
        }
    }

    /**
     * 密钥派生确定性：相同口令与盐两次派生结果一致，长度等于目标密钥长度。
     */
    @Test
    void deriveKeyDeterminismAndLength() {
        byte[] first = AbstractModernCipher.deriveKey(PASSWORD, FIXED_SALT, 32);
        byte[] second = AbstractModernCipher.deriveKey(PASSWORD, FIXED_SALT, 32);
        assertArrayEquals(first, second);
        assertEquals(32, first.length);
        assertFalse(java.util.Arrays.equals(
                AbstractModernCipher.deriveKey("other", FIXED_SALT, 32), first));
    }

    /**
     * DES 弱密钥规避：全 0x01 的弱密钥经 adjustKey 后不再是弱密钥，且调整结果确定。
     */
    @Test
    void desWeakKeyAdjusted() {
        DesCipher cipher = new DesCipher();
        byte[] weakKey = new byte[]{1, 1, 1, 1, 1, 1, 1, 1};
        assertTrue(DESParameters.isWeakKey(weakKey, 0));

        byte[] first = cipher.adjustKey(weakKey);
        byte[] second = cipher.adjustKey(new byte[]{1, 1, 1, 1, 1, 1, 1, 1});
        assertFalse(DESParameters.isWeakKey(first, 0));
        assertArrayEquals(first, second);
    }
}
