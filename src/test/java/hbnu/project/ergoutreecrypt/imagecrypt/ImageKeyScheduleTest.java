package hbnu.project.ergoutreecrypt.imagecrypt;

import hbnu.project.ergoutreecrypt.crypto.Argon2Kdf;
import hbnu.project.ergoutreecrypt.crypto.Mac;
import hbnu.project.ergoutreecrypt.exception.ErrorKind;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptTestSupport.assertKind;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link ImageKeySchedule} 的密钥编排与认证测试。
 *
 * <p>覆盖 HKDF 域分离的确定性、salt 与主密钥的敏感性、keyConfirm 与完整认证标签的构造、
 * 常量时间比较语义，以及 {@code close()} 的密钥清零。
 *
 * <p>密码模式用例会真实执行 v1 固定档 Argon2id（64 MiB / 3 passes / 4 lanes），
 * 单个用例约需数百毫秒，属于协议要求而非测试配置。
 *
 * @author ErgouTree
 * @since 2026/9/15
 */
final class ImageKeyScheduleTest {

    /**
     * HKDF 前缀长度。
     */
    private static final int PREFIX_LENGTH = ImageCryptProtocol.KEY_CONFIRM_COVERED_HEADER_LENGTH;

    // ================================================================
    // 公开恢复分支
    // ================================================================

    @Test
    void publicModeDerivesDistinctEncAndMacKeys() throws Exception {
        byte[] master = filled(ImageCryptProtocol.MASTER_KEY_LENGTH, 0x11);
        byte[] salt = filled(ImageCryptProtocol.HKDF_SALT_LENGTH, 0x22);
        try (ImageKeySchedule schedule = ImageKeySchedule.fromPublicMasterKey(master, salt)) {
            assertEquals(ImageCryptProtocol.ENC_KEY_LENGTH, schedule.encKey().length);
            assertEquals(ImageCryptProtocol.MAC_KEY_LENGTH, schedule.macKey().length);
            assertFalse(Arrays.equals(schedule.encKey(), schedule.macKey()),
                    "HKDF 必须把加密子密钥与 MAC 子密钥分开");
        }
    }

    @Test
    void derivationIsDeterministic() throws Exception {
        byte[] master = filled(ImageCryptProtocol.MASTER_KEY_LENGTH, 0x11);
        byte[] salt = filled(ImageCryptProtocol.HKDF_SALT_LENGTH, 0x22);
        try (ImageKeySchedule first = ImageKeySchedule.fromPublicMasterKey(master, salt);
             ImageKeySchedule second = ImageKeySchedule.fromPublicMasterKey(master, salt)) {
            assertArrayEquals(first.encKey(), second.encKey());
            assertArrayEquals(first.macKey(), second.macKey());
        }
    }

    @Test
    void changingEitherInputChangesBothKeys() throws Exception {
        byte[] master = filled(ImageCryptProtocol.MASTER_KEY_LENGTH, 0x11);
        byte[] salt = filled(ImageCryptProtocol.HKDF_SALT_LENGTH, 0x22);
        byte[] otherSalt = salt.clone();
        otherSalt[0] ^= 0x01;

        try (ImageKeySchedule base = ImageKeySchedule.fromPublicMasterKey(master, salt);
             ImageKeySchedule salted = ImageKeySchedule.fromPublicMasterKey(master, otherSalt)) {
            assertFalse(Arrays.equals(base.encKey(), salted.encKey()));
            assertFalse(Arrays.equals(base.macKey(), salted.macKey()));
        }
    }

    @Test
    void closeZeroesDerivedKeys() throws Exception {
        ImageKeySchedule schedule = ImageKeySchedule.fromPublicMasterKey(
                filled(ImageCryptProtocol.MASTER_KEY_LENGTH, 0x11),
                filled(ImageCryptProtocol.HKDF_SALT_LENGTH, 0x22));
        byte[] enc = schedule.encKey();
        schedule.close();
        assertTrue(isAllZero(enc), "close() 必须清零加密子密钥");
        assertTrue(isAllZero(schedule.macKey()), "close() 必须清零 MAC 子密钥");
    }

    @Test
    void wrongSizedMasterOrSaltIsRejected() {
        assertKind(ErrorKind.INTERNAL_ERROR, () -> ImageKeySchedule.fromPublicMasterKey(
                new byte[31], new byte[ImageCryptProtocol.HKDF_SALT_LENGTH]));
        assertKind(ErrorKind.INTERNAL_ERROR, () -> ImageKeySchedule.fromPublicMasterKey(
                new byte[ImageCryptProtocol.MASTER_KEY_LENGTH], new byte[31]));
    }

    // ================================================================
    // keyConfirm
    // ================================================================

    @Test
    void keyConfirmCoversTheHeaderPrefixOnly() throws Exception {
        byte[] master = filled(ImageCryptProtocol.MASTER_KEY_LENGTH, 0x11);
        byte[] salt = filled(ImageCryptProtocol.HKDF_SALT_LENGTH, 0x22);
        byte[] prefix = filled(PREFIX_LENGTH, 0x33);
        byte[] tampered = prefix.clone();
        tampered[PREFIX_LENGTH - 1] ^= 0x01;

        try (ImageKeySchedule schedule = ImageKeySchedule.fromPublicMasterKey(master, salt)) {
            byte[] expected = schedule.computeKeyConfirm(prefix);
            assertEquals(ImageCryptProtocol.KEY_CONFIRM_LENGTH, expected.length);
            assertArrayEquals(expected, schedule.computeKeyConfirm(prefix));
            assertTrue(schedule.verifyKeyConfirm(prefix, expected));
            assertFalse(schedule.verifyKeyConfirm(tampered, expected));
        }
    }

    @Test
    void keyConfirmDependsOnTheMacKey() throws Exception {
        byte[] prefix = filled(PREFIX_LENGTH, 0x33);
        byte[] salt = filled(ImageCryptProtocol.HKDF_SALT_LENGTH, 0x22);
        try (ImageKeySchedule first = ImageKeySchedule.fromPublicMasterKey(
                filled(ImageCryptProtocol.MASTER_KEY_LENGTH, 0x11), salt);
             ImageKeySchedule second = ImageKeySchedule.fromPublicMasterKey(
                     filled(ImageCryptProtocol.MASTER_KEY_LENGTH, 0x99), salt)) {
            assertFalse(Arrays.equals(first.computeKeyConfirm(prefix),
                    second.computeKeyConfirm(prefix)));
        }
    }

    @Test
    void keyConfirmRejectsWrongSizedInputs() throws Exception {
        try (ImageKeySchedule schedule = ImageKeySchedule.fromPublicMasterKey(
                filled(ImageCryptProtocol.MASTER_KEY_LENGTH, 0x11),
                filled(ImageCryptProtocol.HKDF_SALT_LENGTH, 0x22))) {
            assertKind(ErrorKind.INTERNAL_ERROR, () -> schedule.computeKeyConfirm(new byte[10]));
            assertKind(ErrorKind.INTERNAL_ERROR,
                    () -> schedule.verifyKeyConfirm(filled(PREFIX_LENGTH, 1), new byte[15]));
        }
    }

    // ================================================================
    // 完整认证标签
    // ================================================================

    @Test
    void authTagCoversHeaderLengthAndCiphertext() throws Exception {
        byte[] headerPrefix = filled(ImageCryptProtocol.MAC_COVERED_HEADER_LENGTH, 0x44);
        byte[] ciphertext = filled(64, 0x55);
        try (ImageKeySchedule schedule = ImageKeySchedule.fromPublicMasterKey(
                filled(ImageCryptProtocol.MASTER_KEY_LENGTH, 0x11),
                filled(ImageCryptProtocol.HKDF_SALT_LENGTH, 0x22))) {
            byte[] expected = tag(schedule, headerPrefix, ciphertext.length, ciphertext);
            assertEquals(ImageCryptProtocol.AUTH_TAG_LENGTH, expected.length);
            assertArrayEquals(expected, tag(schedule, headerPrefix, ciphertext.length, ciphertext));

            byte[] otherHeader = headerPrefix.clone();
            otherHeader[0] ^= 0x01;
            assertFalse(Arrays.equals(expected, tag(schedule, otherHeader, ciphertext.length, ciphertext)));

            byte[] otherCipher = ciphertext.clone();
            otherCipher[0] ^= 0x01;
            assertFalse(Arrays.equals(expected, tag(schedule, headerPrefix, ciphertext.length, otherCipher)));

            assertFalse(Arrays.equals(expected, tag(schedule, headerPrefix, ciphertext.length - 1, ciphertext)),
                    "密文长度必须进入认证范围");
        }
    }

    @Test
    void authTagRejectsWrongSizedHeaderPrefix() throws Exception {
        try (ImageKeySchedule schedule = ImageKeySchedule.fromPublicMasterKey(
                filled(ImageCryptProtocol.MASTER_KEY_LENGTH, 0x11),
                filled(ImageCryptProtocol.HKDF_SALT_LENGTH, 0x22))) {
            assertKind(ErrorKind.INTERNAL_ERROR, () -> schedule.beginAuthTag(new byte[10], 0));
            assertKind(ErrorKind.INTERNAL_ERROR,
                    () -> schedule.beginAuthTag(new byte[ImageCryptProtocol.MAC_COVERED_HEADER_LENGTH], -1));
        }
    }

    @Test
    void authTagComparisonRejectsNullAndMismatch() {
        byte[] tag = filled(ImageCryptProtocol.AUTH_TAG_LENGTH, 0x66);
        assertTrue(ImageKeySchedule.verifyAuthTag(tag, tag.clone()));
        assertFalse(ImageKeySchedule.verifyAuthTag(tag, filled(ImageCryptProtocol.AUTH_TAG_LENGTH, 0x67)));
        assertFalse(ImageKeySchedule.verifyAuthTag(null, tag));
        assertFalse(ImageKeySchedule.verifyAuthTag(tag, null));
        byte[] shortened = Arrays.copyOf(tag, ImageCryptProtocol.AUTH_TAG_LENGTH - 1);
        assertFalse(ImageKeySchedule.verifyAuthTag(tag, shortened));
    }

    // ================================================================
    // 密码保护分支
    // ================================================================

    @Test
    void passwordModeUsesTheFrozenArgon2Profile() throws Exception {
        byte[] password = ImageCryptPassword.encodeForV1("correct horse battery staple");
        byte[] salt = filled(ImageCryptProtocol.ARGON2_SALT_LENGTH, 0x77);
        byte[] hkdfSalt = filled(ImageCryptProtocol.HKDF_SALT_LENGTH, 0x88);

        byte[] expected = argon2Reference(password, salt);
        try (ImageKeySchedule schedule = ImageKeySchedule.fromPassword(password, salt, hkdfSalt, null);
             ImageKeySchedule reference = ImageKeySchedule.fromPublicMasterKey(expected, hkdfSalt)) {
            assertArrayEquals(reference.encKey(), schedule.encKey(),
                    "密码模式的 masterKey 必须等于固定档 Argon2id 的输出");
            assertArrayEquals(reference.macKey(), schedule.macKey());
        }
    }

    @Test
    void wrongPasswordYieldsDifferentKeys() throws Exception {
        byte[] salt = filled(ImageCryptProtocol.ARGON2_SALT_LENGTH, 0x77);
        byte[] hkdfSalt = filled(ImageCryptProtocol.HKDF_SALT_LENGTH, 0x88);
        byte[] right = ImageCryptPassword.encodeForV1("passphrase-one");
        byte[] wrong = ImageCryptPassword.encodeForV1("passphrase-two");

        byte[] prefix = filled(PREFIX_LENGTH, 0x33);
        byte[] confirm;
        try (ImageKeySchedule schedule = ImageKeySchedule.fromPassword(right, salt, hkdfSalt, null)) {
            confirm = schedule.computeKeyConfirm(prefix);
        }
        try (ImageKeySchedule schedule = ImageKeySchedule.fromPassword(wrong, salt, hkdfSalt, null)) {
            assertFalse(schedule.verifyKeyConfirm(prefix, confirm),
                    "错误密码必须在 keyConfirm 阶段被快速拒绝");
        }
    }

    @Test
    void passwordModeRejectsEmptyAndWrongSizedInputs() throws Exception {
        byte[] hkdfSalt = filled(ImageCryptProtocol.HKDF_SALT_LENGTH, 0x88);
        assertKind(ErrorKind.INTERNAL_ERROR, () -> ImageKeySchedule.fromPassword(
                new byte[0], new byte[ImageCryptProtocol.ARGON2_SALT_LENGTH], hkdfSalt, null));
        assertKind(ErrorKind.INTERNAL_ERROR, () -> ImageKeySchedule.fromPassword(
                new byte[4], new byte[15], hkdfSalt, null));
    }

    // ================================================================
    // 夹具
    // ================================================================

    /**
     * 计算一段数据的完整认证标签。
     *
     * @param schedule    密钥编排
     * @param headerPrefix 协议头 {@code [0, 180)}
     * @param length      声明的密文长度
     * @param ciphertext  密文字节
     * @return 64 字节标签
     * @throws Exception MAC 构造失败
     */
    private static byte[] tag(final ImageKeySchedule schedule, final byte[] headerPrefix,
                              final long length, final byte[] ciphertext) throws Exception {
        Mac mac = schedule.beginAuthTag(headerPrefix, length);
        try {
            mac.update(ciphertext, ciphertext.length);
            return mac.doFinal();
        } finally {
            mac.close();
        }
    }

    /**
     * 直接用 {@code Argon2Kdf} 的固定档参数复算主密钥，作为密钥编排的独立参照。
     *
     * @param password 规范化后的密码字节
     * @param salt     Argon2id salt
     * @return 32 字节主密钥
     * @throws Exception 派生失败
     */
    private static byte[] argon2Reference(final byte[] password, final byte[] salt) throws Exception {
        return Argon2Kdf.deriveKey(password, salt, false,
                ImageCryptProtocol.ARGON2_MEMORY_KIB,
                ImageCryptProtocol.ARGON2_PASSES,
                ImageCryptProtocol.ARGON2_LANES);
    }

    /**
     * 生成定长填充数组。
     *
     * @param length 长度
     * @param value  填充值
     * @return 填充数组
     */
    private static byte[] filled(final int length, final int value) {
        byte[] out = new byte[length];
        Arrays.fill(out, (byte) value);
        return out;
    }

    /**
     * 判断数组是否全为零。
     *
     * @param data 数组
     * @return true 表示全零
     */
    private static boolean isAllZero(final byte[] data) {
        for (byte b : data) {
            if (b != 0) {
                return false;
            }
        }
        return true;
    }
}
