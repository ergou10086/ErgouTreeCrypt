package hbnu.project.ergoutreecrypt.volume;

import static hbnu.project.ergoutreecrypt.volume.FastVolumeRoundtripTest.*;

import static org.junit.jupiter.api.Assertions.*;

import hbnu.project.ergoutreecrypt.crypto.BruteForceGuard;
import hbnu.project.ergoutreecrypt.exception.CryptoException;
import hbnu.project.ergoutreecrypt.exception.ErrorKind;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Random;

/** 头、分段顺序、跨文件拼接和末尾认证失败时不能输出最终明文。 */
final class FastVerifyTest {
    /**
     * @param directory 独占测试目录
     * @throws Exception 测试准备或拒绝策略失败
     */
    @Test
    void everyMutationFailsBothAuthenticationAndDecryption(@TempDir Path directory)
            throws Exception {
        Path source = directory.resolve("source"),
                cipher = directory.resolve("cipher"),
                other = directory.resolve("other");
        byte[] data = new byte[4 * (1 << 20) + 77];
        new Random(711).nextBytes(data);
        Files.write(source, data);
        Encryptor.encrypt(encryption(source, cipher, "密码"));
        Encryptor.encrypt(encryption(source, other, "密码"));
        byte[] original = Files.readAllBytes(cipher), second = Files.readAllBytes(other);
        var attacks = new ArrayList<byte[]>();
        for (int offset :
                new int[] {
                    8,
                    10,
                    12,
                    14,
                    16,
                    20,
                    24,
                    28,
                    32,
                    36,
                    37,
                    38,
                    39,
                    40,
                    56,
                    88,
                    96,
                    127,
                    128,
                    159,
                    160,
                    200,
                    160 + (1 << 20) + 19,
                    original.length - 1
                }) {
            byte[] invalid = original.clone();
            invalid[offset] ^= 1;
            attacks.add(invalid);
        }
        attacks.add(Arrays.copyOf(original, original.length - 1));
        attacks.add(Arrays.copyOf(original, original.length + 1));
        attacks.add(Arrays.copyOf(original, 160 + (1 << 20)));
        attacks.add(Arrays.copyOf(original, original.length - (1 << 20)));
        byte[] swapped = original.clone();
        System.arraycopy(original, 160 + (1 << 20), swapped, 160 + 2 * (1 << 20), 1 << 20);
        System.arraycopy(original, 160 + 2 * (1 << 20), swapped, 160 + (1 << 20), 1 << 20);
        attacks.add(swapped);
        byte[] duplicated = original.clone();
        System.arraycopy(original, 160 + (1 << 20), duplicated, 160 + 2 * (1 << 20), 1 << 20);
        attacks.add(duplicated);
        byte[] transplanted = original.clone();
        System.arraycopy(second, 160, transplanted, 160, original.length - 160);
        attacks.add(transplanted);
        byte[] segment = original.clone();
        System.arraycopy(second, 160 + (1 << 20), segment, 160 + (1 << 20), 1 << 20);
        attacks.add(segment);
        byte[] removed = new byte[original.length - (1 << 20)];
        System.arraycopy(original, 0, removed, 0, 160 + (1 << 20));
        System.arraycopy(
                original,
                160 + 2 * (1 << 20),
                removed,
                160 + (1 << 20),
                original.length - 160 - 2 * (1 << 20));
        attacks.add(removed);
        int index = 0;
        for (byte[] attack : attacks) {
            Path invalid = directory.resolve("attack-" + (index++)),
                    output = directory.resolve("out-" + index);
            Files.write(invalid, attack);
            var before = entries(directory);
            BruteForceGuard.getInstance().resetCounter(invalid.toString());
            CryptoException auth =
                    assertThrows(
                            CryptoException.class,
                            () -> Verifier.verify(verification(invalid, "密码")));
            assertNotEquals(ErrorKind.BRUTE_FORCE_LOCKED, auth.kind());
            CryptoException dec =
                    assertThrows(
                            CryptoException.class,
                            () -> Decryptor.decrypt(decryption(invalid, output, "密码")));
            assertNotEquals(ErrorKind.BRUTE_FORCE_LOCKED, dec.kind());
            assertFalse(Files.exists(output));
            assertEquals(before, entries(directory));
        }
        Path badMagic = directory.resolve("bad-magic");
        byte[] bad = original.clone();
        bad[0] ^= 1;
        Files.write(badMagic, bad);
        assertThrows(
                CryptoException.class, () -> FastVolumeCodec.verify(badMagic, "密码", null, null));
        assertThrows(
                CryptoException.class,
                () ->
                        FastVolumeCodec.decrypt(
                                badMagic, directory.resolve("bad-output"), "密码", null, null));
    }

    /**
     * @param directory 独占测试目录
     * @throws Exception 密码或绕过处理失败
     */
    @Test
    void wrongPasswordAndForceCannotReleasePlaintext(@TempDir Path directory) throws Exception {
        Path input = directory.resolve("source"),
                cipher = directory.resolve("cipher"),
                output = directory.resolve("output");
        Files.writeString(input, "验证");
        Encryptor.encrypt(encryption(input, cipher, "正确密码"));
        var wrong = decryption(cipher, output, "错误密码");
        assertEquals(
                ErrorKind.WRONG_PASSWORD,
                assertThrows(CryptoException.class, () -> Decryptor.decrypt(wrong)).kind());
        assertEquals(1, BruteForceGuard.getInstance().getFailCount(cipher.toString()));
        assertEquals(
                ErrorKind.WRONG_PASSWORD,
                assertThrows(
                                CryptoException.class,
                                () -> Verifier.verify(verification(cipher, "错误密码")))
                        .kind());
        assertEquals(2, BruteForceGuard.getInstance().getFailCount(cipher.toString()));
        var force = decryption(cipher, output, "正确密码");
        force.setForceDecrypt(true);
        assertEquals(
                ErrorKind.UNSUPPORTED_FORMAT,
                assertThrows(CryptoException.class, () -> Decryptor.decrypt(force)).kind());
        var forceAuth = verification(cipher, "正确密码");
        forceAuth.setForceDecrypt(true);
        assertThrows(CryptoException.class, () -> Verifier.verify(forceAuth));
        assertFalse(Files.exists(output));
        assertTrue(Verifier.verify(verification(cipher, "正确密码")));
        assertEquals(0, BruteForceGuard.getInstance().getFailCount(cipher.toString()));
    }
}
