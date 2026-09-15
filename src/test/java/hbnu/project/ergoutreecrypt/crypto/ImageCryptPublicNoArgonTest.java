package hbnu.project.ergoutreecrypt.crypto;

import hbnu.project.ergoutreecrypt.imagecrypt.ImageKeySchedule;
import hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptPassword;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * 「公开恢复模式不执行 Argon2」的硬性验证。
 *
 * <p>本类刻意放在 {@code crypto} 包，以便读取 {@link Argon2Kdf} 的包内并发观测计数
 * （{@code kdfInFlight}/{@code kdfMaxInFlight}），从而把"没调用"变成可断言的客观事实，
 * 而不是依赖耗时测量。
 *
 * <p>公开模式把随机主密钥明文写入文件头，任何拿到文件的人都能恢复；在这条路径上执行
 * Argon2 既没有安全性收益，也会白白占用移动端的内存与时间。
 *
 * @author ErgouTree
 * @since 2026/9/15
 */
final class ImageCryptPublicNoArgonTest {

    @Test
    void publicModeNeverEntersArgon2() throws Exception {
        Argon2Kdf.resetKdfStats();
        byte[] master = new byte[32];
        Arrays.fill(master, (byte) 0x11);
        byte[] hkdfSalt = new byte[32];

        try (ImageKeySchedule schedule = ImageKeySchedule.fromPublicMasterKey(master, hkdfSalt)) {
            assertNotNull(schedule.encKey());
        }
        assertEquals(0, Argon2Kdf.kdfMaxInFlight.get(), "公开恢复模式不得进入 Argon2");
    }

    @Test
    void passwordModeDoesEnterArgon2() throws Exception {
        Argon2Kdf.resetKdfStats();
        byte[] password = ImageCryptPassword.encodeForV1("counted-password");
        byte[] salt = new byte[16];
        Arrays.fill(salt, (byte) 0x22);
        byte[] hkdfSalt = new byte[32];

        try (ImageKeySchedule schedule = ImageKeySchedule.fromPassword(
                password, salt, hkdfSalt, null)) {
            assertNotNull(schedule.encKey());
        }
        assertEquals(1, Argon2Kdf.kdfMaxInFlight.get(),
                "密码保护模式必须真实执行一次 Argon2，否则本测试失去判别力");
    }

    @Test
    void publicRecoveryUsesNoHardcodedSecret() throws Exception {
        // 两个不同文件的主密钥彼此独立：公开模式的安全性不依赖任何固定常量。
        byte[] salt = new byte[32];
        try (ImageKeySchedule first = ImageKeySchedule.fromPublicMasterKey(
                key(0x01), salt);
             ImageKeySchedule second = ImageKeySchedule.fromPublicMasterKey(
                     key(0x02), salt)) {
            assertFalse(Arrays.equals(first.encKey(), second.encKey()));
        }
    }

    /**
     * 构造定长填充密钥。
     *
     * @param value 填充值
     * @return 32 字节数组
     */
    private static byte[] key(final int value) {
        byte[] out = new byte[32];
        Arrays.fill(out, (byte) value);
        return out;
    }
}
