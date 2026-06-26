package hbnu.project.ergoutreecrypt.password;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 无密码模式测试。
 *
 * <p>验证"无密码 = 使用公开默认密码"的设计：
 * 加密时若用户留空密码，系统以 DEFAULT_PASSWORD 派生密钥；
 * 解密时若用户未提供密码，系统以 DEFAULT_PASSWORD 尝试解密。
 *
 * @author ErgouTree
 */
public final class PasswordlessTest {

    @Test
    void testDefaultPasswordIsNotEmpty() {
        assertNotNull(Passwordless.DEFAULT_PASSWORD);
        assertFalse(Passwordless.DEFAULT_PASSWORD.isEmpty(),
                "DEFAULT_PASSWORD should not be empty");
    }

    @Test
    void testDefaultPasswordLength() {
        // 足够长的密码确保 Argon2 有充分熵输入
        assertTrue(Passwordless.DEFAULT_PASSWORD.length() >= 16,
                "DEFAULT_PASSWORD should be at least 16 characters");
    }

    @Test
    void testIsNoPasswordNull() {
        assertTrue(Passwordless.isNoPassword(null));
    }

    @Test
    void testIsNoPasswordEmpty() {
        assertTrue(Passwordless.isNoPassword(""));
    }

    @Test
    void testIsNoPasswordNonEmpty() {
        assertFalse(Passwordless.isNoPassword("hello"));
    }

    @Test
    void testEffectivePasswordReturnsDefaultWhenNull() {
        assertEquals(Passwordless.DEFAULT_PASSWORD,
                Passwordless.effectivePassword(null));
    }

    @Test
    void testEffectivePasswordReturnsDefaultWhenEmpty() {
        assertEquals(Passwordless.DEFAULT_PASSWORD,
                Passwordless.effectivePassword(""));
    }

    @Test
    void testEffectivePasswordReturnsOriginalWhenProvided() {
        String pw = "my-secret-password";
        assertEquals(pw, Passwordless.effectivePassword(pw));
    }

    @Test
    void testEffectivePasswordConsistent() {
        // 多次调用应返回相同结果
        assertEquals(Passwordless.effectivePassword(null),
                Passwordless.effectivePassword(null));
        assertEquals(Passwordless.effectivePassword(""),
                Passwordless.effectivePassword(""));
    }
}
