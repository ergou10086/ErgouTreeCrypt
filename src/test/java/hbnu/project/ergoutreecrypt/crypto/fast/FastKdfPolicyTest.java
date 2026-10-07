package hbnu.project.ergoutreecrypt.crypto.fast;

import hbnu.project.ergoutreecrypt.exception.CryptoException;
import org.junit.jupiter.api.Test;
import java.nio.charset.StandardCharsets;
import static org.junit.jupiter.api.Assertions.*;

/** FAST 密码编码边界；不改变旧格式的密码候选规则。 */
final class FastKdfPolicyTest {
    /** @throws Exception 编码异常 */
    @Test
    void unicodeAndLimitsAreStrict() throws Exception {
        assertArrayEquals(FastKdfPolicy.encodePassword("é-极速🔐"), FastKdfPolicy.encodePassword("e\u0301-极速🔐"));
        assertArrayEquals(" 密码 ".getBytes(StandardCharsets.UTF_8), FastKdfPolicy.encodePassword(" 密码 "));
        assertEquals(1024, FastKdfPolicy.encodePassword("a".repeat(1024)).length);
        for (String invalid : new String[]{null,""," \t\n", "\u00a0", "\ud800", "\udc00", "x\ud800y", "a".repeat(1025), "中".repeat(342)}) {
            assertThrows(CryptoException.class, () -> FastKdfPolicy.encodePassword(invalid));
        }
        FastKdfPolicy.validate(65536,3,4,19,1);
        assertThrows(CryptoException.class, () -> FastKdfPolicy.validate(Integer.MAX_VALUE,3,4,19,1));
        assertThrows(CryptoException.class, () -> FastKdfPolicy.validate(65536,1,4,19,1));
        assertThrows(CryptoException.class, () -> FastKdfPolicy.validate(65536,3,1,19,1));
        assertThrows(CryptoException.class, () -> FastKdfPolicy.validate(65536,3,4,16,1));
        assertThrows(CryptoException.class, () -> FastKdfPolicy.validate(65536,3,4,19,0));
    }
}
