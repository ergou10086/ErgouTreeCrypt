package hbnu.project.ergoutreecrypt.password;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 密码归一化测试，覆盖 Go {@code internal/password/normalize_test.go} 所有场景。
 *
 * <h3>UAX #15 测试向量</h3>
 * <p>使用显式码点而非字面量构造测试输入，防止编辑器 NFC 归一化破坏测试意图。
 * <ul>
 *   <li>é (U+00E9) = NFC composed</li>
 *   <li>e (U+0065) + combining acute (U+0301) = NFD decomposed</li>
 *   <li>가 (U+AC00) = NFC hangul</li>
 *   <li>ᄀ (U+1100) + ᅡ (U+1161) = NFD conjoining jamo</li>
 * </ul>
 *
 * @author ErgouTree
 * @since 2026/6/16
 */
public final class PasswordNormalizerTest {

    // 使用显式码点构造，不使用字面量（防止编辑器归一化）
    private static final String E_COMPOSED = new String(new int[] { 0x00E9 }, 0, 1);
    private static final String E_DECOMPOSED = new String(new int[] { 0x0065, 0x0301 }, 0, 2);
    private static final String GA_COMPOSED = new String(new int[] { 0xAC00 }, 0, 1);
    private static final String GA_DECOMPOSED = new String(new int[] { 0x1100, 0x1161 }, 0, 2);
    private static final String DEV_EMOJI = new String(new int[] { 0x1F469, 0x200D, 0x1F4BB }, 0, 3);
    // e + acute (ccc 230) + dot-below (ccc 220): non-canonical order
    private static final String NON_CANONICAL = new String(new int[] { 0x0065, 0x0301, 0x0323 }, 0, 3);

    private static final byte[] E_NFC_BYTES = { (byte) 0xc3, (byte) 0xa9 };
    private static final byte[] E_NFD_BYTES = { 0x65, (byte) 0xcc, (byte) 0x81 };
    private static final byte[] GA_NFC_BYTES = { (byte) 0xea, (byte) 0xb0, (byte) 0x80 };
    private static final byte[] GA_NFD_BYTES = { (byte) 0xe1, (byte) 0x84, (byte) 0x80,
            (byte) 0xe1, (byte) 0x85, (byte) 0xa1 };

    @Test
    void testVectorConstantsHaveExpectedByteForms() {
        assertArrayEquals(E_NFC_BYTES, E_COMPOSED.getBytes(StandardCharsets.UTF_8), "eComposed");
        assertArrayEquals(E_NFD_BYTES, E_DECOMPOSED.getBytes(StandardCharsets.UTF_8), "eDecomposed");
        assertArrayEquals(GA_NFC_BYTES, GA_COMPOSED.getBytes(StandardCharsets.UTF_8), "gaComposed");
        assertArrayEquals(GA_NFD_BYTES, GA_DECOMPOSED.getBytes(StandardCharsets.UTF_8), "gaDecomposed");
    }

    @Test
    void testNormalizeProducesNFC() {
        // Composed + decomposed forms → same NFC bytes
        assertArrayEquals(E_NFC_BYTES, PasswordNormalizer.normalize(E_COMPOSED)
                .getBytes(StandardCharsets.UTF_8), "e composed → NFC");
        assertArrayEquals(E_NFC_BYTES, PasswordNormalizer.normalize(E_DECOMPOSED)
                .getBytes(StandardCharsets.UTF_8), "e decomposed → NFC");
        assertArrayEquals(GA_NFC_BYTES, PasswordNormalizer.normalize(GA_COMPOSED)
                .getBytes(StandardCharsets.UTF_8), "ga composed → NFC");
        assertArrayEquals(GA_NFC_BYTES, PasswordNormalizer.normalize(GA_DECOMPOSED)
                .getBytes(StandardCharsets.UTF_8), "ga decomposed → NFC");
    }

    @Test
    void testNormalizeIsIdempotent() {
        for (String in : new String[] { E_COMPOSED, E_DECOMPOSED, GA_DECOMPOSED, DEV_EMOJI, "ascii" }) {
            String once = PasswordNormalizer.normalize(in);
            String twice = PasswordNormalizer.normalize(once);
            assertEquals(once, twice, "NFC should be idempotent");
        }
    }

    @Test
    void testNormalizeLeavesASCIIUnchanged() {
        String in = "Correct Horse Battery Staple 123!@#";
        assertEquals(in, PasswordNormalizer.normalize(in));
    }

    @Test
    void testNormalizeDoesNotCaseFoldOrTrim() {
        // ß must NOT fold to "ss"; spaces must be preserved
        String in = " stra" + new String(Character.toChars(0x00DF)) + "e ";
        assertEquals(in, PasswordNormalizer.normalize(in));
    }

    @Test
    void testNormalizeLeavesEmojiZWJUnchanged() {
        assertEquals(DEV_EMOJI, PasswordNormalizer.normalize(DEV_EMOJI),
                "ZWJ emoji should pass through unchanged");
    }

    @Test
    void testNormalizeNull() {
        assertEquals("", PasswordNormalizer.normalize(null));
    }

    @Test
    void testEncodeForKDFIsNFCBytes() {
        assertArrayEquals(E_NFC_BYTES, PasswordNormalizer.encodeForKdf(E_DECOMPOSED),
                "EncodeForKDF(decomposed) should yield NFC bytes");
    }

    @Test
    void testEncodeForKDFNull() {
        assertArrayEquals(new byte[0], PasswordNormalizer.encodeForKdf(null));
    }

    @Test
    void testCandidatesASCIISingleAttempt() {
        List<byte[]> got = PasswordNormalizer.candidates("password123");
        assertEquals(1, got.size(), "ASCII → 1 candidate");
        assertArrayEquals("password123".getBytes(StandardCharsets.UTF_8), got.get(0));
    }

    @Test
    void testCandidatesNonASCIIOrderAndDedup() {
        for (String in : new String[] { E_COMPOSED, E_DECOMPOSED }) {
            List<byte[]> got = PasswordNormalizer.candidates(in);
            assertEquals(2, got.size(), "should be 2 candidates (NFC, NFD) after dedup");
            assertArrayEquals(E_NFC_BYTES, got.get(0), "[0] should be NFC");
            assertArrayEquals(E_NFD_BYTES, got.get(1), "[1] should be NFD");
        }
    }

    @Test
    void testCandidatesIncludesRawWhenNeitherNFCNorNFD() {
        List<byte[]> got = PasswordNormalizer.candidates(NON_CANONICAL);
        assertEquals(3, got.size(), "non-canonical → 3 candidates");
        byte[] raw = NON_CANONICAL.getBytes(StandardCharsets.UTF_8);
        assertArrayEquals(raw, got.get(2), "[2] should be raw bytes");
        assertFalse(Arrays.equals(got.get(0), raw), "raw must be distinct from NFC");
        assertFalse(Arrays.equals(got.get(1), raw), "raw must be distinct from NFD");
    }

    @Test
    void testCandidatesEmptyPassword() {
        List<byte[]> got = PasswordNormalizer.candidates("");
        assertEquals(1, got.size(), "empty → 1 candidate");
        assertEquals(0, got.get(0).length, "empty candidate");
    }

    @Test
    void testCandidatesNull() {
        List<byte[]> got = PasswordNormalizer.candidates(null);
        assertEquals(1, got.size(), "null → 1 candidate");
        assertEquals(0, got.get(0).length, "empty candidate for null");
    }

    @Test
    void testContainsNonASCII() {
        assertFalse(PasswordNormalizer.containsNonASCII("Password123!@#"));
        assertFalse(PasswordNormalizer.containsNonASCII(""));
        assertFalse(PasswordNormalizer.containsNonASCII(null));
        assertFalse(PasswordNormalizer.containsNonASCII("")); // DEL, not high
        assertTrue(PasswordNormalizer.containsNonASCII(E_COMPOSED));
        assertTrue(PasswordNormalizer.containsNonASCII(E_DECOMPOSED));
        assertTrue(PasswordNormalizer.containsNonASCII(GA_COMPOSED));
        assertTrue(PasswordNormalizer.containsNonASCII("pass" + E_COMPOSED));
    }
}
