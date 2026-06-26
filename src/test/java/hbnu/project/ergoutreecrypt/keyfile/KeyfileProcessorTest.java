package hbnu.project.ergoutreecrypt.keyfile;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Keyfile 处理器测试，覆盖 Go {@code internal/keyfile/processor_test.go} 所有场景。
 *
 * @author ErgouTree
 * @since 2026/6/16
 */
public final class KeyfileProcessorTest {

    @Test
    void testProcessEmpty() throws IOException {
        try (KeyfileProcessor r = KeyfileProcessor.process(null, true, null)) {
            assertEquals(32, r.key().length);
            assertEquals(32, r.hash().length);
            // Both should be all zeros
            for (byte b : r.key()) {
                assertEquals(0, b);
            }
        }
    }

    @Test
    void testProcessEmptyList() throws IOException {
        try (KeyfileProcessor r = KeyfileProcessor.process(List.of(), false, null)) {
            assertEquals(32, r.key().length);
            for (byte b : r.key()) {
                assertEquals(0, b);
            }
        }
    }

    @Test
    void testProcessOrdered(@TempDir Path tempDir) throws IOException {
        Path a = createFile(tempDir, "a.key", "keyfile1-content".getBytes());
        Path b = createFile(tempDir, "b.key", "keyfile2-content".getBytes());
        Path c = createFile(tempDir, "c.key", "keyfile3-content".getBytes());

        List<Path> abc = List.of(a, b, c);
        List<Path> cba = List.of(c, b, a);

        try (KeyfileProcessor rabc = KeyfileProcessor.process(abc, true, null);
             KeyfileProcessor rcba = KeyfileProcessor.process(cba, true, null)) {

            // Ordered: different order → different keys
            assertFalse(Arrays.equals(rabc.key(), rcba.key()),
                    "ordered: different order should produce different keys");

            // hash = SHA3-256(key)
            assertArrayEquals(sha3256(rabc.key()), rabc.hash(), "hash should be SHA3-256(key)");
        }
    }

    @Test
    void testProcessUnordered(@TempDir Path tempDir) throws IOException {
        Path a = createFile(tempDir, "a.key", "keyfile1-content".getBytes());
        Path b = createFile(tempDir, "b.key", "keyfile2-content".getBytes());
        Path c = createFile(tempDir, "c.key", "keyfile3-content".getBytes());

        List<Path> abc = List.of(a, b, c);
        List<Path> cba = List.of(c, b, a);

        try (KeyfileProcessor rabc = KeyfileProcessor.process(abc, false, null);
             KeyfileProcessor rcba = KeyfileProcessor.process(cba, false, null)) {

            // Unordered: XOR is commutative → same key regardless of order
            assertArrayEquals(rabc.key(), rcba.key(),
                    "unordered: different order should produce same keys (XOR commutativity)");
        }
    }

    @Test
    void testProcessProgress(@TempDir Path tempDir) throws IOException {
        byte[] largeContent = new byte[2 * 1024 * 1024]; // 2 MiB
        Arrays.fill(largeContent, (byte) 'x');
        Path large = createFile(tempDir, "large.key", largeContent);

        int[] callCount = { 0 };
        float[] lastProgress = { -1f };

        try (KeyfileProcessor r = KeyfileProcessor.process(
                List.of(large), true,
                fraction -> { callCount[0]++; lastProgress[0] = fraction; })) {

            assertTrue(callCount[0] > 0, "progress callback should be called");
            assertTrue(lastProgress[0] >= 0.99f, "last progress should be ~1.0, got: " + lastProgress[0]);
            assertEquals(32, r.key().length);
        }
    }

    @Test
    void testIsDuplicateKeyfileKey() {
        byte[] zeroKey = new byte[32];
        assertTrue(KeyfileProcessor.isDuplicateKeyfileKey(zeroKey));

        byte[] nonZeroKey = new byte[32];
        nonZeroKey[0] = 1;
        assertFalse(KeyfileProcessor.isDuplicateKeyfileKey(nonZeroKey));

        assertFalse(KeyfileProcessor.isDuplicateKeyfileKey(new byte[16]), "wrong length");
        assertFalse(KeyfileProcessor.isDuplicateKeyfileKey(null), "null");
    }

    @Test
    void testXorWithKey() {
        byte[] passwordKey = new byte[32];
        byte[] keyfileKey = new byte[32];
        for (int i = 0; i < 32; i++) {
            passwordKey[i] = (byte) i;
            keyfileKey[i] = (byte) (255 - i);
        }

        byte[] result = KeyfileProcessor.xorWithKey(passwordKey, keyfileKey);
        assertEquals(32, result.length);

        for (int i = 0; i < 32; i++) {
            assertEquals((byte) (i ^ (255 - i)), result[i], "result[" + i + "]");
        }

        // XOR with self → all zeros
        byte[] selfResult = KeyfileProcessor.xorWithKey(passwordKey, passwordKey);
        for (byte b : selfResult) {
            assertEquals(0, b);
        }
    }

    @Test
    void testXorWithKeyInvalidLength() {
        byte[] a = new byte[16];
        byte[] b = new byte[32];
        assertThrows(IllegalArgumentException.class,
                () -> KeyfileProcessor.xorWithKey(a, b));
    }

    @Test
    void testDuplicateKeyfilesCancelOut(@TempDir Path tempDir) throws IOException {
        byte[] content = "same-content-in-all-files".getBytes();
        Path a = createFile(tempDir, "a.key", content);
        Path b = createFile(tempDir, "b.key", content); // duplicate

        try (KeyfileProcessor r = KeyfileProcessor.process(List.of(a, b), false, null)) {
            assertTrue(KeyfileProcessor.isDuplicateKeyfileKey(r.key()),
                    "two identical keyfiles (unordered) should XOR to zero");
        }
    }

    @Test
    void testOrderedSameFileTwice(@TempDir Path tempDir) throws IOException {
        byte[] content = "keyfile-content".getBytes();
        Path a = createFile(tempDir, "a.key", content);

        try (KeyfileProcessor once = KeyfileProcessor.process(List.of(a), true, null);
             KeyfileProcessor twice = KeyfileProcessor.process(List.of(a, a), true, null)) {

            assertFalse(Arrays.equals(once.key(), twice.key()),
                    "ordered: same file twice should produce different key than once");
        }
    }

    @Test
    void testCloseZeroesKeyButPreservesHash(@TempDir Path tempDir) throws IOException {
        Path a = createFile(tempDir, "test.key", "keyfile-content".getBytes());

        KeyfileProcessor r = KeyfileProcessor.process(List.of(a), true, null);
        assertNotNull(r.key());
        assertEquals(32, r.key().length);

        byte[] hashBefore = r.hash().clone();

        r.close();
        assertNull(r.key(), "key should be null after close()");
        assertArrayEquals(hashBefore, r.hash(), "hash should be preserved after close()");

        // Multiple close() should be safe
        r.close();
        r.close();
    }

    @Test
    void testCloseOnNullSafe() {
        // Should not NPE
        new KeyfileProcessor(new byte[32], new byte[32]).close();
    }

    @Test
    void testProcessNonexistentFile() {
        assertThrows(IOException.class,
                () -> KeyfileProcessor.process(
                        List.of(Path.of("/nonexistent/path/to/keyfile.bin")),
                        true, null));
    }

    // ---- helpers ----

    private static Path createFile(Path dir, String name, byte[] data) throws IOException {
        Path path = dir.resolve(name);
        Files.write(path, data);
        return path;
    }

    private static byte[] sha3256(byte[] data) {
        org.bouncycastle.crypto.digests.SHA3Digest digest =
                new org.bouncycastle.crypto.digests.SHA3Digest(256);
        digest.update(data, 0, data.length);
        byte[] out = new byte[digest.getDigestSize()];
        digest.doFinal(out, 0);
        return out;
    }
}
