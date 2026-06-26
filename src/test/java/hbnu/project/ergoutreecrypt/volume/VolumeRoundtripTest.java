package hbnu.project.ergoutreecrypt.volume;

import hbnu.project.ergoutreecrypt.encoding.RsCodecs;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Volume 加解密往返测试
 *
 * @author ErgouTree
 */
public final class VolumeRoundtripTest {

    private static RsCodecs rs;

    @BeforeAll
    static void setUp() {
        rs = new RsCodecs();
    }

    // ================================================================
    // Basic roundtrip
    // ================================================================

    @Test
    void testRoundTripBasic(@TempDir Path tempDir) throws Exception {
        byte[] plaintext = "Hello, ErgouTreeCrypt! This is a test file for roundtrip validation.\n"
                .getBytes(java.nio.charset.StandardCharsets.UTF_8);
        Path input = createFile(tempDir, "test.txt", plaintext);

        Path encrypted = tempDir.resolve("test.ergou");
        Path decrypted = tempDir.resolve("test_decrypted.txt");

        // Encrypt
        EncryptRequest encReq = new EncryptRequest();
        encReq.setInputFile(input.toString());
        encReq.setOutputFile(encrypted.toString());
        encReq.setPassword("test-password");
        encReq.setRsCodecs(rs);

        Encryptor.encrypt(encReq);
        assertTrue(Files.exists(encrypted), "encrypted file should exist");

        // Decrypt
        DecryptRequest decReq = new DecryptRequest();
        decReq.setInputFile(encrypted.toString());
        decReq.setOutputFile(decrypted.toString());
        decReq.setPassword("test-password");
        decReq.setRsCodecs(rs);

        Decryptor.decrypt(decReq);
        assertTrue(Files.exists(decrypted), "decrypted file should exist");

        // Verify byte-identical
        byte[] decryptedBytes = Files.readAllBytes(decrypted);
        assertArrayEquals(plaintext, decryptedBytes, "roundtrip should be byte-identical");
    }

    @Test
    void testRoundTripParanoid(@TempDir Path tempDir) throws Exception {
        byte[] plaintext = generateTestData(1024 * 1024 + 500); // ~1.5 MiB
        Path input = createFile(tempDir, "paranoid_test.bin", plaintext);

        Path encrypted = tempDir.resolve("paranoid.ergou");
        Path decrypted = tempDir.resolve("paranoid_dec.bin");

        EncryptRequest encReq = new EncryptRequest();
        encReq.setInputFile(input.toString());
        encReq.setOutputFile(encrypted.toString());
        encReq.setPassword("paranoid-pass");
        encReq.setParanoid(true);
        encReq.setRsCodecs(rs);
        Encryptor.encrypt(encReq);

        DecryptRequest decReq = new DecryptRequest();
        decReq.setInputFile(encrypted.toString());
        decReq.setOutputFile(decrypted.toString());
        decReq.setPassword("paranoid-pass");
        decReq.setRsCodecs(rs);
        Decryptor.decrypt(decReq);

        assertArrayEquals(plaintext, Files.readAllBytes(decrypted));
    }

    @Test
    void testRoundTripReedSolomon(@TempDir Path tempDir) throws Exception {
        byte[] plaintext = generateTestData(2 * 1024 * 1024 + 777); // ~2 MiB + partial
        Path input = createFile(tempDir, "rs_test.bin", plaintext);

        Path encrypted = tempDir.resolve("rs.ergou");
        Path decrypted = tempDir.resolve("rs_dec.bin");

        EncryptRequest encReq = new EncryptRequest();
        encReq.setInputFile(input.toString());
        encReq.setOutputFile(encrypted.toString());
        encReq.setPassword("rs-pass");
        encReq.setReedSolomon(true);
        encReq.setRsCodecs(rs);
        Encryptor.encrypt(encReq);

        DecryptRequest decReq = new DecryptRequest();
        decReq.setInputFile(encrypted.toString());
        decReq.setOutputFile(decrypted.toString());
        decReq.setPassword("rs-pass");
        decReq.setRsCodecs(rs);
        Decryptor.decrypt(decReq);

        assertArrayEquals(plaintext, Files.readAllBytes(decrypted));
    }

    @Test
    void testRoundTripWithComments(@TempDir Path tempDir) throws Exception {
        byte[] plaintext = "File with comments test.\n".getBytes();
        Path input = createFile(tempDir, "comment_test.txt", plaintext);

        Path encrypted = tempDir.resolve("comment.ergou");
        Path decrypted = tempDir.resolve("comment_dec.txt");

        String comment = "This is a test comment! Unicode: 日本語 :lock:";

        EncryptRequest encReq = new EncryptRequest();
        encReq.setInputFile(input.toString());
        encReq.setOutputFile(encrypted.toString());
        encReq.setPassword("comment-pass");
        encReq.setComments(comment);
        encReq.setRsCodecs(rs);
        Encryptor.encrypt(encReq);

        DecryptRequest decReq = new DecryptRequest();
        decReq.setInputFile(encrypted.toString());
        decReq.setOutputFile(decrypted.toString());
        decReq.setPassword("comment-pass");
        decReq.setRsCodecs(rs);
        Decryptor.decrypt(decReq);

        assertArrayEquals(plaintext, Files.readAllBytes(decrypted));
    }

    @Test
    void testRoundTripWithKeyfile(@TempDir Path tempDir) throws Exception {
        byte[] plaintext = "Keyfile-protected file.\n".getBytes();
        Path input = createFile(tempDir, "kf_test.txt", plaintext);

        Path keyfilePath = createFile(tempDir, "my.key", "this-is-a-keyfile-secret".getBytes());
        Path encrypted = tempDir.resolve("kf.ergou");
        Path decrypted = tempDir.resolve("kf_dec.txt");

        EncryptRequest encReq = new EncryptRequest();
        encReq.setInputFile(input.toString());
        encReq.setOutputFile(encrypted.toString());
        encReq.setPassword("keyfile-pass");
        encReq.setKeyfiles(List.of(keyfilePath.toString()));
        encReq.setRsCodecs(rs);
        Encryptor.encrypt(encReq);

        DecryptRequest decReq = new DecryptRequest();
        decReq.setInputFile(encrypted.toString());
        decReq.setOutputFile(decrypted.toString());
        decReq.setPassword("keyfile-pass");
        decReq.setKeyfiles(List.of(keyfilePath.toString()));
        decReq.setRsCodecs(rs);
        Decryptor.decrypt(decReq);

        assertArrayEquals(plaintext, Files.readAllBytes(decrypted));
    }

    @Test
    void testRoundTripEmptyFile(@TempDir Path tempDir) throws Exception {
        byte[] plaintext = new byte[0];
        Path input = createFile(tempDir, "empty.bin", plaintext);

        Path encrypted = tempDir.resolve("empty.ergou");
        Path decrypted = tempDir.resolve("empty_dec.bin");

        EncryptRequest encReq = new EncryptRequest();
        encReq.setInputFile(input.toString());
        encReq.setOutputFile(encrypted.toString());
        encReq.setPassword("empty-pass");
        encReq.setRsCodecs(rs);
        Encryptor.encrypt(encReq);

        DecryptRequest decReq = new DecryptRequest();
        decReq.setInputFile(encrypted.toString());
        decReq.setOutputFile(decrypted.toString());
        decReq.setPassword("empty-pass");
        decReq.setRsCodecs(rs);
        Decryptor.decrypt(decReq);

        assertEquals(0, Files.size(decrypted));
    }

    @Test
    void testRoundTripPasswordless(@TempDir Path tempDir) throws Exception {
        byte[] plaintext = "Passwordless encryption test.\n".getBytes();
        Path input = createFile(tempDir, "nopass_test.txt", plaintext);

        Path encrypted = tempDir.resolve("nopass.ergou");
        Path decrypted = tempDir.resolve("nopass_dec.txt");

        // Encrypt WITHOUT password → internally uses DEFAULT_PASSWORD
        EncryptRequest encReq = new EncryptRequest();
        encReq.setInputFile(input.toString());
        encReq.setOutputFile(encrypted.toString());
        encReq.setPassword(null); // no password
        encReq.setRsCodecs(rs);
        Encryptor.encrypt(encReq);

        assertTrue(Files.exists(encrypted));
        assertTrue(Files.size(encrypted) > 0);

        // Decrypt WITHOUT password → internally uses DEFAULT_PASSWORD, succeeds
        DecryptRequest decReq = new DecryptRequest();
        decReq.setInputFile(encrypted.toString());
        decReq.setOutputFile(decrypted.toString());
        decReq.setPassword(null); // also no password
        decReq.setRsCodecs(rs);
        Decryptor.decrypt(decReq);

        assertTrue(Files.exists(decrypted), "decrypted file should exist");
        assertArrayEquals(plaintext, Files.readAllBytes(decrypted),
                "passwordless roundtrip should be byte-identical");
    }

    @Test
    void testRoundTripPasswordlessWithKeyfile(@TempDir Path tempDir) throws Exception {
        byte[] plaintext = "Keyfile-only encryption test.\n".getBytes();
        Path input = createFile(tempDir, "kfonly_test.txt", plaintext);
        Path keyfilePath = createFile(tempDir, "master.key",
                "this-keyfile-replaces-the-password-entirely".getBytes());

        Path encrypted = tempDir.resolve("kfonly.ergou");
        Path decrypted = tempDir.resolve("kfonly_dec.txt");

        // Encrypt with keyfile only (no password)
        EncryptRequest encReq = new EncryptRequest();
        encReq.setInputFile(input.toString());
        encReq.setOutputFile(encrypted.toString());
        encReq.setPassword(null);
        encReq.setKeyfiles(List.of(keyfilePath.toString()));
        encReq.setRsCodecs(rs);
        Encryptor.encrypt(encReq);

        // Decrypt with same keyfile (no password)
        DecryptRequest decReq = new DecryptRequest();
        decReq.setInputFile(encrypted.toString());
        decReq.setOutputFile(decrypted.toString());
        decReq.setPassword(null);
        decReq.setKeyfiles(List.of(keyfilePath.toString()));
        decReq.setRsCodecs(rs);
        Decryptor.decrypt(decReq);

        assertArrayEquals(plaintext, Files.readAllBytes(decrypted));
    }

    @Test
    void testWrongPasswordFails(@TempDir Path tempDir) throws Exception {
        byte[] plaintext = "Password test file.\n".getBytes();
        Path input = createFile(tempDir, "pwd_test.txt", plaintext);

        Path encrypted = tempDir.resolve("pwd.ergou");
        Path decrypted = tempDir.resolve("pwd_dec.txt");

        EncryptRequest encReq = new EncryptRequest();
        encReq.setInputFile(input.toString());
        encReq.setOutputFile(encrypted.toString());
        encReq.setPassword("correct-password");
        encReq.setRsCodecs(rs);
        Encryptor.encrypt(encReq);

        DecryptRequest decReq = new DecryptRequest();
        decReq.setInputFile(encrypted.toString());
        decReq.setOutputFile(decrypted.toString());
        decReq.setPassword("wrong-password");
        decReq.setRsCodecs(rs);

        assertThrows(Exception.class, () -> Decryptor.decrypt(decReq),
                "wrong password should fail");
        // Output file should NOT exist
        assertFalse(Files.exists(decrypted), "decrypted file should not exist after wrong password");
    }

    @Test
    void testWrongKeyfileFails(@TempDir Path tempDir) throws Exception {
        byte[] plaintext = "Keyfile test.\n".getBytes();
        Path input = createFile(tempDir, "kffail_test.txt", plaintext);
        Path correctKeyfile = createFile(tempDir, "correct.key", "correct-keyfile".getBytes());
        Path wrongKeyfile = createFile(tempDir, "wrong.key", "wrong-keyfile-content".getBytes());

        Path encrypted = tempDir.resolve("kffail.ergou");
        Path decrypted = tempDir.resolve("kffail_dec.txt");

        EncryptRequest encReq = new EncryptRequest();
        encReq.setInputFile(input.toString());
        encReq.setOutputFile(encrypted.toString());
        encReq.setPassword("kf-pass");
        encReq.setKeyfiles(List.of(correctKeyfile.toString()));
        encReq.setRsCodecs(rs);
        Encryptor.encrypt(encReq);

        DecryptRequest decReq = new DecryptRequest();
        decReq.setInputFile(encrypted.toString());
        decReq.setOutputFile(decrypted.toString());
        decReq.setPassword("kf-pass");
        decReq.setKeyfiles(List.of(wrongKeyfile.toString()));
        decReq.setRsCodecs(rs);

        assertThrows(Exception.class, () -> Decryptor.decrypt(decReq),
                "wrong keyfile should fail");
    }

    @Test
    void testRoundTripEmptyComments(@TempDir Path tempDir) throws Exception {
        byte[] plaintext = "Zero-length comments.\n".getBytes();
        Path input = createFile(tempDir, "zero_comment.txt", plaintext);

        Path encrypted = tempDir.resolve("zero_comment.ergou");
        Path decrypted = tempDir.resolve("zero_comment_dec.txt");

        EncryptRequest encReq = new EncryptRequest();
        encReq.setInputFile(input.toString());
        encReq.setOutputFile(encrypted.toString());
        encReq.setPassword("zero-pass");
        encReq.setComments(""); // explicitly empty
        encReq.setRsCodecs(rs);
        Encryptor.encrypt(encReq);

        DecryptRequest decReq = new DecryptRequest();
        decReq.setInputFile(encrypted.toString());
        decReq.setOutputFile(decrypted.toString());
        decReq.setPassword("zero-pass");
        decReq.setRsCodecs(rs);
        Decryptor.decrypt(decReq);

        assertArrayEquals(plaintext, Files.readAllBytes(decrypted));
    }

    @Test
    void testEncryptedFileHeaderIsWellFormed(@TempDir Path tempDir) throws Exception {
        byte[] plaintext = generateTestData(500);
        Path input = createFile(tempDir, "header_check.bin", plaintext);

        Path encrypted = tempDir.resolve("header_check.ergou");

        EncryptRequest encReq = new EncryptRequest();
        encReq.setInputFile(input.toString());
        encReq.setOutputFile(encrypted.toString());
        encReq.setPassword("hdr-check");
        encReq.setRsCodecs(rs);
        Encryptor.encrypt(encReq);

        // Verify header can be read back
        try (java.io.InputStream in = Files.newInputStream(encrypted)) {
            String version = hbnu.project.ergoutreecrypt.header.HeaderReader.peekVersion(in, rs);
            assertEquals(hbnu.project.ergoutreecrypt.header.VolumeHeader.CURRENT_VERSION, version);
        }

        // Verify total file size = header + encrypted data
        long fileSize = Files.size(encrypted);
        assertTrue(fileSize > 789, "file should be larger than base header");
    }

    // ================================================================
    // Deniability
    // ================================================================

    @Test
    void testRoundTripDeniability(@TempDir Path tempDir) throws Exception {
        byte[] plaintext = generateTestData(1024 * 512); // 512 KiB
        Path input = createFile(tempDir, "deny_test.bin", plaintext);
        Path encrypted = tempDir.resolve("deny.ergou");
        Path decrypted = tempDir.resolve("deny_dec.bin");

        EncryptRequest encReq = new EncryptRequest();
        encReq.setInputFile(input.toString());
        encReq.setOutputFile(encrypted.toString());
        encReq.setPassword("deniability-pass");
        encReq.setDeniability(true);
        encReq.setRsCodecs(rs);
        Encryptor.encrypt(encReq);

        // Verify deniability wrapper is detectable
        assertTrue(Deniability.isDeniable(encrypted.toString(), rs),
                "file should be detected as deniable");

        DecryptRequest decReq = new DecryptRequest();
        decReq.setInputFile(encrypted.toString());
        decReq.setOutputFile(decrypted.toString());
        decReq.setPassword("deniability-pass");
        decReq.setDeniability(true); // signal to strip deniability
        decReq.setRsCodecs(rs);
        Decryptor.decrypt(decReq);

        assertArrayEquals(plaintext, Files.readAllBytes(decrypted));
    }

    @Test
    void testDeniabilityWrongPasswordFails(@TempDir Path tempDir) throws Exception {
        byte[] plaintext = generateTestData(1024);
        Path input = createFile(tempDir, "deny_wrong.bin", plaintext);
        Path encrypted = tempDir.resolve("deny_wrong.ergou");

        EncryptRequest encReq = new EncryptRequest();
        encReq.setInputFile(input.toString());
        encReq.setOutputFile(encrypted.toString());
        encReq.setPassword("correct-pass");
        encReq.setDeniability(true);
        encReq.setRsCodecs(rs);
        Encryptor.encrypt(encReq);

        DecryptRequest decReq = new DecryptRequest();
        decReq.setInputFile(encrypted.toString());
        decReq.setOutputFile(tempDir.resolve("out.bin").toString());
        decReq.setPassword("wrong-pass");
        decReq.setDeniability(true);
        decReq.setRsCodecs(rs);

        assertThrows(Exception.class, () -> Decryptor.decrypt(decReq),
                "deniability wrong password should fail");
    }

    @Test
    void testDeniabilityWithKeyfile(@TempDir Path tempDir) throws Exception {
        byte[] plaintext = "Deniability + keyfile test.\n".getBytes();
        Path input = createFile(tempDir, "deny_kf_test.txt", plaintext);
        Path kf = createFile(tempDir, "deny.key", "deniability-keyfile-secret".getBytes());
        Path encrypted = tempDir.resolve("deny_kf.ergou");
        Path decrypted = tempDir.resolve("deny_kf_dec.txt");

        EncryptRequest encReq = new EncryptRequest();
        encReq.setInputFile(input.toString());
        encReq.setOutputFile(encrypted.toString());
        encReq.setPassword("deny-kf-pass");
        encReq.setKeyfiles(List.of(kf.toString()));
        encReq.setDeniability(true);
        encReq.setRsCodecs(rs);
        Encryptor.encrypt(encReq);

        DecryptRequest decReq = new DecryptRequest();
        decReq.setInputFile(encrypted.toString());
        decReq.setOutputFile(decrypted.toString());
        decReq.setPassword("deny-kf-pass");
        decReq.setKeyfiles(List.of(kf.toString()));
        decReq.setDeniability(true);
        decReq.setRsCodecs(rs);
        Decryptor.decrypt(decReq);

        assertArrayEquals(plaintext, Files.readAllBytes(decrypted));
    }

    // ================================================================
    // Split / Recombine
    // ================================================================

    @Test
    void testRoundTripSplit(@TempDir Path tempDir) throws Exception {
        byte[] plaintext = generateTestData(3 * 1024 * 1024); // ~3 MiB
        Path input = createFile(tempDir, "split_test.bin", plaintext);
        Path encrypted = tempDir.resolve("split.ergou");
        Path decrypted = tempDir.resolve("split_dec.bin");

        EncryptRequest encReq = new EncryptRequest();
        encReq.setInputFile(input.toString());
        encReq.setOutputFile(encrypted.toString());
        encReq.setPassword("split-pass");
        encReq.setSplit(true);
        encReq.setChunkSize(1); // 1 MiB chunks
        encReq.setRsCodecs(rs);
        Encryptor.encrypt(encReq);

        // 单文件分卷：加密结果移入以原文件同名的文件夹中再分卷
        // folderName = "split" (strip .ergou from split.ergou)
        Path chunkDir = tempDir.resolve("split");
        assertFalse(Files.exists(encrypted), "unsplit file should be deleted");
        assertTrue(Files.exists(chunkDir.resolve("split.ergou.0")), "chunk 0 should exist");
        assertTrue(Files.exists(chunkDir.resolve("split.ergou.1")), "chunk 1 should exist");

        // Decrypt with recombine — use the chunk base inside the folder
        DecryptRequest decReq = new DecryptRequest();
        decReq.setInputFile(chunkDir.resolve("split.ergou.0").toString()); // first chunk
        decReq.setOutputFile(decrypted.toString());
        decReq.setPassword("split-pass");
        decReq.setRecombine(true); // signal recombine
        decReq.setRsCodecs(rs);
        Decryptor.decrypt(decReq);

        assertArrayEquals(plaintext, Files.readAllBytes(decrypted));
    }

    @Test
    void testRoundTripSplitWithDeniability(@TempDir Path tempDir) throws Exception {
        byte[] plaintext = generateTestData(3 * 1024 * 1024); // ~3 MiB
        Path input = createFile(tempDir, "split_deny.bin", plaintext);
        Path encrypted = tempDir.resolve("split_deny.ergou");

        EncryptRequest encReq = new EncryptRequest();
        encReq.setInputFile(input.toString());
        encReq.setOutputFile(encrypted.toString());
        encReq.setPassword("split-deny-pass");
        encReq.setDeniability(true);
        encReq.setSplit(true);
        encReq.setChunkSize(1); // 1 MiB chunks
        encReq.setRsCodecs(rs);
        Encryptor.encrypt(encReq);

        // 单文件分卷：chunk 在 split_deny/ 子文件夹中
        Path chunkDir = tempDir.resolve("split_deny");
        assertTrue(Files.exists(chunkDir.resolve("split_deny.ergou.0")), "chunk 0 should exist");

        DecryptRequest decReq = new DecryptRequest();
        decReq.setInputFile(chunkDir.resolve("split_deny.ergou.0").toString());
        decReq.setOutputFile(tempDir.resolve("split_deny_dec.bin").toString());
        decReq.setPassword("split-deny-pass");
        decReq.setDeniability(true);
        decReq.setRecombine(true);
        decReq.setRsCodecs(rs);
        Decryptor.decrypt(decReq);

        assertArrayEquals(plaintext, Files.readAllBytes(tempDir.resolve("split_deny_dec.bin")));
    }

    @Test
    void testIsNotDeniable(@TempDir Path tempDir) throws Exception {
        // A regular encrypted file (no deniability) should NOT be detected as deniable
        byte[] plaintext = generateTestData(1024);
        Path input = createFile(tempDir, "regular.bin", plaintext);
        Path encrypted = tempDir.resolve("regular.ergou");

        EncryptRequest encReq = new EncryptRequest();
        encReq.setInputFile(input.toString());
        encReq.setOutputFile(encrypted.toString());
        encReq.setPassword("regular-pass");
        encReq.setRsCodecs(rs);
        Encryptor.encrypt(encReq);

        assertFalse(Deniability.isDeniable(encrypted.toString(), rs),
                "regular file should NOT be detected as deniable");
    }

    @Test
    void testAllOptionsCombined(@TempDir Path tempDir) throws Exception {
        // Test: Paranoid + RS + Deniability + Split — all together
        byte[] plaintext = generateTestData(200 * 1024); // 200 KiB
        Path input = createFile(tempDir, "all_opts.bin", plaintext);
        Path kf = createFile(tempDir, "all_opts.key", "all-options-keyfile".getBytes());
        Path encrypted = tempDir.resolve("all_opts.ergou");

        EncryptRequest encReq = new EncryptRequest();
        encReq.setInputFile(input.toString());
        encReq.setOutputFile(encrypted.toString());
        encReq.setPassword("all-pass");
        encReq.setKeyfiles(List.of(kf.toString()));
        encReq.setParanoid(true);
        encReq.setReedSolomon(true);
        encReq.setDeniability(true);
        encReq.setSplit(true);
        encReq.setChunkSize(50); // 50 KiB chunks
        encReq.setRsCodecs(rs);
        Encryptor.encrypt(encReq);

        // 单文件分卷：chunk 在 all_opts/ 子文件夹中
        Path chunkDir = tempDir.resolve("all_opts");
        DecryptRequest decReq = new DecryptRequest();
        decReq.setInputFile(chunkDir.resolve("all_opts.ergou.0").toString());
        decReq.setOutputFile(tempDir.resolve("all_opts_dec.bin").toString());
        decReq.setPassword("all-pass");
        decReq.setKeyfiles(List.of(kf.toString()));
        decReq.setDeniability(true);
        decReq.setRecombine(true);
        decReq.setRsCodecs(rs);
        Decryptor.decrypt(decReq);

        assertArrayEquals(plaintext, Files.readAllBytes(tempDir.resolve("all_opts_dec.bin")));
    }

    @Test
    void testLargeFileRoundTrip(@TempDir Path tempDir) throws Exception {
        // Test a larger file (~5 MiB) to exercise the full streaming pipeline
        byte[] plaintext = generateTestData(5 * 1024 * 1024 + 12345); // 5 MiB + offset
        Path input = createFile(tempDir, "large.bin", plaintext);
        Path encrypted = tempDir.resolve("large.ergou");
        Path decrypted = tempDir.resolve("large_dec.bin");

        EncryptRequest encReq = new EncryptRequest();
        encReq.setInputFile(input.toString());
        encReq.setOutputFile(encrypted.toString());
        encReq.setPassword("large-pass");
        encReq.setRsCodecs(rs);
        Encryptor.encrypt(encReq);

        DecryptRequest decReq = new DecryptRequest();
        decReq.setInputFile(encrypted.toString());
        decReq.setOutputFile(decrypted.toString());
        decReq.setPassword("large-pass");
        decReq.setRsCodecs(rs);
        Decryptor.decrypt(decReq);

        assertArrayEquals(plaintext, Files.readAllBytes(decrypted));
    }

    @Test
    void testParanoidRsOnly(@TempDir Path tempDir) throws Exception {
        byte[] plaintext = generateTestData(200 * 1024);
        Path input = createFile(tempDir, "pr.bin", plaintext);
        Path encrypted = tempDir.resolve("pr.ergou");
        Path decrypted = tempDir.resolve("pr_dec.bin");

        EncryptRequest encReq = new EncryptRequest();
        encReq.setInputFile(input.toString());
        encReq.setOutputFile(encrypted.toString());
        encReq.setPassword("pr-pass");
        encReq.setParanoid(true);
        encReq.setReedSolomon(true);
        encReq.setRsCodecs(rs);
        Encryptor.encrypt(encReq);

        DecryptRequest decReq = new DecryptRequest();
        decReq.setInputFile(encrypted.toString());
        decReq.setOutputFile(decrypted.toString());
        decReq.setPassword("pr-pass");
        decReq.setForceDecrypt(true); // ignore MAC, just check bytes
        decReq.setRsCodecs(rs);
        Decryptor.decrypt(decReq);

        byte[] got = Files.readAllBytes(decrypted);
        if (!Arrays.equals(plaintext, got)) {
            int firstDiff = -1;
            for (int i = 0; i < Math.min(plaintext.length, got.length); i++) {
                if (plaintext[i] != got[i]) { firstDiff = i; break; }
            }
            System.out.println("LEN exp=" + plaintext.length + " got=" + got.length
                    + " firstDiff=" + firstDiff);
        }
        assertArrayEquals(plaintext, got);
    }

    // ================================================================
    // Helpers
    // ================================================================

    private static Path createFile(Path dir, String name, byte[] data) throws IOException {
        Path path = dir.resolve(name);
        Files.write(path, data);
        return path;
    }

    private static byte[] generateTestData(int size) {
        byte[] data = new byte[size];
        for (int i = 0; i < size; i++) {
            data[i] = (byte) ((i * 7 + 1) & 0xff);
        }
        return data;
    }
}
