package hbnu.project.ergoutreecrypt.volume;

import hbnu.project.ergoutreecrypt.encoding.RsCodecs;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 双卷可否认加密（DualDeniability）单元测试。
 *
 * @author ErgouTree
 */
public final class DualDeniabilityTest {

    private static RsCodecs rs;

    @BeforeAll
    static void setUp() {
        rs = new RsCodecs();
    }

    // ================================================================
    // 基本加解密
    // ================================================================

    @Test
    void testEncryptDecryptRealPassword(@TempDir Path tempDir) throws Exception {
        byte[] realData = generateTestData(1024 * 512);
        byte[] decoyData = "This is harmless decoy content.\n".getBytes(StandardCharsets.UTF_8);

        Path realFile = createFile(tempDir, "secret.pdf", realData);
        Path decoyFile = createFile(tempDir, "decoy.txt", decoyData);
        Path output = tempDir.resolve("dual.ergou");
        Path decrypted = tempDir.resolve("output.bin");

        // 加密
        EncryptRequest encReq = new EncryptRequest();
        encReq.setInputFile(realFile.toString());
        encReq.setDecoyFilePath(decoyFile.toString());
        encReq.setPassword("real-password-123");
        encReq.setFakePassword("fake-password-456");
        encReq.setDualDeniability(true);
        encReq.setOutputFile(output.toString());
        encReq.setRsCodecs(rs);

        Encryptor.encrypt(encReq);
        assertTrue(Files.exists(output), "encrypted EGTD file should exist");
        assertTrue(DualDeniability.isDualDeniable(output.toString()),
                "should be detected as dual-deniable");

        // 用真实密码解密
        DecryptRequest decReq = new DecryptRequest();
        decReq.setInputFile(output.toString());
        decReq.setOutputFile(decrypted.toString());
        decReq.setPassword("real-password-123");
        decReq.setRsCodecs(rs);

        Decryptor.decrypt(decReq);
        assertTrue(Files.exists(decrypted), "decrypted file should exist");
        assertArrayEquals(realData, Files.readAllBytes(decrypted),
                "real password should decrypt real data");
    }

    @Test
    void testEncryptDecryptFakePassword(@TempDir Path tempDir) throws Exception {
        byte[] realData = generateTestData(1024 * 512);
        byte[] decoyData = "Harmless decoy content for coercion scenario.\n"
                .getBytes(StandardCharsets.UTF_8);

        Path realFile = createFile(tempDir, "secret.pdf", realData);
        Path decoyFile = createFile(tempDir, "decoy.txt", decoyData);
        Path output = tempDir.resolve("dual.ergou");
        Path decrypted = tempDir.resolve("output.txt");

        EncryptRequest encReq = new EncryptRequest();
        encReq.setInputFile(realFile.toString());
        encReq.setDecoyFilePath(decoyFile.toString());
        encReq.setPassword("real-password-123");
        encReq.setFakePassword("fake-password-456");
        encReq.setDualDeniability(true);
        encReq.setOutputFile(output.toString());
        encReq.setRsCodecs(rs);
        Encryptor.encrypt(encReq);

        // 用钓鱼密码解密
        DecryptRequest decReq = new DecryptRequest();
        decReq.setInputFile(output.toString());
        decReq.setOutputFile(decrypted.toString());
        decReq.setPassword("fake-password-456");
        decReq.setRsCodecs(rs);
        Decryptor.decrypt(decReq);

        assertArrayEquals(decoyData, Files.readAllBytes(decrypted),
                "fake password should decrypt decoy data");
    }

    @Test
    void testWrongPasswordFails(@TempDir Path tempDir) throws Exception {
        byte[] realData = generateTestData(1024);
        byte[] decoyData = "Decoy.\n".getBytes(StandardCharsets.UTF_8);

        Path realFile = createFile(tempDir, "real.bin", realData);
        Path decoyFile = createFile(tempDir, "decoy.txt", decoyData);
        Path output = tempDir.resolve("dual.ergou");
        Path decrypted = tempDir.resolve("output.bin");

        EncryptRequest encReq = new EncryptRequest();
        encReq.setInputFile(realFile.toString());
        encReq.setDecoyFilePath(decoyFile.toString());
        encReq.setPassword("real-pass");
        encReq.setFakePassword("fake-pass");
        encReq.setDualDeniability(true);
        encReq.setOutputFile(output.toString());
        encReq.setRsCodecs(rs);
        Encryptor.encrypt(encReq);

        DecryptRequest decReq = new DecryptRequest();
        decReq.setInputFile(output.toString());
        decReq.setOutputFile(decrypted.toString());
        decReq.setPassword("wrong-password");
        decReq.setRsCodecs(rs);

        assertThrows(Exception.class, () -> Decryptor.decrypt(decReq),
                "wrong password should fail");
        assertFalse(Files.exists(decrypted),
                "decrypted file should not exist after wrong password");
    }

    // ================================================================
    // 格式检测
    // ================================================================

    @Test
    void testIsDualDeniableTrue(@TempDir Path tempDir) throws Exception {
        byte[] realData = generateTestData(500);
        byte[] decoyData = "Decoy.\n".getBytes(StandardCharsets.UTF_8);
        Path realFile = createFile(tempDir, "real.bin", realData);
        Path decoyFile = createFile(tempDir, "decoy.txt", decoyData);
        Path output = tempDir.resolve("dual.ergou");

        EncryptRequest encReq = new EncryptRequest();
        encReq.setInputFile(realFile.toString());
        encReq.setDecoyFilePath(decoyFile.toString());
        encReq.setPassword("real");
        encReq.setFakePassword("fake");
        encReq.setDualDeniability(true);
        encReq.setOutputFile(output.toString());
        encReq.setRsCodecs(rs);
        Encryptor.encrypt(encReq);

        assertTrue(DualDeniability.isDualDeniable(output.toString()));
    }

    @Test
    void testIsDualDeniableFalse(@TempDir Path tempDir) throws Exception {
        // 普通 .ergou 文件不应被误判为 EGTD
        byte[] data = generateTestData(500);
        Path input = createFile(tempDir, "plain.bin", data);
        Path encrypted = tempDir.resolve("normal.ergou");

        EncryptRequest encReq = new EncryptRequest();
        encReq.setInputFile(input.toString());
        encReq.setOutputFile(encrypted.toString());
        encReq.setPassword("normal-pass");
        encReq.setRsCodecs(rs);
        Encryptor.encrypt(encReq);

        assertFalse(DualDeniability.isDualDeniable(encrypted.toString()),
                "regular .ergou should NOT be detected as dual-deniable");
    }

    @Test
    void testIsDualDeniableTooSmall(@TempDir Path tempDir) throws Exception {
        Path tiny = createFile(tempDir, "tiny.bin", "small".getBytes(StandardCharsets.UTF_8));
        assertFalse(DualDeniability.isDualDeniable(tiny.toString()),
                "files smaller than header should not be dual-deniable");
    }

    // ================================================================
    // 大文件
    // ================================================================

    @Test
    void testLargeFiles(@TempDir Path tempDir) throws Exception {
        byte[] realData = generateTestData(5 * 1024 * 1024 + 12345); // ~5 MiB
        byte[] decoyData = generateTestData(2 * 1024 * 1024); // ~2 MiB

        Path realFile = createFile(tempDir, "large_real.bin", realData);
        Path decoyFile = createFile(tempDir, "large_decoy.bin", decoyData);
        Path output = tempDir.resolve("large.ergou");
        Path decReal = tempDir.resolve("real_out.bin");
        Path decDecoy = tempDir.resolve("decoy_out.bin");

        EncryptRequest encReq = new EncryptRequest();
        encReq.setInputFile(realFile.toString());
        encReq.setDecoyFilePath(decoyFile.toString());
        encReq.setPassword("real-large");
        encReq.setFakePassword("fake-large");
        encReq.setDualDeniability(true);
        encReq.setOutputFile(output.toString());
        encReq.setRsCodecs(rs);
        Encryptor.encrypt(encReq);

        // 解密真实数据
        DecryptRequest decRealReq = new DecryptRequest();
        decRealReq.setInputFile(output.toString());
        decRealReq.setOutputFile(decReal.toString());
        decRealReq.setPassword("real-large");
        decRealReq.setRsCodecs(rs);
        Decryptor.decrypt(decRealReq);
        assertArrayEquals(realData, Files.readAllBytes(decReal));

        // 解密钓鱼数据
        DecryptRequest decDecoyReq = new DecryptRequest();
        decDecoyReq.setInputFile(output.toString());
        decDecoyReq.setOutputFile(decDecoy.toString());
        decDecoyReq.setPassword("fake-large");
        decDecoyReq.setRsCodecs(rs);
        Decryptor.decrypt(decDecoyReq);
        assertArrayEquals(decoyData, Files.readAllBytes(decDecoy));
    }

    // ================================================================
    // 偏执模式
    // ================================================================

    @Test
    void testWithParanoidMode(@TempDir Path tempDir) throws Exception {
        byte[] realData = generateTestData(200 * 1024);
        byte[] decoyData = "Paranoid decoy.\n".getBytes(StandardCharsets.UTF_8);

        Path realFile = createFile(tempDir, "real.bin", realData);
        Path decoyFile = createFile(tempDir, "decoy.txt", decoyData);
        Path output = tempDir.resolve("paranoid.ergou");
        Path decrypted = tempDir.resolve("out.bin");

        EncryptRequest encReq = new EncryptRequest();
        encReq.setInputFile(realFile.toString());
        encReq.setDecoyFilePath(decoyFile.toString());
        encReq.setPassword("real-paranoid");
        encReq.setFakePassword("fake-paranoid");
        encReq.setDualDeniability(true);
        encReq.setParanoid(true);
        encReq.setOutputFile(output.toString());
        encReq.setRsCodecs(rs);
        Encryptor.encrypt(encReq);

        // 真实密码解密
        DecryptRequest decReq = new DecryptRequest();
        decReq.setInputFile(output.toString());
        decReq.setOutputFile(decrypted.toString());
        decReq.setPassword("real-paranoid");
        decReq.setRsCodecs(rs);
        Decryptor.decrypt(decReq);
        assertArrayEquals(realData, Files.readAllBytes(decrypted));
    }

    // ================================================================
    // RS 纠错
    // ================================================================

    @Test
    void testWithReedSolomon(@TempDir Path tempDir) throws Exception {
        byte[] realData = generateTestData(200 * 1024);
        byte[] decoyData = generateTestData(100 * 1024);

        Path realFile = createFile(tempDir, "real.bin", realData);
        Path decoyFile = createFile(tempDir, "decoy.bin", decoyData);
        Path output = tempDir.resolve("rs.ergou");
        Path decrypted = tempDir.resolve("out.bin");

        EncryptRequest encReq = new EncryptRequest();
        encReq.setInputFile(realFile.toString());
        encReq.setDecoyFilePath(decoyFile.toString());
        encReq.setPassword("real-rs");
        encReq.setFakePassword("fake-rs");
        encReq.setDualDeniability(true);
        encReq.setReedSolomon(true);
        encReq.setOutputFile(output.toString());
        encReq.setRsCodecs(rs);
        Encryptor.encrypt(encReq);

        // 真实密码解密
        DecryptRequest decReq = new DecryptRequest();
        decReq.setInputFile(output.toString());
        decReq.setOutputFile(decrypted.toString());
        decReq.setPassword("real-rs");
        decReq.setRsCodecs(rs);
        Decryptor.decrypt(decReq);
        assertArrayEquals(realData, Files.readAllBytes(decrypted));
    }

    // ================================================================
    // 空文件
    // ================================================================

    @Test
    void testEmptyRealFile(@TempDir Path tempDir) throws Exception {
        byte[] realData = new byte[0];
        byte[] decoyData = "Non-empty decoy.\n".getBytes(StandardCharsets.UTF_8);

        Path realFile = createFile(tempDir, "empty.bin", realData);
        Path decoyFile = createFile(tempDir, "decoy.txt", decoyData);
        Path output = tempDir.resolve("empty.ergou");
        Path decrypted = tempDir.resolve("out.bin");

        EncryptRequest encReq = new EncryptRequest();
        encReq.setInputFile(realFile.toString());
        encReq.setDecoyFilePath(decoyFile.toString());
        encReq.setPassword("real-empty");
        encReq.setFakePassword("fake-empty");
        encReq.setDualDeniability(true);
        encReq.setOutputFile(output.toString());
        encReq.setRsCodecs(rs);
        Encryptor.encrypt(encReq);

        DecryptRequest decReq = new DecryptRequest();
        decReq.setInputFile(output.toString());
        decReq.setOutputFile(decrypted.toString());
        decReq.setPassword("real-empty");
        decReq.setRsCodecs(rs);
        Decryptor.decrypt(decReq);

        assertEquals(0, Files.size(decrypted), "empty real file should decrypt to empty");
    }

    // ================================================================
    // 无密码模式
    // ================================================================

    @Test
    void testPasswordlessRealPassword(@TempDir Path tempDir) throws Exception {
        byte[] realData = generateTestData(1024);
        byte[] decoyData = "Decoy.\n".getBytes(StandardCharsets.UTF_8);

        Path realFile = createFile(tempDir, "real.bin", realData);
        Path decoyFile = createFile(tempDir, "decoy.txt", decoyData);
        Path output = tempDir.resolve("nopass.ergou");
        Path decrypted = tempDir.resolve("out.bin");

        EncryptRequest encReq = new EncryptRequest();
        encReq.setInputFile(realFile.toString());
        encReq.setDecoyFilePath(decoyFile.toString());
        encReq.setPassword(null); // 无密码
        encReq.setFakePassword("fake-pass");
        encReq.setDualDeniability(true);
        encReq.setOutputFile(output.toString());
        encReq.setRsCodecs(rs);
        Encryptor.encrypt(encReq);

        DecryptRequest decReq = new DecryptRequest();
        decReq.setInputFile(output.toString());
        decReq.setOutputFile(decrypted.toString());
        decReq.setPassword(null); // 无密码
        decReq.setRsCodecs(rs);
        Decryptor.decrypt(decReq);
        assertArrayEquals(realData, Files.readAllBytes(decrypted));
    }

    // ================================================================
    // 元数据块随机性验证
    // ================================================================

    @Test
    void testMetaBlock2IsNotAllZeros(@TempDir Path tempDir) throws Exception {
        byte[] realData = generateTestData(1024);
        byte[] decoyData = "Decoy.\n".getBytes(StandardCharsets.UTF_8);

        Path realFile = createFile(tempDir, "real.bin", realData);
        Path decoyFile = createFile(tempDir, "decoy.txt", decoyData);
        Path output = tempDir.resolve("mb2.ergou");

        EncryptRequest encReq = new EncryptRequest();
        encReq.setInputFile(realFile.toString());
        encReq.setDecoyFilePath(decoyFile.toString());
        encReq.setPassword("real");
        encReq.setFakePassword("fake");
        encReq.setDualDeniability(true);
        encReq.setOutputFile(output.toString());
        encReq.setRsCodecs(rs);
        Encryptor.encrypt(encReq);

        // MetaBlock-2 位于偏移 9 + 552 = 561，大小 552
        byte[] fileBytes = Files.readAllBytes(output);
        byte[] mb2 = Arrays.copyOfRange(fileBytes, 9 + 552, 9 + 552 + 552);

        // Mini entropy check: not all zeros, not all identical
        boolean allZero = true;
        boolean allSame = true;
        byte first = mb2[0];
        for (byte b : mb2) {
            if (b != 0) {
                allZero = false;
            }
            if (b != first) {
                allSame = false;
            }
        }
        assertFalse(allZero, "MetaBlock-2 should not be all zeros (would reveal no hidden vol)");
        assertFalse(allSame, "MetaBlock-2 should have variation (would reveal no hidden vol)");
    }

    // ================================================================
    // 辅助方法
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
