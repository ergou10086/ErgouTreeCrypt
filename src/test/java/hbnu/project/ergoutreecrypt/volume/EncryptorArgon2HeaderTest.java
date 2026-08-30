package hbnu.project.ergoutreecrypt.volume;

import hbnu.project.ergoutreecrypt.crypto.CryptoConstants;
import hbnu.project.ergoutreecrypt.encoding.RsCodecs;
import hbnu.project.ergoutreecrypt.header.HeaderReader;
import hbnu.project.ergoutreecrypt.header.VolumeHeader;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Phase B1：桌面端始终把 Argon2 参数写进卷头（记录参数）测试。
 *
 * <p>验证加密后卷头：
 * <ul>
 *   <li>普通模式：v2.15，记录默认 1 GiB / 4 轮 / 4 线程；</li>
 *   <li>偏执模式：v2.15，记录默认 1 GiB / 8 轮 / 8 线程；</li>
 *   <li>加密前压缩：v2.16，压缩标志置位且同样记录参数；</li>
 *   <li>显式覆写（移动端档位）：记录覆写值；</li>
 *   <li>部分覆写：缺失字段回落到普通默认值（与 {@code Argon2Kdf.deriveKey} 一致）。</li>
 * </ul>
 *
 * <p>每一场景同时做一次解密往返、逐字节比对，证明「卷头记录的参数」与「实际派生
 * 所用的参数」严格一致（若不一致，HMAC 校验必然失败、解密抛异常）。
 *
 * @author ErgouTree
 */
public final class EncryptorArgon2HeaderTest {

    private static final RsCodecs RS = new RsCodecs();

    /**
     * 普通模式：卷头 v2.15 且记录默认 1 GiB / 4 / 4 参数。
     */
    @Test
    void normalMode_recordsDefaultParamsAndV215(@TempDir Path tempDir) throws Exception {
        byte[] plaintext = "normal-mode".getBytes(StandardCharsets.UTF_8);
        EncryptRequest req = baseRequest(tempDir, "normal.ergou", plaintext);
        Encryptor.encrypt(req);

        VolumeHeader h = readHeader(req.getOutputFile());
        assertEquals(VolumeHeader.VERSION_V215, h.getVersion());
        assertTrue(h.hasArgon2Params());
        assertEquals(CryptoConstants.ARGON2_NORMAL_MEMORY_KIB, h.getArgon2MemoryKib());
        assertEquals(CryptoConstants.ARGON2_NORMAL_PASSES, h.getArgon2Passes());
        assertEquals(CryptoConstants.ARGON2_NORMAL_THREADS, h.getArgon2Threads());
        assertFalse(h.isCompressed());

        assertRoundTrip(plaintext, req, tempDir.resolve("normal.dec"));
    }

    /**
     * 偏执模式：卷头 v2.15 且记录默认 1 GiB / 8 / 8 参数。
     */
    @Test
    void paranoidMode_recordsParanoidParamsAndV215(@TempDir Path tempDir) throws Exception {
        byte[] plaintext = "paranoid-mode".getBytes(StandardCharsets.UTF_8);
        EncryptRequest req = baseRequest(tempDir, "paranoid.ergou", plaintext);
        req.setParanoid(true);
        Encryptor.encrypt(req);

        VolumeHeader h = readHeader(req.getOutputFile());
        assertEquals(VolumeHeader.VERSION_V215, h.getVersion());
        assertTrue(h.hasArgon2Params());
        assertEquals(CryptoConstants.ARGON2_PARANOID_MEMORY_KIB, h.getArgon2MemoryKib());
        assertEquals(CryptoConstants.ARGON2_PARANOID_PASSES, h.getArgon2Passes());
        assertEquals(CryptoConstants.ARGON2_PARANOID_THREADS, h.getArgon2Threads());

        assertRoundTrip(plaintext, req, tempDir.resolve("paranoid.dec"));
    }

    /**
     * 加密前压缩：卷头 v2.16、压缩标志置位，且同样记录有效参数（不再全零）。
     */
    @Test
    void compressMode_recordsParamsAndV216(@TempDir Path tempDir) throws Exception {
        byte[] plaintext = "compress-mode".getBytes(StandardCharsets.UTF_8);
        EncryptRequest req = baseRequest(tempDir, "compress.ergou", plaintext);
        req.setCompress(true);
        Encryptor.encrypt(req);

        VolumeHeader h = readHeader(req.getOutputFile());
        assertEquals(VolumeHeader.VERSION_V216, h.getVersion());
        assertTrue(h.isCompressed());
        assertTrue(h.hasArgon2Params(), "压缩文件也应记录有效 Argon2 参数");
        assertEquals(CryptoConstants.ARGON2_NORMAL_MEMORY_KIB, h.getArgon2MemoryKib());
        assertEquals(CryptoConstants.ARGON2_NORMAL_PASSES, h.getArgon2Passes());
        assertEquals(CryptoConstants.ARGON2_NORMAL_THREADS, h.getArgon2Threads());

        assertRoundTrip(plaintext, req, tempDir.resolve("compress.dec"));
    }

    /**
     * 显式覆写（移动端 256 MiB 档）：卷头记录覆写值。
     */
    @Test
    void overrideMode_recordsMobileParams(@TempDir Path tempDir) throws Exception {
        byte[] plaintext = "override-mode".getBytes(StandardCharsets.UTF_8);
        int mem = 256 << 10;
        EncryptRequest req = baseRequest(tempDir, "override.ergou", plaintext);
        req.setArgon2MemoryKib(mem);
        req.setArgon2Passes(3);
        req.setArgon2Threads(4);
        Encryptor.encrypt(req);

        VolumeHeader h = readHeader(req.getOutputFile());
        assertEquals(VolumeHeader.VERSION_V215, h.getVersion());
        assertEquals(mem, h.getArgon2MemoryKib());
        assertEquals(3, h.getArgon2Passes());
        assertEquals(4, h.getArgon2Threads());

        assertRoundTrip(plaintext, req, tempDir.resolve("override.dec"));
    }

    /**
     * 部分覆写：仅覆写内存，passes/threads 回落到普通默认值，与 deriveKey 决策一致。
     */
    @Test
    void partialOverride_usesDefaultsForMissingFields(@TempDir Path tempDir) throws Exception {
        byte[] plaintext = "partial-override".getBytes(StandardCharsets.UTF_8);
        int mem = 256 << 10;
        EncryptRequest req = baseRequest(tempDir, "partial.ergou", plaintext);
        req.setArgon2MemoryKib(mem);
        Encryptor.encrypt(req);

        VolumeHeader h = readHeader(req.getOutputFile());
        assertEquals(VolumeHeader.VERSION_V215, h.getVersion());
        assertEquals(mem, h.getArgon2MemoryKib());
        assertEquals(CryptoConstants.ARGON2_NORMAL_PASSES, h.getArgon2Passes());
        assertEquals(CryptoConstants.ARGON2_NORMAL_THREADS, h.getArgon2Threads());

        assertRoundTrip(plaintext, req, tempDir.resolve("partial.dec"));
    }

    /**
     * 构建基础加密请求（普通模式、固定密码），并把明文写入输入文件。
     */
    private static EncryptRequest baseRequest(Path dir, String name, byte[] plaintext)
            throws Exception {
        Path input = dir.resolve("in.txt");
        Files.write(input, plaintext);
        EncryptRequest req = new EncryptRequest();
        req.setInputFile(input.toString());
        req.setOutputFile(dir.resolve(name).toString());
        req.setPassword("b1-test-password");
        req.setRsCodecs(RS);
        return req;
    }

    /**
     * 读取加密文件的卷头。
     */
    private static VolumeHeader readHeader(String encryptedFile) throws Exception {
        try (InputStream in = Files.newInputStream(Path.of(encryptedFile))) {
            return new HeaderReader(in, RS).readHeader().getHeader();
        }
    }

    /**
     * 解密并逐字节比对明文（同时印证卷头参数与派生参数一致）。
     */
    private static void assertRoundTrip(byte[] plaintext, EncryptRequest encReq, Path decPath)
            throws Exception {
        DecryptRequest decReq = new DecryptRequest();
        decReq.setInputFile(encReq.getOutputFile());
        decReq.setOutputFile(decPath.toString());
        decReq.setPassword(encReq.getPassword());
        decReq.setRsCodecs(RS);
        Decryptor.decrypt(decReq);
        assertArrayEquals(plaintext, Files.readAllBytes(decPath));
    }
}
