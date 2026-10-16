package hbnu.project.ergoutreecrypt.keyfile;

import hbnu.project.ergoutreecrypt.encoding.RsCodecs;
import hbnu.project.ergoutreecrypt.volume.*;
import hbnu.project.ergoutreecrypt.exception.CryptoException;
import hbnu.project.ergoutreecrypt.exception.ErrorKind;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** 密钥文件不可被选项静默忽略，也不可在无序模式中部分抵消。 */
public class KeyfileSafetyTest {
    @TempDir Path root;

    /**
     * 重复内容夹在第三个密钥文件中也必须在加密前拒绝。
     * @throws Exception 测试失败
     */
    @Test void rejectsPartiallyCancelledKeyfiles() throws Exception {
        Path a = Files.write(root.resolve("a"), new byte[]{1, 2});
        Path copy = Files.copy(a, root.resolve("copy"));
        Path b = Files.write(root.resolve("b"), new byte[]{3, 4});
        EncryptRequest request = request();
        request.setKeyfiles(List.of(a.toString(), copy.toString(), b.toString()));
        assertThrows(java.io.IOException.class, () -> Encryptor.encrypt(request));
        assertFalse(Files.exists(Path.of(request.getOutputFile())));
        assertFalse(Files.exists(Path.of(request.getOutputFile() + ".incomplete")));
    }

    /**
     * 双卷格式没有密钥文件字段，必须显式拒绝该组合。
     * @throws Exception 测试失败
     */
    @Test void dualMustNotIgnoreKeyfiles() throws Exception {
        EncryptRequest request = request();
        request.setDualDeniability(true);
        request.setFakePassword("decoy");
        request.setDecoyFilePath(request.getInputFile());
        request.setKeyfiles(List.of(request.getInputFile()));
        CryptoException error = assertThrows(CryptoException.class, () -> Encryptor.encrypt(request));
        assertEquals(ErrorKind.UNSUPPORTED_FORMAT, error.kind());
        assertFalse(Files.exists(Path.of(request.getOutputFile())));
    }

    /**
     * 双卷的解密与独立认证入口也须明确拒绝无效密钥参数。
     * @throws Exception 测试失败
     */
    @Test void dualReadersMustNotIgnoreKeyfiles() throws Exception {
        DecryptRequest request = new DecryptRequest();
        request.setInputFile(root.resolve("missing.egtd").toString());
        request.setOutputFile(root.resolve("forbidden").toString());
        request.setKeyfiles(List.of("selected-key"));
        assertEquals(ErrorKind.UNSUPPORTED_FORMAT,
                assertThrows(CryptoException.class, () -> DualDeniability.verify(request)).kind());
        assertEquals(ErrorKind.UNSUPPORTED_FORMAT,
                assertThrows(CryptoException.class, () -> DualDeniability.decrypt(request)).kind());
        assertFalse(Files.exists(Path.of(request.getOutputFile())));
    }

    /**
     * 新任务拒绝重复内容，但读取旧格式保持原来的 SHA3/XOR 算法。
     * @throws Exception 测试失败
     */
    @Test void preservesLegacyDuplicateDerivation() throws Exception {
        Path a = Files.write(root.resolve("a"), new byte[]{1, 2});
        Path copy = Files.copy(a, root.resolve("copy"));
        Path b = Files.write(root.resolve("b"), new byte[]{3, 4});
        try (var legacy = KeyfileProcessor.process(List.of(a, copy, b), false, null);
             var single = KeyfileProcessor.process(List.of(b), false, null)) {
            assertArrayEquals(single.key(), legacy.key());
        }
        assertThrows(java.io.IOException.class,
                () -> KeyfileProcessor.processForEncryption(List.of(a, copy, b), false, null));
        try (var ordered = KeyfileProcessor.processForEncryption(List.of(a, copy, b), true, null)) {
            assertEquals(32, ordered.key().length);
        }
    }

    /**
     * @return 小内存参数的真实请求
     * @throws Exception 文件创建失败
     */
    private EncryptRequest request() throws Exception {
        EncryptRequest request = new EncryptRequest();
        request.setInputFile(Files.write(root.resolve("source"), new byte[]{7, 8, 9}).toString());
        request.setOutputFile(root.resolve("cipher.ergou").toString());
        request.setPassword("keyfile-audit");
        request.setRsCodecs(new RsCodecs());
        request.setArgon2MemoryKib(4096);
        request.setArgon2Passes(1);
        request.setArgon2Threads(1);
        return request;
    }

    /**
     * SHA3-256 固定向量同时约束有序拼接与无序单文件派生。
     * @throws Exception 测试失败
     */
    @Test void sha3GoldenVector() throws Exception {
        Path a = Files.write(root.resolve("a"), new byte[]{'a'});
        Path bc = Files.write(root.resolve("bc"), new byte[]{'b', 'c'});
        Path abc = Files.write(root.resolve("abc"), new byte[]{'a', 'b', 'c'});
        byte[] expected = java.util.HexFormat.of().parseHex("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
        try (var ordered = KeyfileProcessor.processForEncryption(List.of(a, bc), true, null);
             var unordered = KeyfileProcessor.processForEncryption(List.of(abc), false, null)) {
            assertArrayEquals(expected, ordered.key());
            assertArrayEquals(expected, unordered.key());
        }
    }

    /**
     * 旧版 A、A、B 派生等同单个 B，旧卷在修复后仍能读取。
     * @throws Exception 测试失败
     */
    @Test void readsLegacyPartiallyCancelledVolume() throws Exception {
        Path a = Files.write(root.resolve("a"), new byte[]{1, 2});
        Path copy = Files.copy(a, root.resolve("copy"));
        Path b = Files.write(root.resolve("b"), new byte[]{3, 4});
        for (String password : List.of("", "keyfile-audit")) {
            EncryptRequest encrypt = request();
            encrypt.setPassword(password);
            encrypt.setKeyfiles(List.of(b.toString()));
            Encryptor.encrypt(encrypt);
            VerifyRequest verify = new VerifyRequest();
            verify.setInputFile(encrypt.getOutputFile()); verify.setPassword(password);
            verify.setKeyfiles(List.of(a.toString(), copy.toString(), b.toString())); verify.setRsCodecs(new RsCodecs());
            assertTrue(Verifier.verify(verify));
            DecryptRequest decrypt = new DecryptRequest();
            decrypt.setInputFile(encrypt.getOutputFile()); decrypt.setOutputFile(root.resolve("restored").toString());
            decrypt.setPassword(password); decrypt.setKeyfiles(verify.getKeyfiles()); decrypt.setRsCodecs(new RsCodecs());
            Decryptor.decrypt(decrypt);
            assertArrayEquals(Files.readAllBytes(Path.of(encrypt.getInputFile())), Files.readAllBytes(Path.of(decrypt.getOutputFile())));
            Files.delete(Path.of(encrypt.getOutputFile())); Files.delete(Path.of(decrypt.getOutputFile()));
        }
    }
}
