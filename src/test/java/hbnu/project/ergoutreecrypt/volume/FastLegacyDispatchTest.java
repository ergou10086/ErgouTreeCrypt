package hbnu.project.ergoutreecrypt.volume;

import static org.junit.jupiter.api.Assertions.*;

import hbnu.project.ergoutreecrypt.crypto.*;
import hbnu.project.ergoutreecrypt.encoding.RsCodecs;
import hbnu.project.ergoutreecrypt.header.*;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

/** FAST 探测加入公共入口后，旧版本的完整认证与解密仍必须由原流水线完成。 */
final class FastLegacyDispatchTest {
    /**
     * 生成明确版本的旧格式样本，不能用只读头测试代替完整载荷回归。
     *
     * @param directory 独占测试目录
     * @throws Exception 旧版本认证或解密失败
     */
    @Test
    void allFourLegacyVersionsUseOriginalReader(@TempDir Path directory) throws Exception {
        byte[] salt = RandomBytes.generate(16), hsalt = RandomBytes.generate(32);
        byte[] master = Argon2Kdf.deriveKey("旧格式密码".getBytes(StandardCharsets.UTF_8), salt, false);
        byte[] expected = "旧格式完整载荷🔐\n".repeat(100).getBytes(StandardCharsets.UTF_8);
        RsCodecs rs = new RsCodecs();
        try {
            for (String version : new String[] {"v1.33", "v2.14", "v2.15", "v2.16"}) {
                var header =
                        new VolumeHeader(
                                salt, hsalt, RandomBytes.generate(16), RandomBytes.generate(24));
                header.setVersion(version);
                if (header.isV215()) {
                    header.setArgon2MemoryKib(CryptoConstants.ARGON2_NORMAL_MEMORY_KIB);
                    header.setArgon2Passes(CryptoConstants.ARGON2_NORMAL_PASSES);
                    header.setArgon2Threads(CryptoConstants.ARGON2_NORMAL_THREADS);
                }
                var subkeys = new SubkeyReader(new HkdfStream(master, hsalt));
                header.setKeyHash(
                        header.isLegacyV1()
                                ? HeaderAuth.computeV1KeyHash(master)
                                : HeaderAuth.computeV2HeaderMac(
                                        subkeys.headerSubkey(), header, new byte[32]));
                byte[] payload = new byte[expected.length];
                Path file = directory.resolve(version + ".ergou");
                byte[] macKey = subkeys.macSubkey(), serpent = subkeys.serpentKey();
                try (var cipher =
                        new CipherSuite(
                                master,
                                header.getNonce(),
                                serpent,
                                header.getSerpentIV(),
                                MacFactory.create(macKey, false),
                                subkeys.stream(),
                                false)) {
                    cipher.encrypt(payload, expected, expected.length);
                    header.setAuthTag(cipher.sum());
                }
                try (var out = Files.newOutputStream(file)) {
                    new HeaderWriter(out, rs).writeHeader(header);
                    out.write(payload);
                }
                try (var channel = FileChannel.open(file, StandardOpenOption.WRITE)) {
                    HeaderWriter.writeAuthValues(
                            channel,
                            HeaderLayout.authValuesOffset(0, version),
                            header.getKeyHash(),
                            new byte[32],
                            header.getAuthTag(),
                            rs);
                }
                assertFalse(VolumeFormatProbe.isFast(file));
                var auth = new VerifyRequest();
                auth.setInputFile(file.toString());
                auth.setPassword("旧格式密码");
                auth.setRsCodecs(rs);
                assertTrue(Verifier.verify(auth));
                Path output = directory.resolve(version + ".plain");
                var request = new DecryptRequest();
                request.setInputFile(file.toString());
                request.setOutputFile(output.toString());
                request.setPassword("旧格式密码");
                request.setRsCodecs(rs);
                Decryptor.decrypt(request);
                assertArrayEquals(expected, Files.readAllBytes(output));
                SecureZero.zeroAll(macKey, serpent);
            }
        } finally {
            SecureZero.zero(master);
        }
    }
}
