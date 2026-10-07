package hbnu.project.ergoutreecrypt.volume;

import static org.junit.jupiter.api.Assertions.*;

import hbnu.project.ergoutreecrypt.header.FastHeaderReaderWriter;
import hbnu.project.ergoutreecrypt.header.VolumeFormatProbe;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Random;

/** 真实 Path 流程的分段边界、默认分派、独立认证及随机性测试。 */
final class FastVolumeRoundtripTest {
    /**
     * @param directory 独占测试目录
     * @throws Exception 边界或默认分派失败
     */
    @Test
    void everySegmentBoundaryUsesDefaultReader(@TempDir Path directory) throws Exception {
        int first = (1 << 20) - 56, following = (1 << 20) - 16;
        assertEquals(EncryptionMode.STANDARD, new EncryptRequest().getMode());
        for (int size :
                new int[] {
                    0,
                    1,
                    15,
                    16,
                    17,
                    first - 1,
                    first,
                    first + 1,
                    first + following - 1,
                    first + following,
                    first + following + 1,
                    3 * (1 << 20) + 17
                }) {
            Path input = directory.resolve("input-" + size),
                    cipher = directory.resolve("cipher-" + size),
                    restored = directory.resolve("plain-" + size);
            byte[] bytes = new byte[size];
            new Random(size).nextBytes(bytes);
            Files.write(input, bytes);
            Encryptor.encrypt(encryption(input, cipher, "e\u0301-极速🔐"));
            assertTrue(VolumeFormatProbe.isFast(cipher));
            assertEquals(FastHeaderReaderWriter.containerLength(size), Files.size(cipher));
            var before = entries(directory);
            assertTrue(Verifier.verify(verification(cipher, "é-极速🔐")));
            assertEquals(before, entries(directory), "认证不能创建明文或临时文件");
            Decryptor.decrypt(decryption(cipher, restored, "é-极速🔐"));
            assertEquals(-1, Files.mismatch(input, restored));
            assertFalse(
                    entries(directory).stream().anyMatch(name -> name.startsWith(".ergou-fast-")));
        }
    }

    /**
     * @param directory 独占测试目录
     * @throws Exception 加密或黄金向量读取失败
     */
    @Test
    void randomizedWritesAndIndependentGoldenReader(@TempDir Path directory) throws Exception {
        Path input = directory.resolve("input"),
                one = directory.resolve("one"),
                two = directory.resolve("two");
        Files.writeString(input, "相同明文🔐");
        Encryptor.encrypt(encryption(input, one, "密码"));
        Encryptor.encrypt(encryption(input, two, "密码"));
        assertNotEquals(-1, Files.mismatch(one, two));
        var properties = new java.util.Properties();
        try (var in = getClass().getResourceAsStream("/fast/v1/golden.properties")) {
            properties.load(in);
        }
        byte[] expected = java.util.HexFormat.of().parseHex(properties.getProperty("plaintext"));
        Path golden = directory.resolve("golden"), plain = directory.resolve("golden-plain");
        Files.write(golden, java.util.HexFormat.of().parseHex(properties.getProperty("container")));
        assertTrue(Verifier.verify(verification(golden, "é-极速🔐")));
        Decryptor.decrypt(decryption(golden, plain, "é-极速🔐"));
        assertArrayEquals(expected, Files.readAllBytes(plain));
    }

    /**
     * 构造只含基础字段的 FAST 请求。
     *
     * @param input 输入
     * @param output 输出
     * @param password 密码
     * @return 新请求
     */
    static EncryptRequest encryption(Path input, Path output, String password) {
        var request = new EncryptRequest();
        request.setMode(EncryptionMode.FAST);
        request.setInputFile(input.toString());
        request.setOutputFile(output.toString());
        request.setPassword(password);
        return request;
    }

    /**
     * 构造没有高级选项和模式字段的读取请求。
     *
     * @param input 密文
     * @param output 明文
     * @param password 密码
     * @return 新请求
     */
    static DecryptRequest decryption(Path input, Path output, String password) {
        var request = new DecryptRequest();
        request.setInputFile(input.toString());
        request.setOutputFile(output.toString());
        request.setPassword(password);
        return request;
    }

    /**
     * 构造独立完整认证请求。
     *
     * @param input 密文
     * @param password 密码
     * @return 新请求
     */
    static VerifyRequest verification(Path input, String password) {
        var request = new VerifyRequest();
        request.setInputFile(input.toString());
        request.setPassword(password);
        return request;
    }

    /**
     * 保存目录名称快照。
     *
     * @param directory 目录
     * @return 排序后的名称
     * @throws Exception 读取失败
     */
    static List<String> entries(Path directory) throws Exception {
        try (var files = Files.list(directory)) {
            return files.map(p -> p.getFileName().toString()).sorted().toList();
        }
    }
}
