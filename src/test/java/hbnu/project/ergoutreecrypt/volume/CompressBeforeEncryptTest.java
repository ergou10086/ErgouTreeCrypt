package hbnu.project.ergoutreecrypt.volume;

import hbnu.project.ergoutreecrypt.encoding.RsCodecs;
import hbnu.project.ergoutreecrypt.header.HeaderReader;
import hbnu.project.ergoutreecrypt.header.ReadResult;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 加密前压缩（Zstandard）往返测试。
 *
 * <p>覆盖：
 * <ul>
 *   <li>单文件 + 不同压缩档位（1 / 3 / 22）的逐字节往返；</li>
 *   <li>多文件合并 + 压缩的逐字节往返；</li>
 *   <li>header 版本升级到 v2.16 且 compressed 标志置位；</li>
 *   <li>压缩确实缩小高冗余数据（对比未压缩输出）。</li>
 * </ul>
 *
 * @author ErgouTree
 */
public final class CompressBeforeEncryptTest {

    private static RsCodecs rs;

    /**
     * 初始化共享 RS 编解码器。
     */
    @BeforeAll
    static void setUp() {
        rs = new RsCodecs();
    }

    /**
     * 单文件压缩往返，覆盖多个档位。
     */
    @Test
    void singleFileCompressRoundtrip(@TempDir Path tempDir) throws Exception {
        for (int level : new int[] {1, 3, 22}) {
            byte[] plaintext = compressibleData(512 * 1024);
            Path input = createFile(tempDir, "input_level" + level + ".bin", plaintext);
            Path encrypted = tempDir.resolve("out_level" + level + ".ergou");
            Path decrypted = tempDir.resolve("dec_level" + level + ".bin");

            EncryptRequest encReq = new EncryptRequest();
            encReq.setInputFile(input.toString());
            encReq.setOutputFile(encrypted.toString());
            encReq.setPassword("compress-pass");
            encReq.setCompress(true);
            encReq.setCompressionLevel(level);
            encReq.setRsCodecs(rs);
            Encryptor.encrypt(encReq);

            DecryptRequest decReq = new DecryptRequest();
            decReq.setInputFile(encrypted.toString());
            decReq.setOutputFile(decrypted.toString());
            decReq.setPassword("compress-pass");
            decReq.setRsCodecs(rs);
            Decryptor.decrypt(decReq);

            assertArrayEquals(plaintext, Files.readAllBytes(decrypted),
                    "level " + level + " roundtrip should be byte-identical");
        }
    }

    /**
     * 多文件合并 + 压缩往返：解密结果应为拼接后的原始字节。
     */
    @Test
    void multiFileCompressRoundtrip(@TempDir Path tempDir) throws Exception {
        byte[] data1 = compressibleData(128 * 1024);
        byte[] data2 = compressibleData(96 * 1024);
        byte[] expected = concat(data1, data2);

        Path f1 = createFile(tempDir, "a.bin", data1);
        Path f2 = createFile(tempDir, "b.bin", data2);
        Path encrypted = tempDir.resolve("multi.ergou");
        Path decrypted = tempDir.resolve("multi_dec.bin");

        EncryptRequest encReq = new EncryptRequest();
        encReq.setInputFiles(List.of(f1.toString(), f2.toString()));
        encReq.setOutputFile(encrypted.toString());
        encReq.setPassword("multi-compress");
        encReq.setCompress(true);
        encReq.setCompressionLevel(3);
        encReq.setRsCodecs(rs);
        Encryptor.encrypt(encReq);

        DecryptRequest decReq = new DecryptRequest();
        decReq.setInputFile(encrypted.toString());
        decReq.setOutputFile(decrypted.toString());
        decReq.setPassword("multi-compress");
        decReq.setRsCodecs(rs);
        Decryptor.decrypt(decReq);

        assertArrayEquals(expected, Files.readAllBytes(decrypted));
    }

    /**
     * 压缩文件 header 版本为 v2.16 且 compressed 标志置位。
     */
    @Test
    void compressedHeaderIsV216(@TempDir Path tempDir) throws Exception {
        byte[] plaintext = compressibleData(64 * 1024);
        Path input = createFile(tempDir, "input.bin", plaintext);
        Path encrypted = tempDir.resolve("out.ergou");

        EncryptRequest encReq = new EncryptRequest();
        encReq.setInputFile(input.toString());
        encReq.setOutputFile(encrypted.toString());
        encReq.setPassword("hdr-pass");
        encReq.setCompress(true);
        encReq.setRsCodecs(rs);
        Encryptor.encrypt(encReq);

        try (InputStream in = Files.newInputStream(encrypted)) {
            HeaderReader reader = new HeaderReader(in, rs);
            ReadResult result = reader.readHeader();
            assertEquals("v2.16", result.getHeader().getVersion());
            assertTrue(result.getHeader().isCompressed());
        }
    }

    /**
     * 压缩确实缩小高冗余数据：压缩输出的密文应小于未压缩输出。
     */
    @Test
    void compressionReducesSize(@TempDir Path tempDir) throws Exception {
        byte[] plaintext = compressibleData(1024 * 1024);
        Path input = createFile(tempDir, "input.bin", plaintext);

        Path plainEnc = tempDir.resolve("plain.ergou");
        Path compressedEnc = tempDir.resolve("compressed.ergou");

        EncryptRequest plainReq = new EncryptRequest();
        plainReq.setInputFile(input.toString());
        plainReq.setOutputFile(plainEnc.toString());
        plainReq.setPassword("size-pass");
        plainReq.setRsCodecs(rs);
        Encryptor.encrypt(plainReq);

        EncryptRequest compReq = new EncryptRequest();
        compReq.setInputFile(input.toString());
        compReq.setOutputFile(compressedEnc.toString());
        compReq.setPassword("size-pass");
        compReq.setCompress(true);
        compReq.setCompressionLevel(22);
        compReq.setRsCodecs(rs);
        Encryptor.encrypt(compReq);

        assertTrue(Files.size(compressedEnc) < Files.size(plainEnc),
                "compressed ciphertext should be smaller than uncompressed");
    }

    /**
     * 创建测试文件。
     */
    private static Path createFile(Path dir, String name, byte[] data) throws Exception {
        Path path = dir.resolve(name);
        Files.write(path, data);
        return path;
    }

    /**
     * 生成高冗余、易压缩的确定性数据。
     */
    private static byte[] compressibleData(int size) {
        byte[] data = new byte[size];
        for (int i = 0; i < size; i++) {
            data[i] = (byte) (i % 16);
        }
        return data;
    }

    /**
     * 拼接两个字节数组。
     */
    private static byte[] concat(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }
}
