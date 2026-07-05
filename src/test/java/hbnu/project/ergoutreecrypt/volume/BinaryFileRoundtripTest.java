package hbnu.project.ergoutreecrypt.volume;

import hbnu.project.ergoutreecrypt.crypto.CryptoConstants;
import hbnu.project.ergoutreecrypt.encoding.RsCodecs;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 针对二进制/压缩文件场景的往返测试，覆盖各种边界尺寸。
 *
 * <p>重点关注 RS 填充标记（padded flag）附近的尺寸，以及恰好整倍数的尺寸，
 * 这些是压缩文件（zip/7z 等）容易出现加解密失败的位置。
 *
 * @author ErgouTree
 */
public final class BinaryFileRoundtripTest {

    private static final int MIB = CryptoConstants.MIB;
    private static final int BLOCK = 128;

    private static RsCodecs rs;

    @BeforeAll
    static void setUp() {
        rs = new RsCodecs();
    }

    // ================================================================
    // Non-RS 场景：各种二进制尺寸
    // ================================================================

    /**
     * 小文件（< 1 KiB），普通模式。
     */
    @Test
    void testSmallBinaryNonRs(@TempDir Path tempDir) throws Exception {
        roundTrip(tempDir, 500, false, false);
    }

    /**
     * 恰好 1 MiB，普通模式。
     */
    @Test
    void testExactOneMiBNonRs(@TempDir Path tempDir) throws Exception {
        roundTrip(tempDir, MIB, false, false);
    }

    /**
     * 1 MiB + 500 字节，普通模式。
     */
    @Test
    void testOneMiBPlusSmallNonRs(@TempDir Path tempDir) throws Exception {
        roundTrip(tempDir, MIB + 500, false, false);
    }

    /**
     * 恰好 5 MiB，普通模式（多块 + 无余数）。
     */
    @Test
    void testExactFiveMiBNonRs(@TempDir Path tempDir) throws Exception {
        roundTrip(tempDir, 5 * MIB, false, false);
    }

    /**
     * 5 MiB + 7777 字节，普通模式。
     */
    @Test
    void testFiveMiBPlusNonRs(@TempDir Path tempDir) throws Exception {
        roundTrip(tempDir, 5 * MIB + 7777, false, false);
    }

    /**
     * 空文件，普通模式。
     */
    @Test
    void testEmptyNonRs(@TempDir Path tempDir) throws Exception {
        roundTrip(tempDir, 0, false, false);
    }

    // ================================================================
    // RS 场景：padded 边界尺寸
    // ================================================================

    /**
     * 恰好 1 MiB，RS 模式（padded=false 的整块路径）。
     */
    @Test
    void testExactOneMiBRs(@TempDir Path tempDir) throws Exception {
        roundTrip(tempDir, MIB, true, false);
    }

    /**
     * MIB - BLOCK - 1 = 1048447 字节，RS 模式（padded=false，末块需填充）。
     */
    @Test
    void testJustBelowPaddedThresholdRs(@TempDir Path tempDir) throws Exception {
        roundTrip(tempDir, MIB - BLOCK - 1, true, false);
    }

    /**
     * MIB - BLOCK = 1048448 字节，RS 模式（padded=true 的阈值）。
     */
    @Test
    void testAtPaddedThresholdRs(@TempDir Path tempDir) throws Exception {
        roundTrip(tempDir, MIB - BLOCK, true, false);
    }

    /**
     * MIB - 1 = 1048575 字节，RS 模式（padded=true 的最大余数）。
     */
    @Test
    void testAtPaddedMaxRs(@TempDir Path tempDir) throws Exception {
        roundTrip(tempDir, MIB - 1, true, false);
    }

    /**
     * 恰好 2 MiB，RS 模式（padded=false，多整块）。
     */
    @Test
    void testExactTwoMiBRs(@TempDir Path tempDir) throws Exception {
        roundTrip(tempDir, 2 * MIB, true, false);
    }

    /**
     * 2 MiB + (MIB - BLOCK) = 2 MiB + 1048448 字节，RS 模式（第二块触发 padded=true）。
     */
    @Test
    void testTwoMiBPlusPaddedRs(@TempDir Path tempDir) throws Exception {
        roundTrip(tempDir, 2 * MIB + (MIB - BLOCK), true, false);
    }

    /**
     * 2 MiB + 500 字节，RS 模式（第二块为部分块，padded=false）。
     */
    @Test
    void testTwoMiBPlusSmallRs(@TempDir Path tempDir) throws Exception {
        roundTrip(tempDir, 2 * MIB + 500, true, false);
    }

    /**
     * 128 字节（恰好一个 RS 块），RS 模式。
     * <p>由于文件 < 1 MiB，且 padded=false（128 < 1048448），末块会走部分块路径，
     * RS 编码时 ALWAYS 添加一个填充块。
     */
    @Test
    void testOneRsBlockRs(@TempDir Path tempDir) throws Exception {
        roundTrip(tempDir, BLOCK, true, false);
    }

    /**
     * 129 字节（一个 RS 块 + 1 字节），RS 模式。
     */
    @Test
    void testOneRsBlockPlusOneRs(@TempDir Path tempDir) throws Exception {
        roundTrip(tempDir, BLOCK + 1, true, false);
    }

    // ================================================================
    // 偏执模式 + RS 组合
    // ================================================================

    /**
     * 偏执 + RS 组合，200 KiB。
     */
    @Test
    void testParanoidRsSmall(@TempDir Path tempDir) throws Exception {
        roundTrip(tempDir, 200 * 1024, true, true);
    }

    /**
     * 偏执 + RS 组合，恰好 1 MiB。
     */
    @Test
    void testParanoidRsExactMiB(@TempDir Path tempDir) throws Exception {
        roundTrip(tempDir, MIB, true, true);
    }

    /**
     * 偏执 + RS 组合，padded 阈值。
     */
    @Test
    void testParanoidRsPaddedThreshold(@TempDir Path tempDir) throws Exception {
        roundTrip(tempDir, MIB - BLOCK, true, true);
    }

    /**
     * 偏执 + RS 组合，大文件 5 MiB + 12345。
     */
    @Test
    void testParanoidRsLarge(@TempDir Path tempDir) throws Exception {
        roundTrip(tempDir, 5 * MIB + 12345, true, true);
    }

    // ================================================================
    // 辅助方法
    // ================================================================

    /**
     * 生成与 zip/7z 等压缩文件类似的真实二进制数据（全范围 0x00-0xFF），
     * 往返加密解密后逐字节比对。
     *
     * @param tempDir  临时目录
     * @param size     明文大小（字节）
     * @param reedSolomon 是否启用 RS 纠错
     * @param paranoid    是否启用偏执模式
     */
    private static void roundTrip(Path tempDir, int size, boolean reedSolomon,
                                   boolean paranoid) throws Exception {
        // 生成覆盖全部 256 种字节值的伪随机二进制数据
        byte[] plaintext = generateBinaryData(size);

        Path input = tempDir.resolve("input.bin");
        Files.write(input, plaintext);

        Path encrypted = tempDir.resolve("output.ergou");
        Path decrypted = tempDir.resolve("decrypted.bin");

        // 加密
        EncryptRequest encReq = new EncryptRequest();
        encReq.setInputFile(input.toString());
        encReq.setOutputFile(encrypted.toString());
        encReq.setPassword("binary-test-pass");
        encReq.setReedSolomon(reedSolomon);
        encReq.setParanoid(paranoid);
        encReq.setRsCodecs(rs);
        Encryptor.encrypt(encReq);

        assertTrue(Files.exists(encrypted), "encrypted file should exist (size=" + size
                + " RS=" + reedSolomon + " paranoid=" + paranoid + ")");
        assertTrue(Files.size(encrypted) > 0, "encrypted file should not be empty");

        // 解密
        DecryptRequest decReq = new DecryptRequest();
        decReq.setInputFile(encrypted.toString());
        decReq.setOutputFile(decrypted.toString());
        decReq.setPassword("binary-test-pass");
        decReq.setRsCodecs(rs);
        Decryptor.decrypt(decReq);

        byte[] result = Files.readAllBytes(decrypted);
        if (!Arrays.equals(plaintext, result)) {
            int firstDiff = -1;
            int minLen = Math.min(plaintext.length, result.length);
            for (int i = 0; i < minLen; i++) {
                if (plaintext[i] != result[i]) {
                    firstDiff = i;
                    break;
                }
            }
            throw new AssertionError(
                    String.format(
                            "Roundtrip mismatch at size=%d RS=%s paranoid=%s: "
                                    + "expected.length=%d actual.length=%d firstDiff=%d",
                            size, reedSolomon, paranoid,
                            plaintext.length, result.length, firstDiff));
        }
    }

    /**
     * 生成覆盖全部 256 种字节值的二进制测试数据。
     */
    private static byte[] generateBinaryData(int size) {
        byte[] data = new byte[size];
        for (int i = 0; i < size; i++) {
            // 使用乘数 17（与 256 互质），保证遍历完整周期
            data[i] = (byte) ((i * 17 + 13) & 0xff);
        }
        return data;
    }
}
