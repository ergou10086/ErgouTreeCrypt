package hbnu.project.ergoutreecrypt.crypto;

import org.junit.jupiter.api.Test;

import java.security.Security;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

/**
 * 流密码与 MAC 的分块/一次性处理字节等价性测试。
 *
 * <p>隐写流式化依赖"BouncyCastle 有状态流密码逐块调用与一次性调用产出
 * 完全一致字节"这一性质，本测试将其锚定为回归保障。
 *
 * @author ErgouTree
 * @since 2026/8/14
 */
class CryptoStreamingEquivalenceTest {

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }
    }

    /**
     * 随机测试数据（约 2 MiB，跨多个密码内部缓冲块）。
     */
    private static byte[] randomData(final int size) {
        byte[] data = new byte[size];
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) ((i * 31 + 7) & 0xFF);
        }
        return data;
    }

    /**
     * XChaCha20：一次性处理与 1 字节 / 3 字节 / 1 MiB 分块处理的输出必须一致。
     */
    @Test
    void xChaCha20ChunkedEqualsOneShot() {
        byte[] key = randomData(32);
        byte[] nonce = randomData(24);
        byte[] input = randomData(2 * 1024 * 1024 + 123);

        byte[] oneShot = new byte[input.length];
        new XChaCha20(key, nonce).process(oneShot, input, input.length);

        assertChunkedEquals(key, nonce, input, oneShot, 1);
        assertChunkedEquals(key, nonce, input, oneShot, 3);
        assertChunkedEquals(key, nonce, input, oneShot, 1024 * 1024);
    }

    /**
     * 以指定分块大小处理输入，断言输出与一次性结果一致。
     *
     * <p>与生产代码的流式用法一致：每个分块使用独立的输入/输出缓冲
     * （{@code process} 无偏移参数，总是从数组 0 位置开始处理）。
     */
    private static void assertChunkedEquals(final byte[] key, final byte[] nonce,
                                            final byte[] input, final byte[] expected,
                                            final int chunkSize) {
        XChaCha20 cipher = new XChaCha20(key, nonce);
        byte[] out = new byte[input.length];
        byte[] chunkIn = new byte[chunkSize];
        byte[] chunkOut = new byte[chunkSize];
        int off = 0;
        while (off < input.length) {
            int len = Math.min(chunkSize, input.length - off);
            System.arraycopy(input, off, chunkIn, 0, len);
            cipher.process(chunkOut, chunkIn, len);
            System.arraycopy(chunkOut, 0, out, off, len);
            off += len;
        }
        assertArrayEquals(expected, out, "XChaCha20 分块 " + chunkSize + " 字节应与一次性结果一致");
    }

    /**
     * SerpentCTR：一次性处理与 1 字节 / 3 字节 / 1 MiB 分块处理的输出必须一致。
     */
    @Test
    void serpentCtrChunkedEqualsOneShot() {
        byte[] key = randomData(32);
        byte[] iv = randomData(16);
        byte[] input = randomData(2 * 1024 * 1024 + 321);

        byte[] oneShot = new byte[input.length];
        new SerpentCtr(key, iv).process(oneShot, input, input.length);

        for (int chunkSize : new int[]{1, 3, 1024 * 1024}) {
            SerpentCtr cipher = new SerpentCtr(key, iv);
            byte[] out = new byte[input.length];
            byte[] chunkIn = new byte[chunkSize];
            byte[] chunkOut = new byte[chunkSize];
            int off = 0;
            while (off < input.length) {
                int len = Math.min(chunkSize, input.length - off);
                System.arraycopy(input, off, chunkIn, 0, len);
                cipher.process(chunkOut, chunkIn, len);
                System.arraycopy(chunkOut, 0, out, off, len);
                off += len;
            }
            assertArrayEquals(oneShot, out,
                    "SerpentCtr 分块 " + chunkSize + " 字节应与一次性结果一致");
        }
    }

    /**
     * Mac（BLAKE2b 分支）：增量 update 与一次性 update 的 doFinal 结果必须一致。
     */
    @Test
    void macIncrementalEqualsOneShot() {
        byte[] key = randomData(32);
        byte[] input = randomData(3 * 1024 * 1024 + 17);

        Mac oneShot = MacFactory.create(key, false);
        oneShot.update(input, input.length);
        byte[] expected = oneShot.doFinal();
        oneShot.close();

        Mac incremental = MacFactory.create(key, false);
        int off = 0;
        while (off < input.length) {
            int len = Math.min(1024 * 1024, input.length - off);
            incremental.update(Arrays.copyOfRange(input, off, off + len), len);
            off += len;
        }
        byte[] actual = incremental.doFinal();
        incremental.close();

        assertArrayEquals(expected, actual, "增量 MAC 应与一次性 MAC 结果一致");
    }
}
