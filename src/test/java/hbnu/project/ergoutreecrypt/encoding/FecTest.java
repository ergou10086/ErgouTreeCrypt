package hbnu.project.ergoutreecrypt.encoding;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

import org.junit.jupiter.api.Test;

/**
 * 验证 {@link Fec} 的编码、重建与 Berlekamp-Welch 纠错。
 *
 * <p>覆盖 infectious README 的经典用例（k=8,n=14）以及 Picocrypt 实际使用的各 RS 规格，
 * 重点验证"纠错"这一高风险路径的正确性。
 */
class FecTest {

    @Test
    void encodeProducesNSharesWithKDataPrefix() {
        Fec fec = Fec.newFec(8, 14);
        byte[] input = "hello, world! __".getBytes(StandardCharsets.US_ASCII); // 16 = 8*2
        List<Fec.Share> shares = fec.encodeAll(input);

        assertEquals(14, shares.size());
        // 前 k 个 share 是原始数据切片。
        int blockSize = input.length / 8;
        for (int i = 0; i < 8; i++) {
            byte[] expected = new byte[blockSize];
            System.arraycopy(input, i * blockSize, expected, 0, blockSize);
            assertArrayEquals(expected, shares.get(i).data, "data share " + i);
        }
    }

    @Test
    void rebuildFromAllShares() {
        Fec fec = Fec.newFec(8, 14);
        byte[] input = "hello, world! __".getBytes(StandardCharsets.US_ASCII);
        List<Fec.Share> shares = deepCopy(fec.encodeAll(input));

        byte[] decoded = fec.decode(shares);
        assertArrayEquals(input, decoded);
    }

    @Test
    void decodeRecoversFromMissingShares() {
        Fec fec = Fec.newFec(8, 14);
        byte[] input = "hello, world! __".getBytes(StandardCharsets.US_ASCII);
        List<Fec.Share> shares = deepCopy(fec.encodeAll(input));

        // 丢弃前两片（仅保留 12 片，仍 >= k=8）。
        List<Fec.Share> subset = new ArrayList<>(shares.subList(2, shares.size()));
        byte[] decoded = fec.decode(subset);
        assertArrayEquals(input, decoded);
    }

    @Test
    void decodeCorrectsCorruptedShare() {
        // infectious README 场景：丢两片 + 改一片，仍能恢复（Berlekamp-Welch）。
        Fec fec = Fec.newFec(8, 14);
        byte[] input = "hello, world! __".getBytes(StandardCharsets.US_ASCII);
        List<Fec.Share> shares = deepCopy(fec.encodeAll(input));

        List<Fec.Share> subset = new ArrayList<>(shares.subList(2, shares.size()));
        subset.get(2).data[1] = (byte) '!'; // 篡改一个字节

        byte[] decoded = fec.decode(subset);
        assertArrayEquals(input, decoded);
    }

    @Test
    void rs128RoundTripAndSingleByteErrorCorrection() {
        Fec fec = Fec.newFec(128, 136);
        byte[] input = new byte[128];
        Random rng = new Random(42);
        rng.nextBytes(input);

        List<Fec.Share> shares = deepCopy(fec.encodeAll(input));
        assertEquals(136, shares.size());

        // 注入 1 个字节错误（RS128 可纠正 (136-128)/2 = 4 个错误）。
        shares.get(10).data[0] ^= 0xFF;
        byte[] decoded = fec.decode(shares);
        assertArrayEquals(input, decoded);
    }

    @Test
    void rs128CorrectsUpToFourErrors() {
        Fec fec = Fec.newFec(128, 136);
        byte[] input = new byte[128];
        new Random(7).nextBytes(input);

        List<Fec.Share> shares = deepCopy(fec.encodeAll(input));
        // 4 个错误，正好是纠错上限。
        shares.get(3).data[0] ^= 0x01;
        shares.get(50).data[0] ^= 0x80;
        shares.get(99).data[0] ^= 0x55;
        shares.get(135).data[0] ^= 0xAA;

        byte[] decoded = fec.decode(shares);
        assertArrayEquals(input, decoded);
    }

    @Test
    void tooManyErrorsThrows() {
        Fec fec = Fec.newFec(128, 136);
        byte[] input = new byte[128];
        new Random(7).nextBytes(input);

        List<Fec.Share> shares = deepCopy(fec.encodeAll(input));
        // 5 个错误，超过纠错上限 4，应抛出。
        shares.get(3).data[0] ^= 0x01;
        shares.get(50).data[0] ^= 0x80;
        shares.get(99).data[0] ^= 0x55;
        shares.get(135).data[0] ^= 0xAA;
        shares.get(7).data[0] ^= 0x33;

        assertThrows(RuntimeException.class, () -> fec.decode(shares));
    }

    private static List<Fec.Share> deepCopy(List<Fec.Share> in) {
        List<Fec.Share> out = new ArrayList<>(in.size());
        for (Fec.Share s : in) {
            out.add(s.deepCopy());
        }
        return out;
    }
}
