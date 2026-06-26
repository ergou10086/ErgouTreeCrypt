package hbnu.project.ergoutreecrypt.encoding;

/**
 * PKCS#7 填充
 *
 * <p>块大小 128（RS128 数据块）。当最后一块载荷不足 128 字节时填充以便 RS128 编码；
 * 若已是 128 的整数倍，则补满一整块（128 个值为 0x80 的字节）。
 *
 * @author ErgouTree
 */
public final class Padding {

    /** RS128 数据块与 PKCS#7 填充的块大小。 */
    public static final int BLOCK_SIZE = 128;

    private Padding() {
    }

    /**
     * 施加 PKCS#7 填充至 128 字节边界。对应 {@code Pad}。
     * 例：100 字节 → 128 字节（追加 28 个值为 0x1C 的字节）。
     */
    public static byte[] pad(byte[] data) {
        int padLen = BLOCK_SIZE - data.length % BLOCK_SIZE;
        byte[] out = new byte[data.length + padLen];
        System.arraycopy(data, 0, out, 0, data.length);
        for (int i = data.length; i < out.length; i++) {
            out[i] = (byte) padLen;
        }
        return out;
    }

    /**
     * 移除 128 字节块的 PKCS#7 填充。对应 {@code Unpad}。
     *
     * <p>对损坏数据做了容错：若数据不足 128 字节、或填充值非法（&gt;128 或 ==0），原样返回。
     */
    public static byte[] unpad(byte[] data) {
        if (data.length < BLOCK_SIZE) {
            return data;
        }
        int padLen = data[BLOCK_SIZE - 1] & 0xff;
        if (padLen > BLOCK_SIZE || padLen == 0) {
            return data;
        }
        byte[] out = new byte[BLOCK_SIZE - padLen];
        System.arraycopy(data, 0, out, 0, out.length);
        return out;
    }
}
