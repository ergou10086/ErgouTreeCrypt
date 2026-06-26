package hbnu.project.ergoutreecrypt.encoding;

/**
 * PKCS#7 填充工具。
 *
 * <p>以 128 字节为块大小（与 RS128 数据块对齐）。若载荷不足 128 字节则填充至 128 字节边界；
 * 若已是 128 的整数倍，则补满一整块（128 个值为 0x80 的字节）。
 *
 * @author ErgouTree
 */
public final class Padding {

    /**
     * PKCS#7 填充的块大小（字节），与 RS128 数据块对齐。
     */
    public static final int BLOCK_SIZE = 128;

    private Padding() {
    }

    /**
     * 施加 PKCS#7 填充至 128 字节边界。
     *
     * <p>例：100 字节输入 → 128 字节输出，追加 28 个值为 0x1C 的填充字节。
     *
     * @param data 原始数据
     * @return 填充后的数据（长度为 128 的整数倍）
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
     * 移除 128 字节块的 PKCS#7 填充。
     *
     * <p>对损坏数据做了容错处理：若数据不足 128 字节、或填充值非法（>128 或 ==0），则原样返回。
     *
     * @param data 填充后的数据
     * @return 去填充后的原始数据
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
