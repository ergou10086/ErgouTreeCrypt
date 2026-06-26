package hbnu.project.ergoutreecrypt.encoding;

import java.util.ArrayList;
import java.util.List;

/**
 * Reed-Solomon 编解码封装。
 *
 * <p>以逐字节方式使用 FEC：输入 k 字节编码为 n 字节（每个 Share 仅包含 1 字节）。
 * 对于 RS128（total==136）提供快速路径——跳过纠错直接取前 128 字节；
 * MAC 校验失败时上层再以 {@code fastDecode=false} 重试纠错。
 *
 * @author ErgouTree
 */
public final class ReedSolomon {

    private ReedSolomon() {
    }

    /**
     * RS 编码：将 data 编码为 fec.total() 字节。
     *
     * @param fec  FEC 编解码器
     * @param data 原始数据（长度须等于 fec.required()）
     * @return 编码后的数据（长度等于 fec.total()）
     * @throws IllegalArgumentException 若输入长度不匹配
     */
    public static byte[] encode(Fec fec, byte[] data) {
        byte[] res = new byte[fec.total()];
        encodeInto(res, fec, data);
        return res;
    }

    /**
     * 无分配编码：直接写入 dst（长度须为 total）。
     *
     * @param dst  输出缓冲区（长度须等于 fec.total()）
     * @param fec  FEC 编解码器
     * @param data 原始数据（长度须等于 fec.required()）
     * @throws IllegalArgumentException 若长度不匹配
     */
    public static void encodeInto(byte[] dst, Fec fec, byte[] data) {
        if (data.length != fec.required()) {
            throw new IllegalArgumentException(
                    "rs encode: input size " + data.length + " != required " + fec.required());
        }
        if (dst.length != fec.total()) {
            throw new IllegalArgumentException(
                    "rs encode: dst size " + dst.length + " != total " + fec.total());
        }
        fec.encode(data, share -> dst[share.number] = share.data[0]);
    }

    /**
     * RS 解码结果：包含解码数据及是否发生无法纠正的错误的标志。
     */
    public static final class DecodeResult {

        /**
         * 解码后的数据。
         */
        public final byte[] data;

        /**
         * 若 RS 无法纠正但仍返回尽力恢复的数据则为 true。
         */
        public final boolean corrupted;

        /**
         * @param data      解码后的数据
         * @param corrupted 是否发生无法纠正的错误
         */
        DecodeResult(byte[] data, boolean corrupted) {
            this.data = data;
            this.corrupted = corrupted;
        }
    }

    /**
     * RS 解码。
     *
     * @param fec        与编码时一致的 FEC 编解码器
     * @param data       编码数据（长度须等于 fec.total()）
     * @param fastDecode 仅 RS128 有效：true 时跳过纠错直接取前 128 字节
     * @return 解码结果；若 {@code corrupted=true} 表示 RS 无法纠正
     * @throws IllegalArgumentException 若输入长度不匹配
     */
    public static DecodeResult decode(Fec fec, byte[] data, boolean fastDecode) {
        int total = fec.total();
        if (data.length != total) {
            throw new IllegalArgumentException(
                    "rs decode: input size " + data.length + " != total " + total);
        }

        // RS128 快速路径：跳过纠错，直接取前 128 字节
        if (total == 136 && fastDecode) {
            return new DecodeResult(slice(data, 128), false);
        }

        // 将每字节封装为 Share 后调用 FEC 解码
        List<Fec.Share> shares = new ArrayList<>(total);
        for (int i = 0; i < total; i++) {
            shares.add(new Fec.Share(i, new byte[] { data[i] }));
        }

        try {
            byte[] res = fec.decode(shares);
            return new DecodeResult(res, false);
        } catch (RuntimeException e) {
            // 无法纠正：返回尽力恢复的数据并标记 corrupted
            if (total == 136) {
                return new DecodeResult(slice(data, 128), true);
            }
            return new DecodeResult(slice(data, total / 3), true);
        }
    }

    /**
     * 从 src 复制前 len 字节到新数组。
     */
    private static byte[] slice(byte[] src, int len) {
        byte[] out = new byte[len];
        System.arraycopy(src, 0, out, 0, len);
        return out;
    }
}
