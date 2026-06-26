package hbnu.project.ergoutreecrypt.encoding;

import java.util.ArrayList;
import java.util.List;

/**
 * Reed-Solomon 编解码封装，
 *
 * <p>以 {@code block_size == 1}（每个 share 仅 1 字节）的方式使用 FEC：输入 {@code k} 字节编码为 {@code n} 字节。因此编码回调 {@code res[number] = data[0]}。
 *
 * <p>仅对 RS128（total==136）有意义——跳过纠错直接取前 128 字节，MAC 校验失败时上层再以 {@code fastDecode=false} 重试纠错。
 *
 * @author ErgouTree
 */
public final class ReedSolomon {

    private ReedSolomon() {
    }

    /**
     * RS 编码：输入长度须等于 {@code fec.required()}，输出长度为 {@code fec.total()}。
     * 对应 {@code encoding.Encode}。
     */
    public static byte[] encode(Fec fec, byte[] data) {
        byte[] res = new byte[fec.total()];
        encodeInto(res, fec, data);
        return res;
    }

    /**
     * 无分配编码：直接写入 {@code dst}（长度须为 total）。对应 {@code encoding.EncodeInto}。
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

    /** 解码结果：解码数据 + 是否发生（无法纠正的）错误。 */
    public static final class DecodeResult {
        public final byte[] data;
        public final boolean corrupted;

        DecodeResult(byte[] data, boolean corrupted) {
            this.data = data;
            this.corrupted = corrupted;
        }
    }

    /**
     * RS 解码，对应 {@code encoding.Decode}。
     *
     * @param fec        与编码时一致的编解码器
     * @param data       编码数据（长度须等于 {@code fec.total()}）
     * @param fastDecode 仅 RS128 有效：true 时跳过纠错直接取前 128 字节
     * @return 解码结果；{@code corrupted=true} 表示 RS 无法纠正（但仍返回尽力恢复的数据）
     */
    public static DecodeResult decode(Fec fec, byte[] data, boolean fastDecode) {
        int total = fec.total();
        if (data.length != total) {
            throw new IllegalArgumentException(
                    "rs decode: input size " + data.length + " != total " + total);
        }

        // RS128 fast path：跳过纠错。
        if (total == 136 && fastDecode) {
            return new DecodeResult(slice(data, 128), false);
        }

        List<Fec.Share> shares = new ArrayList<>(total);
        for (int i = 0; i < total; i++) {
            shares.add(new Fec.Share(i, new byte[] { data[i] }));
        }

        try {
            byte[] res = fec.decode(shares);
            return new DecodeResult(res, false);
        } catch (RuntimeException e) {
            // 无法纠正：与 Go 一致地返回"强制取值"的数据并标记 corrupted。
            if (total == 136) {
                return new DecodeResult(slice(data, 128), true);
            }
            return new DecodeResult(slice(data, total / 3), true);
        }
    }

    private static byte[] slice(byte[] src, int len) {
        byte[] out = new byte[len];
        System.arraycopy(src, 0, out, 0, len);
        return out;
    }
}
