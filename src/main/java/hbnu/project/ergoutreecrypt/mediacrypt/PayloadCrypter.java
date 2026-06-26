package hbnu.project.ergoutreecrypt.mediacrypt;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.util.List;

import hbnu.project.ergoutreecrypt.crypto.CryptoConstants;
import hbnu.project.ergoutreecrypt.crypto.Mac;
import hbnu.project.ergoutreecrypt.crypto.MacFactory;
import hbnu.project.ergoutreecrypt.crypto.XChaCha20;

/**
 * 载荷流加密引擎：对一组 {@link ByteRange} 区间用单一连续 XChaCha20 keystream 做等长 XOR
 * 区间之间逻辑上拼成一条流（keystream 连续推进），与各格式无关。
 *
 * <p>这是音视频加密的"等长、可逆、对内容损伤小"特性的核心
 * 流密码 XOR 保证密文长度 == 明文长度，解密用同一 key/nonce 再 XOR 一次即逐字节还原。
 *
 * <p>由于 {@link XChaCha20} 是有状态流（底层 keystream 计数器随处理推进）
 * 本引擎对所有区间复用<b>同一个</b> {@code XChaCha20} 实例顺序处理，因此区间必须按 offset 升序、互不重叠。
 *
 * <p>可选地在 XOR 的同时对<b>明文</b>计算完整性 MAC（加密时 update 原文、解密时 update 还原后的明文），用于校验解密是否正确。注意 MAC 覆盖的是各区间拼接后的明文流。
 *
 * @author ErgouTree
 */
final class PayloadCrypter {

    /** 流式处理缓冲（1 MiB，与主线一致，降低系统调用与 GC）。 */
    private static final int BUFFER_SIZE = CryptoConstants.MIB;

    private PayloadCrypter() {
    }

    /**
     * 原地处理 {@code channel} 中给定区间的字节：读取 → XChaCha20 XOR → 写回原位置。
     *
     * <p>加密与解密为同一操作（流密码自反）。{@code macOverPlaintext} 非空时，对"明文流"累积 MAC：
     * <ul>
     *   <li>加密：明文 = 读取到的原始字节（XOR 前）；</li>
     *   <li>解密：明文 = XOR 还原后的字节。</li>
     * </ul>
     *
     * @param channel          可读写、可定位的文件通道
     * @param ranges           待处理区间（按 offset 升序、互不重叠）
     * @param encKey           32 字节 XChaCha20 密钥
     * @param nonce            24 字节 base nonce
     * @param encrypting       true=加密（MAC 取 XOR 前字节），false=解密（MAC 取 XOR 后字节）
     * @param macOverPlaintext 可选的明文 MAC 累积器；为 null 则不计算
     * @param progress         进度/取消回调，可为 null
     * @throws IOException                   读写错误
     * @throws MediaCryptCancelledException 用户取消
     */
    static void process(FileChannel channel, List<ByteRange> ranges, byte[] encKey, byte[] nonce,
                        boolean encrypting, Mac macOverPlaintext, MediaProgress progress)
            throws IOException, MediaCryptCancelledException {

        long total = 0;
        for (ByteRange r : ranges) {
            total += r.length();
        }

        XChaCha20 cipher = new XChaCha20(encKey, nonce);
        byte[] buf = new byte[BUFFER_SIZE];
        byte[] cipherOut = new byte[BUFFER_SIZE];
        ByteBuffer bb = ByteBuffer.allocate(BUFFER_SIZE);

        long processed = 0;
        if (progress != null) {
            progress.onProgress(0, total);
        }
        for (ByteRange range : ranges) {
            long remaining = range.length();
            long pos = range.offset();

            while (remaining > 0) {
                if (progress != null && progress.isCancelled()) {
                    throw new MediaCryptCancelledException();
                }
                int chunk = (int) Math.min(remaining, BUFFER_SIZE);

                // 读取 [pos, pos+chunk)
                readFully(channel, bb, buf, pos, chunk);

                // 加密：先用原文 update MAC，再 XOR。
                if (encrypting && macOverPlaintext != null) {
                    macOverPlaintext.update(buf, chunk);
                }

                cipher.process(cipherOut, buf, chunk);

                // 解密：XOR 后得到明文，再 update MAC。
                if (!encrypting && macOverPlaintext != null) {
                    macOverPlaintext.update(cipherOut, chunk);
                }

                writeFully(channel, cipherOut, pos, chunk);

                pos += chunk;
                remaining -= chunk;
                processed += chunk;
                if (progress != null) {
                    progress.onProgress(processed, total);
                }
            }
        }
    }

    /**
     * 仅计算给定区间拼接后明文的 MAC（不修改文件）。用于加密前预扫描原文以生成完整性校验值。
     */
    static byte[] computePlaintextMac(FileChannel channel, List<ByteRange> ranges, byte[] macKey,
                                      boolean paranoid) throws IOException {
        Mac mac = MacFactory.create(macKey, paranoid);
        try {
            byte[] buf = new byte[BUFFER_SIZE];
            ByteBuffer bb = ByteBuffer.allocate(BUFFER_SIZE);
            for (ByteRange range : ranges) {
                long remaining = range.length();
                long pos = range.offset();
                while (remaining > 0) {
                    int chunk = (int) Math.min(remaining, BUFFER_SIZE);
                    readFully(channel, bb, buf, pos, chunk);
                    mac.update(buf, chunk);
                    pos += chunk;
                    remaining -= chunk;
                }
            }
            return mac.doFinal();
        } finally {
            mac.close();
        }
    }

    private static void readFully(FileChannel channel, ByteBuffer bb, byte[] dst, long pos, int len)
            throws IOException {
        bb.clear();
        bb.limit(len);
        int read = 0;
        while (read < len) {
            int n = channel.read(bb, pos + read);
            if (n < 0) {
                throw new IOException("意外的文件结束：期望读取 " + len + " 字节，位置 " + pos);
            }
            read += n;
        }
        bb.flip();
        bb.get(dst, 0, len);
    }

    private static void writeFully(FileChannel channel, byte[] src, long pos, int len)
            throws IOException {
        ByteBuffer out = ByteBuffer.wrap(src, 0, len);
        int written = 0;
        while (written < len) {
            int n = channel.write(out, pos + written);
            written += n;
        }
    }
}
