package hbnu.project.ergoutreecrypt.compress;

import com.github.luben.zstd.ZstdInputStream;
import com.github.luben.zstd.ZstdOutputStream;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Zstandard 压缩/解压工具，封装 zstd-jni 的流式 API。
 *
 * <p>Zstandard 支持 1–22 档位（数值越大压缩率越高、速度越慢），本类将档位限制在 {@link #MIN_LEVEL}–{@link #MAX_LEVEL} 区间，越界值自动收敛到边界。解压侧通过帧头自动识别原始大小，无需在调用方保存/传递档位或长度信息。
 *
 * <p>注意：zstd-jni 仅提供桌面端 native（无 Android ABI），故「加密前压缩」产生的文件在移动端无法解压；移动端解密侧在预检阶段会直接拒绝此类文件，本类实际仅桌面端调用压缩/解压。
 *
 * <p>提供字节数组与流式两套 API：字节数组用于内存内小载荷（隐写 payload），流式用于大文件（通用文件加密与隐写的文件级路径），内存占用恒定。
 *
 * @author ErgouTree
 */
public final class ZstdCompressor {

    /**
     * 最低压缩档位（最快、压缩率最低）。
     */
    public static final int MIN_LEVEL = 1;

    /**
     * 最高压缩档位（最慢、压缩率最高，超高级别需较多内存）。
     */
    public static final int MAX_LEVEL = 22;

    /**
     * 默认压缩档位（Zstandard 官方默认值）。
     */
    public static final int DEFAULT_LEVEL = 3;

    /**
     * 流式压缩/解压的分块缓冲大小（64 KiB）：兼顾吞吐与内存占用。
     */
    private static final int STREAM_CHUNK_BYTES = 64 * 1024;

    private ZstdCompressor() {
    }

    /**
     * 将档位收敛到 {@code [MIN_LEVEL, MAX_LEVEL]} 区间。
     *
     * @param level 请求的档位
     * @return 收敛后的档位
     */
    public static int clampLevel(int level) {
        if (level < MIN_LEVEL) {
            return MIN_LEVEL;
        }
        if (level > MAX_LEVEL) {
            return MAX_LEVEL;
        }
        return level;
    }

    /**
     * 使用指定档位压缩字节数组。
     *
     * @param data  待压缩的原始字节
     * @param level 压缩档位（越界自动收敛）
     * @return Zstandard 压缩后的字节
     */
    public static byte[] compress(byte[] data, int level) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (ZstdOutputStream zos = new ZstdOutputStream(baos, clampLevel(level))) {
            zos.write(data);
        } catch (IOException e) {
            throw new IllegalStateException("Zstd 压缩失败", e);
        }
        return baos.toByteArray();
    }

    /**
     * 解压 Zstandard 字节数组。
     *
     * @param data Zstandard 压缩字节
     * @return 解压后的原始字节
     */
    public static byte[] decompress(byte[] data) {
        try (ZstdInputStream zis = new ZstdInputStream(new ByteArrayInputStream(data));
             ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            byte[] buf = new byte[STREAM_CHUNK_BYTES];
            int n;
            while ((n = zis.read(buf)) != -1) {
                baos.write(buf, 0, n);
            }
            return baos.toByteArray();
        } catch (IOException e) {
            throw new IllegalStateException("Zstd 解压失败", e);
        }
    }

    /**
     * 流式压缩：从 {@code in} 读取原始数据，压缩后写入 {@code out}。
     *
     * <p>完成后关闭输入与输出两个流（输出流由 {@link ZstdOutputStream#close()}
     * 完成帧尾写入后关闭），调用方无需再关闭。
     *
     * @param in    原始数据输入流
     * @param out   压缩数据输出流
     * @param level 压缩档位（越界自动收敛）
     * @throws IOException 读写失败
     */
    public static void compress(InputStream in, OutputStream out, int level) throws IOException {
        try (ZstdOutputStream zos = new ZstdOutputStream(out, clampLevel(level))) {
            byte[] buf = new byte[STREAM_CHUNK_BYTES];
            int n;
            while ((n = in.read(buf)) != -1) {
                zos.write(buf, 0, n);
            }
        } finally {
            in.close();
        }
    }

    /**
     * 流式解压：从 {@code in} 读取 Zstandard 数据，解压后写入 {@code out}。
     *
     * <p>完成后关闭输入与输出两个流（输入流由 {@link ZstdInputStream#close()}
     * 关闭），调用方无需再关闭。
     *
     * @param in  Zstandard 数据输入流
     * @param out 原始数据输出流
     * @throws IOException 读写失败
     */
    public static void decompress(InputStream in, OutputStream out) throws IOException {
        try (ZstdInputStream zis = new ZstdInputStream(in)) {
            byte[] buf = new byte[STREAM_CHUNK_BYTES];
            int n;
            while ((n = zis.read(buf)) != -1) {
                out.write(buf, 0, n);
            }
        } finally {
            out.close();
        }
    }
}
