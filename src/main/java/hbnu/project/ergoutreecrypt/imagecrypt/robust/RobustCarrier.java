package hbnu.project.ergoutreecrypt.imagecrypt.robust;

import hbnu.project.ergoutreecrypt.encoding.Fec;
import hbnu.project.ergoutreecrypt.encoding.ReedSolomon;
import hbnu.project.ergoutreecrypt.exception.ErrorKind;
import hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptException;
import hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptFrame;
import hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptProtocol;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.file.Path;
import java.util.Arrays;

/**
 * 抗图片重编码载体的前向纠错与灰度符号编解码器。
 *
 * <p>逻辑帧按 128 字节分块，经 RS(192,128) 增加 64 字节校验。每 16 个码字按列交织，
 * 再把编码位流按 3 bit 分组，以 8 阶灰度表示。灰度只承载亮度信息，避免 JPEG
 * 4:2:0 色度抽样破坏数据；交织则把局部污损分散到多个 Reed-Solomon 码字。
 *
 * @author ErgouTree
 * @since 2026/9/17
 */
public final class RobustCarrier {

    /** 单个 RS 码字的数据字节数。 */
    public static final int DATA_BYTES = 128;

    /** 单个 RS 码字的编码字节数。 */
    public static final int CODE_BYTES = 192;

    /** 一个交织组包含的码字数。 */
    public static final int INTERLEAVE = 16;

    /** 一个交织组承载的逻辑字节数。 */
    public static final int GROUP_DATA_BYTES = DATA_BYTES * INTERLEAVE;

    /** 一个交织组占用的灰度像素数。 */
    public static final int GROUP_PIXELS = CODE_BYTES * INTERLEAVE * 8 / 3;

    /** 为避免常见聊天软件缩放而采用的最大画布边长。 */
    public static final int MAX_CANVAS_SIDE = 1920;

    /** 最大可承载的逻辑帧长度。 */
    public static final long MAX_LOGICAL_BYTES =
            (long) (MAX_CANVAS_SIDE * MAX_CANVAS_SIDE / GROUP_PIXELS) * GROUP_DATA_BYTES;

    /** RS(192,128) 编解码器。 */
    private static final Fec FEC = Fec.newFec(DATA_BYTES, CODE_BYTES);

    /** 桌面图像解码桥的类名。 */
    private static final String DESKTOP_DECODER =
            "hbnu.project.ergoutreecrypt.imagecrypt.robust.DesktopRobustImageDecoder";

    /** 工具类不允许实例化。 */
    private RobustCarrier() {
    }

    /**
     * 根据逻辑帧长度选择不超过 1920×1920 的 JPEG 友好画布。
     *
     * @param logicalLength 逻辑帧字节数
     * @return 宽、高二元数组；两边均按 16 像素对齐
     * @throws ImageCryptException 载荷超过纠错载体上限
     */
    public static int[] chooseCanvas(final long logicalLength) throws ImageCryptException {
        if (logicalLength <= 0 || logicalLength > MAX_LOGICAL_BYTES) {
            throw new ImageCryptException(ErrorKind.CAPACITY_INSUFFICIENT,
                    "抗重编码载体最多承载 " + MAX_LOGICAL_BYTES + " 字节，实际需要 "
                            + logicalLength + " 字节");
        }
        long groups = groupsFor(logicalLength);
        long pixels = groups * GROUP_PIXELS;
        int width = align16((int) Math.ceil(Math.sqrt((double) pixels)));
        if (width > MAX_CANVAS_SIDE) {
            width = MAX_CANVAS_SIDE;
        }
        int height = align16((int) ((pixels + width - 1L) / width));
        if (height > MAX_CANVAS_SIDE) {
            throw new ImageCryptException(ErrorKind.CAPACITY_INSUFFICIENT,
                    "抗重编码载体画布超过 " + MAX_CANVAS_SIDE + "×" + MAX_CANVAS_SIDE);
        }
        return new int[]{width, height};
    }

    /**
     * 把逻辑帧编码为交织后的 RS 字节流。
     *
     * <p>返回流的每个字节仍需由 PNG writer 拆成两个 16 阶灰度像素。
     *
     * @param logical       逻辑帧输入；生命周期由调用方管理
     * @param logicalLength 逻辑帧精确长度
     * @return 编码字节输入流
     */
    public static InputStream encodingStream(final InputStream logical,
                                             final long logicalLength) {
        return new EncodingInputStream(logical, logicalLength);
    }

    /**
     * 从 PNG 或 JPEG 纠错载体读取外层协议头。
     *
     * @param input 载体路径
     * @return 已纠错的 EGTC-IMG 外层头
     * @throws ImageCryptException 不是纠错载体或头部无法纠正
     * @throws IOException 图像读取失败
     */
    public static ImageCryptFrame peekFrame(final Path input)
            throws ImageCryptException, IOException {
        RobustRaster raster = decodeRaster(input);
        byte[] firstGroup = decodeGroup(raster, 0).data();
        if (firstGroup.length < ImageCryptProtocol.OUTER_HEADER_LENGTH) {
            throw invalid("纠错载体首组不足以容纳协议头");
        }
        ImageCryptFrame frame = ImageCryptFrame.fromBytes(Arrays.copyOf(firstGroup,
                ImageCryptProtocol.OUTER_HEADER_LENGTH));
        validateCanvas(frame, raster);
        return frame;
    }

    /**
     * 解码完整纠错载体并把逻辑帧写入接收器。
     *
     * @param input 载体路径
     * @param output 逻辑帧接收器；生命周期由调用方管理
     * @return true 表示至少一个 RS 码字超过纠错能力并使用了系统码尽力恢复
     * @throws ImageCryptException 结构或长度非法
     * @throws IOException 图像读取或接收器写入失败
     */
    public static boolean readFrame(final Path input, final OutputStream output)
            throws ImageCryptException, IOException {
        RobustRaster raster = decodeRaster(input);
        GroupResult first = decodeGroup(raster, 0);
        ImageCryptFrame frame = ImageCryptFrame.fromBytes(Arrays.copyOf(first.data(),
                ImageCryptProtocol.OUTER_HEADER_LENGTH));
        validateCanvas(frame, raster);
        long logicalLength;
        try {
            logicalLength = Math.addExact((long) ImageCryptProtocol.OUTER_HEADER_LENGTH,
                    frame.ciphertextLength());
            logicalLength = Math.addExact(logicalLength,
                    (long) ImageCryptProtocol.AUTH_TAG_LENGTH);
        } catch (ArithmeticException e) {
            throw new ImageCryptException(ErrorKind.INVALID_HEADER, "纠错载体帧长度溢出", e);
        }
        long groups = groupsFor(logicalLength);
        if (groups * GROUP_PIXELS > raster.pixelCount()) {
            throw invalid("纠错载体像素不足，图片可能被裁剪或缩放");
        }

        long remaining = logicalLength;
        boolean corrupted = false;
        for (long group = 0; group < groups; group++) {
            GroupResult result = group == 0 ? first : decodeGroup(raster, group);
            int count = (int) Math.min((long) result.data().length, remaining);
            output.write(result.data(), 0, count);
            remaining -= count;
            corrupted |= result.corrupted();
        }
        if (remaining != 0) {
            throw invalid("纠错载体未能恢复完整逻辑帧");
        }
        return corrupted;
    }

    /**
     * 返回指定逻辑长度需要的完整交织组数。
     *
     * @param logicalLength 逻辑帧长度
     * @return 向上取整后的组数
     */
    public static long groupsFor(final long logicalLength) {
        return (logicalLength + GROUP_DATA_BYTES - 1L) / GROUP_DATA_BYTES;
    }

    /**
     * 将数值向上对齐到 16 的整数倍。
     *
     * @param value 正整数
     * @return 对齐后的值
     */
    private static int align16(final int value) {
        return (value + 15) & ~15;
    }

    /**
     * 通过桌面桥把 PNG 或 JPEG 解码为亮度平面。
     *
     * @param input 图片路径
     * @return 亮度栅格
     * @throws ImageCryptException 当前平台没有像素解码桥或图片不可解码
     * @throws IOException 底层读取失败
     */
    private static RobustRaster decodeRaster(final Path input)
            throws ImageCryptException, IOException {
        try {
            Class<?> type = Class.forName(DESKTOP_DECODER);
            Method method = type.getMethod("decode", Path.class);
            return (RobustRaster) method.invoke(null, input);
        } catch (ClassNotFoundException | NoSuchMethodException | IllegalAccessException e) {
            throw new ImageCryptException(ErrorKind.UNSUPPORTED_FORMAT,
                    "当前平台尚未提供抗重编码 PNG/JPEG 像素解码桥", e);
        } catch (InvocationTargetException e) {
            Throwable cause = e.getCause();
            if (cause instanceof ImageCryptException imageCrypt) {
                throw imageCrypt;
            }
            if (cause instanceof IOException io) {
                throw io;
            }
            throw new ImageCryptException(ErrorKind.UNSUPPORTED_FORMAT,
                    "无法解码抗重编码图片载体", cause);
        }
    }

    /**
     * 解码一个完整交织组。
     *
     * @param raster 亮度栅格
     * @param groupIndex 组序号
     * @return 2048 字节逻辑数据及超限错误标志
     * @throws ImageCryptException 像素不足
     */
    private static GroupResult decodeGroup(final RobustRaster raster, final long groupIndex)
            throws ImageCryptException {
        long firstPixel = groupIndex * GROUP_PIXELS;
        if (firstPixel < 0 || firstPixel + GROUP_PIXELS > raster.pixelCount()) {
            throw invalid("纠错载体缺少第 " + groupIndex + " 个交织组");
        }
        byte[] encoded = new byte[CODE_BYTES * INTERLEAVE];
        long pixel = firstPixel;
        int bitBuffer = 0;
        int bitCount = 0;
        int encodedCursor = 0;
        while (encodedCursor < encoded.length) {
            int symbol = raster.luminanceAt(pixel++) >>> 5;
            bitBuffer = (bitBuffer << 3) | symbol;
            bitCount += 3;
            if (bitCount >= 8) {
                bitCount -= 8;
                encoded[encodedCursor++] = (byte) (bitBuffer >>> bitCount);
                bitBuffer = bitCount == 0 ? 0 : bitBuffer & ((1 << bitCount) - 1);
            }
        }
        byte[][] codewords = new byte[INTERLEAVE][CODE_BYTES];
        encodedCursor = 0;
        for (int column = 0; column < CODE_BYTES; column++) {
            for (int block = 0; block < INTERLEAVE; block++) {
                codewords[block][column] = encoded[encodedCursor++];
            }
        }

        byte[] decoded = new byte[GROUP_DATA_BYTES];
        boolean corrupted = false;
        for (int block = 0; block < INTERLEAVE; block++) {
            ReedSolomon.DecodeResult result = ReedSolomon.decode(FEC, codewords[block], false);
            System.arraycopy(result.data, 0, decoded, block * DATA_BYTES, DATA_BYTES);
            corrupted |= result.corrupted;
        }
        return new GroupResult(decoded, corrupted);
    }

    /**
     * 校验协议头画布与实际解码图片一致。
     *
     * @param frame 协议头
     * @param raster 实际图片
     * @throws ImageCryptException 尺寸不一致
     */
    private static void validateCanvas(final ImageCryptFrame frame, final RobustRaster raster)
            throws ImageCryptException {
        if (frame.canvasWidth() != raster.width() || frame.canvasHeight() != raster.height()) {
            throw invalid("纠错载体尺寸已改变，期望 " + frame.canvasWidth() + "×"
                    + frame.canvasHeight() + "，实际 " + raster.width() + "×" + raster.height());
        }
    }

    /**
     * 构造统一的载体结构异常。
     *
     * @param message 错误说明
     * @return 图片加密异常
     */
    private static ImageCryptException invalid(final String message) {
        return new ImageCryptException(ErrorKind.NOT_IMAGE_CRYPT, message);
    }

    /**
     * 单个交织组的解码结果。
     *
     * @param data 逻辑数据
     * @param corrupted 是否存在超过 RS 能力的码字
     */
    private record GroupResult(byte[] data, boolean corrupted) {
    }

    /**
     * 把逻辑帧按组编码并交织的流式输入。
     *
     * @author ErgouTree
     * @since 2026/9/17
     */
    private static final class EncodingInputStream extends InputStream {

        /** 逻辑输入。 */
        private final InputStream logical;

        /** 尚未读取的逻辑字节数。 */
        private long remaining;

        /** 当前交织组。 */
        private final byte[] encoded = new byte[CODE_BYTES * INTERLEAVE];

        /** 当前交织组读取位置。 */
        private int cursor = encoded.length;

        /** 是否已验证逻辑输入末尾。 */
        private boolean finished;

        /**
         * 创建编码流。
         *
         * @param logical 逻辑输入
         * @param logicalLength 精确长度
         */
        private EncodingInputStream(final InputStream logical, final long logicalLength) {
            if (logicalLength <= 0) {
                throw new IllegalArgumentException("逻辑帧长度必须为正");
            }
            this.logical = logical;
            this.remaining = logicalLength;
        }

        /**
         * 读取一个交织编码字节。
         *
         * @return 编码字节；结束时为 -1
         * @throws IOException 读取失败或逻辑长度不一致
         */
        @Override
        public int read() throws IOException {
            if (cursor == encoded.length && !fillGroup()) {
                return -1;
            }
            return encoded[cursor++] & 0xff;
        }

        /**
         * 生成下一个交织组。
         *
         * @return true 表示生成成功，false 表示全部结束
         * @throws IOException 输入长度不一致或读取失败
         */
        private boolean fillGroup() throws IOException {
            if (remaining == 0) {
                if (!finished) {
                    finished = true;
                    if (logical.read() >= 0) {
                        throw new IOException("逻辑帧包含超出声明长度的额外字节");
                    }
                }
                return false;
            }
            byte[][] codewords = new byte[INTERLEAVE][];
            for (int block = 0; block < INTERLEAVE; block++) {
                byte[] data = new byte[DATA_BYTES];
                int wanted = (int) Math.min((long) DATA_BYTES, remaining);
                readFully(data, wanted);
                remaining -= wanted;
                codewords[block] = ReedSolomon.encode(FEC, data);
            }
            int output = 0;
            for (int column = 0; column < CODE_BYTES; column++) {
                for (int block = 0; block < INTERLEAVE; block++) {
                    encoded[output++] = codewords[block][column];
                }
            }
            cursor = 0;
            return true;
        }

        /**
         * 从逻辑输入读满目标前缀。
         *
         * @param target 目标数组
         * @param length 需要读取的字节数
         * @throws IOException 输入提前结束
         */
        private void readFully(final byte[] target, final int length) throws IOException {
            int offset = 0;
            while (offset < length) {
                int count = logical.read(target, offset, length - offset);
                if (count < 0) {
                    throw new IOException("逻辑帧短于声明长度");
                }
                if (count > 0) {
                    offset += count;
                }
            }
        }
    }
}
