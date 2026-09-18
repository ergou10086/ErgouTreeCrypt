package hbnu.project.ergoutreecrypt.imagecrypt.robust;

import hbnu.project.ergoutreecrypt.encoding.Fec;
import hbnu.project.ergoutreecrypt.encoding.ReedSolomon;
import hbnu.project.ergoutreecrypt.exception.ErrorKind;
import hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptException;
import hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptFrame;
import hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptProtocol;
import hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptRobustness;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.EnumMap;
import java.util.Map;

/**
 * 抗图片重编码载体的分级前向纠错与灰度符号编解码器。
 *
 * <p>载体采用“灰度调制或像素块重复 + Reed-Solomon + 交织”的串接结构。均衡档保持
 * RS(192,128) 与 8 级灰度，以兼容已有产物；增强档和极强档使用 RS(192,96)，并依次
 * 降为 4 级与 2 级灰度。交织会把连续的像素污染分散到多个码字，极强档还通过 2×2
 * 重复块和归一化采样抵抗更强的压缩以及轻微等比例缩放。
 *
 * @author ErgouTree
 * @since 2026/9/17
 */
public final class RobustCarrier {

    /** 兼容均衡档单个 RS 码字的数据字节数。 */
    public static final int DATA_BYTES = ImageCryptRobustness.BALANCED.dataBytes();

    /** 兼容均衡档单个 RS 码字的编码字节数。 */
    public static final int CODE_BYTES = ImageCryptRobustness.BALANCED.codeBytes();

    /** 兼容均衡档一个交织组包含的码字数。 */
    public static final int INTERLEAVE = ImageCryptRobustness.BALANCED.interleave();

    /** 兼容均衡档一个交织组承载的逻辑字节数。 */
    public static final int GROUP_DATA_BYTES = DATA_BYTES * INTERLEAVE;

    /** 兼容均衡档一个交织组占用的灰度像素数。 */
    public static final int GROUP_PIXELS = CODE_BYTES * INTERLEAVE * 8
            / ImageCryptRobustness.BALANCED.bitsPerSymbol();

    /** 为避免常见聊天软件缩放而采用的最大画布边长。 */
    public static final int MAX_CANVAS_SIDE = 1920;

    /** 兼容均衡档最大可承载的逻辑帧长度。 */
    public static final long MAX_LOGICAL_BYTES = maximumLogicalBytes(
            ImageCryptRobustness.BALANCED);

    /** 自动探测时按兼容性和计算成本排列的强度顺序。 */
    private static final ImageCryptRobustness[] DECODING_PROFILES = {
            ImageCryptRobustness.BALANCED,
            ImageCryptRobustness.STRONG,
            ImageCryptRobustness.EXTREME
    };

    /** 每个抗干扰档位对应的 Reed-Solomon 编解码器。 */
    private static final Map<ImageCryptRobustness, Fec> FEC_BY_PROFILE = createFecProfiles();

    /** 桌面图像解码桥的类名。 */
    private static final String DESKTOP_DECODER =
            "hbnu.project.ergoutreecrypt.imagecrypt.robust.DesktopRobustImageDecoder";

    /** 工具类不允许实例化。 */
    private RobustCarrier() {
    }

    /**
     * 根据均衡档逻辑帧长度选择画布。
     *
     * @param logicalLength 逻辑帧字节数
     * @return 宽、高二元数组
     * @throws ImageCryptException 载荷超过均衡档上限
     */
    public static int[] chooseCanvas(final long logicalLength) throws ImageCryptException {
        return chooseCanvas(logicalLength, ImageCryptRobustness.BALANCED);
    }

    /**
     * 根据逻辑帧长度和抗干扰强度选择画布。
     *
     * <p>极强档固定使用 1920×1920 画布，以便接收端在图片被等比例缩放后仍能映射回统一
     * 的符号网格；其余档位选择不超过该尺寸的近似方形画布。
     *
     * @param logicalLength 逻辑帧字节数
     * @param profile 抗干扰强度
     * @return 宽、高二元数组；两边均按 16 像素对齐
     * @throws ImageCryptException 载荷超过所选档位上限
     */
    public static int[] chooseCanvas(final long logicalLength,
                                     final ImageCryptRobustness profile)
            throws ImageCryptException {
        requireProfile(profile);
        long maximum = maximumLogicalBytes(profile);
        if (logicalLength <= 0 || logicalLength > maximum) {
            throw new ImageCryptException(ErrorKind.CAPACITY_INSUFFICIENT,
                    profile + " 纠错载体最多承载 " + maximum + " 字节，实际需要 "
                            + logicalLength + " 字节");
        }
        if (profile == ImageCryptRobustness.EXTREME) {
            return new int[]{MAX_CANVAS_SIDE, MAX_CANVAS_SIDE};
        }
        long modules = groupsFor(logicalLength, profile) * symbolsPerGroup(profile);
        int widthModules = align16((int) Math.ceil(Math.sqrt((double) modules)));
        int maximumModules = MAX_CANVAS_SIDE / profile.moduleSize();
        if (widthModules > maximumModules) {
            widthModules = maximumModules;
        }
        int heightModules = align16((int) ((modules + widthModules - 1L) / widthModules));
        if (heightModules > maximumModules) {
            throw new ImageCryptException(ErrorKind.CAPACITY_INSUFFICIENT,
                    profile + " 纠错载体画布超过 " + MAX_CANVAS_SIDE + "×"
                            + MAX_CANVAS_SIDE);
        }
        return new int[]{widthModules * profile.moduleSize(),
                heightModules * profile.moduleSize()};
    }

    /**
     * 把逻辑帧按均衡档编码为交织后的 Reed-Solomon 字节流。
     *
     * @param logical 逻辑帧输入；生命周期由调用方管理
     * @param logicalLength 逻辑帧精确长度
     * @return 编码字节输入流
     */
    public static InputStream encodingStream(final InputStream logical,
                                             final long logicalLength) {
        return encodingStream(logical, logicalLength, ImageCryptRobustness.BALANCED);
    }

    /**
     * 把逻辑帧按指定强度编码为交织后的 Reed-Solomon 字节流。
     *
     * @param logical 逻辑帧输入；生命周期由调用方管理
     * @param logicalLength 逻辑帧精确长度
     * @param profile 抗干扰强度
     * @return 编码字节输入流
     */
    public static InputStream encodingStream(final InputStream logical,
                                             final long logicalLength,
                                             final ImageCryptRobustness profile) {
        requireProfile(profile);
        return new EncodingInputStream(logical, logicalLength, profile);
    }

    /**
     * 从 PNG 或 JPEG 纠错载体自动识别强度并读取外层协议头。
     *
     * @param input 载体路径
     * @return 已纠错的 EGTC-IMG 外层头
     * @throws ImageCryptException 不是支持的纠错载体或头部无法纠正
     * @throws IOException 图片读取失败
     */
    public static ImageCryptFrame peekFrame(final Path input)
            throws ImageCryptException, IOException {
        return detectCarrier(input).frame();
    }

    /**
     * 自动识别强度、解码完整纠错载体并把逻辑帧写入接收器。
     *
     * @param input 载体路径
     * @param output 逻辑帧接收器；生命周期由调用方管理
     * @return true 表示至少一个 RS 码字超出纠错能力并使用了系统码尽力恢复
     * @throws ImageCryptException 结构或长度非法
     * @throws IOException 图片读取或接收器写入失败
     */
    public static boolean readFrame(final Path input, final OutputStream output)
            throws ImageCryptException, IOException {
        DecodedCarrier carrier = detectCarrier(input);
        RobustRaster raster = carrier.raster();
        ImageCryptRobustness profile = carrier.profile();
        GroupResult first = carrier.firstGroup();
        ImageCryptFrame frame = carrier.frame();
        long logicalLength;
        try {
            logicalLength = Math.addExact((long) ImageCryptProtocol.OUTER_HEADER_LENGTH,
                    frame.ciphertextLength());
            logicalLength = Math.addExact(logicalLength,
                    (long) ImageCryptProtocol.AUTH_TAG_LENGTH);
        } catch (ArithmeticException e) {
            throw new ImageCryptException(ErrorKind.INVALID_HEADER,
                    "纠错载体帧长度溢出", e);
        }
        long groups = groupsFor(logicalLength, profile);
        if (groups * symbolsPerGroup(profile) > availableModules(raster, profile)) {
            throw invalid("纠错载体像素不足，图片可能被裁剪或过度缩放");
        }

        long remaining = logicalLength;
        boolean corrupted = false;
        for (long group = 0; group < groups; group++) {
            GroupResult result = group == 0 ? first : decodeGroup(raster, group, profile);
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
     * 返回均衡档指定逻辑长度需要的完整交织组数。
     *
     * @param logicalLength 逻辑帧长度
     * @return 向上取整后的组数
     */
    public static long groupsFor(final long logicalLength) {
        return groupsFor(logicalLength, ImageCryptRobustness.BALANCED);
    }

    /**
     * 返回指定档位和逻辑长度需要的完整交织组数。
     *
     * @param logicalLength 逻辑帧长度
     * @param profile 抗干扰强度
     * @return 向上取整后的组数
     */
    public static long groupsFor(final long logicalLength,
                                 final ImageCryptRobustness profile) {
        long groupBytes = groupDataBytes(profile);
        return (logicalLength + groupBytes - 1L) / groupBytes;
    }

    /**
     * 返回指定档位一个交织组的灰度符号数。
     *
     * @param profile 抗干扰强度
     * @return 灰度符号数
     */
    public static long symbolsPerGroup(final ImageCryptRobustness profile) {
        return (long) profile.codeBytes() * profile.interleave() * 8L
                / profile.bitsPerSymbol();
    }

    /**
     * 返回指定档位的最大逻辑帧容量。
     *
     * @param profile 抗干扰强度
     * @return 最大逻辑帧字节数
     */
    public static long maximumLogicalBytes(final ImageCryptRobustness profile) {
        requireProfile(profile);
        long sideModules = MAX_CANVAS_SIDE / profile.moduleSize();
        long groups = sideModules * sideModules / symbolsPerGroup(profile);
        return groups * groupDataBytes(profile);
    }

    /**
     * 创建各纠错档位的 Reed-Solomon 编解码器。
     *
     * @return 档位到编解码器的映射
     */
    private static Map<ImageCryptRobustness, Fec> createFecProfiles() {
        Map<ImageCryptRobustness, Fec> result = new EnumMap<>(ImageCryptRobustness.class);
        for (ImageCryptRobustness profile : DECODING_PROFILES) {
            result.put(profile, Fec.newFec(profile.dataBytes(), profile.codeBytes()));
        }
        return result;
    }

    /**
     * 自动探测载体采用的抗干扰强度。
     *
     * @param input 图片路径
     * @return 已识别并解出首组的载体
     * @throws ImageCryptException 所有支持档位均无法恢复有效协议头
     * @throws IOException 图片读取失败
     */
    private static DecodedCarrier detectCarrier(final Path input)
            throws ImageCryptException, IOException {
        RobustRaster raster = decodeRaster(input);
        for (ImageCryptRobustness profile : DECODING_PROFILES) {
            try {
                GroupResult first = decodeGroup(raster, 0, profile);
                if (first.data().length < ImageCryptProtocol.OUTER_HEADER_LENGTH) {
                    continue;
                }
                ImageCryptFrame frame = ImageCryptFrame.fromBytes(Arrays.copyOf(first.data(),
                        ImageCryptProtocol.OUTER_HEADER_LENGTH));
                validateCanvas(frame, raster, profile);
                return new DecodedCarrier(raster, profile, frame, first);
            } catch (ImageCryptException | RuntimeException ignored) {
                // 协议头的魔数与 CRC 共同承担无歧义的档位识别。
            }
        }
        throw invalid("图片不是受支持的纠错载体，或协议头损坏程度超过纠错能力");
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
     * @param profile 抗干扰强度
     * @return 逻辑数据及超限错误标志
     * @throws ImageCryptException 灰度符号不足
     */
    private static GroupResult decodeGroup(final RobustRaster raster, final long groupIndex,
                                           final ImageCryptRobustness profile)
            throws ImageCryptException {
        long symbolsPerGroup = symbolsPerGroup(profile);
        long firstSymbol = groupIndex * symbolsPerGroup;
        if (firstSymbol < 0 || firstSymbol + symbolsPerGroup
                > availableModules(raster, profile)) {
            throw invalid("纠错载体缺少第 " + groupIndex + " 个交织组");
        }
        int encodedLength = profile.codeBytes() * profile.interleave();
        byte[] encoded = new byte[encodedLength];
        long symbolIndex = firstSymbol;
        int bitBuffer = 0;
        int bitCount = 0;
        int encodedCursor = 0;
        int symbolBits = profile.bitsPerSymbol();
        int quantizationShift = 8 - symbolBits;
        int symbolMask = (1 << symbolBits) - 1;
        while (encodedCursor < encoded.length) {
            int symbol = sampleLuminance(raster, symbolIndex++, profile)
                    >>> quantizationShift;
            symbol = Math.min(symbol, symbolMask);
            bitBuffer = (bitBuffer << symbolBits) | symbol;
            bitCount += symbolBits;
            if (bitCount >= 8) {
                bitCount -= 8;
                encoded[encodedCursor++] = (byte) (bitBuffer >>> bitCount);
                bitBuffer = bitCount == 0 ? 0 : bitBuffer & ((1 << bitCount) - 1);
            }
        }

        byte[][] codewords = new byte[profile.interleave()][profile.codeBytes()];
        encodedCursor = 0;
        for (int column = 0; column < profile.codeBytes(); column++) {
            for (int block = 0; block < profile.interleave(); block++) {
                codewords[block][column] = encoded[encodedCursor++];
            }
        }

        byte[] decoded = new byte[groupDataBytes(profile)];
        boolean corrupted = false;
        Fec fec = FEC_BY_PROFILE.get(profile);
        for (int block = 0; block < profile.interleave(); block++) {
            ReedSolomon.DecodeResult result = ReedSolomon.decode(fec, codewords[block], false);
            System.arraycopy(result.data, 0, decoded,
                    block * profile.dataBytes(), profile.dataBytes());
            corrupted |= result.corrupted;
        }
        return new GroupResult(decoded, corrupted);
    }

    /**
     * 取得一个符号块的平均亮度。
     *
     * <p>极强档把固定 960×960 符号网格按比例投影到实际图像，因此经过等比例缩小后仍可
     * 解码。其余档位每个像素就是一个符号，保持与已有产物完全兼容。
     *
     * @param raster 亮度栅格
     * @param symbolIndex 符号线性序号
     * @param profile 抗干扰强度
     * @return 0 至 255 的平均亮度
     */
    private static int sampleLuminance(final RobustRaster raster, final long symbolIndex,
                                       final ImageCryptRobustness profile) {
        if (profile.moduleSize() == 1) {
            return raster.luminanceAt(symbolIndex);
        }
        int gridWidth = MAX_CANVAS_SIDE / profile.moduleSize();
        int gridHeight = gridWidth;
        int moduleX = (int) (symbolIndex % gridWidth);
        int moduleY = (int) (symbolIndex / gridWidth);
        int x0 = moduleX * raster.width() / gridWidth;
        int x1 = (moduleX + 1) * raster.width() / gridWidth;
        int y0 = moduleY * raster.height() / gridHeight;
        int y1 = (moduleY + 1) * raster.height() / gridHeight;
        x1 = Math.max(x0 + 1, x1);
        y1 = Math.max(y0 + 1, y1);
        long sum = 0;
        int count = 0;
        for (int y = y0; y < y1; y++) {
            long row = (long) y * raster.width();
            for (int x = x0; x < x1; x++) {
                sum += raster.luminanceAt(row + x);
                count++;
            }
        }
        return (int) ((sum + count / 2L) / count);
    }

    /**
     * 校验协议头画布与实际解码图片的关系。
     *
     * @param frame 协议头
     * @param raster 实际图片
     * @param profile 已识别的抗干扰强度
     * @throws ImageCryptException 尺寸不满足该档位约束
     */
    private static void validateCanvas(final ImageCryptFrame frame, final RobustRaster raster,
                                       final ImageCryptRobustness profile)
            throws ImageCryptException {
        if (profile != ImageCryptRobustness.EXTREME) {
            if (frame.canvasWidth() != raster.width()
                    || frame.canvasHeight() != raster.height()) {
                throw invalid("纠错载体尺寸已改变，期望 " + frame.canvasWidth() + "×"
                        + frame.canvasHeight() + "，实际 " + raster.width() + "×"
                        + raster.height());
            }
            return;
        }
        int minimumSide = MAX_CANVAS_SIDE / profile.moduleSize();
        double aspectError = Math.abs((double) raster.width() / raster.height() - 1.0);
        if (frame.canvasWidth() != MAX_CANVAS_SIDE
                || frame.canvasHeight() != MAX_CANVAS_SIDE
                || raster.width() < minimumSide || raster.height() < minimumSide
                || aspectError > 0.02) {
            throw invalid("极强纠错载体必须保持近似正方形，且不得缩小到 "
                    + minimumSide + " 像素以下");
        }
    }

    /**
     * 返回实际栅格可表示的符号块数量。
     *
     * @param raster 亮度栅格
     * @param profile 抗干扰强度
     * @return 可用符号块数
     */
    private static long availableModules(final RobustRaster raster,
                                         final ImageCryptRobustness profile) {
        if (profile == ImageCryptRobustness.EXTREME) {
            long side = MAX_CANVAS_SIDE / profile.moduleSize();
            return side * side;
        }
        return raster.pixelCount();
    }

    /**
     * 返回一个交织组承载的逻辑字节数。
     *
     * @param profile 抗干扰强度
     * @return 逻辑字节数
     */
    private static int groupDataBytes(final ImageCryptRobustness profile) {
        return profile.dataBytes() * profile.interleave();
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
     * 拒绝未启用纠错载体的档位。
     *
     * @param profile 待校验档位
     * @throws IllegalArgumentException 档位为空或为 NONE
     */
    private static void requireProfile(final ImageCryptRobustness profile) {
        if (profile == null || !profile.enabled()) {
            throw new IllegalArgumentException("抗重编码载体需要启用纠错强度");
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
     * @param corrupted 是否存在超出 RS 能力的码字
     */
    private record GroupResult(byte[] data, boolean corrupted) {
    }

    /**
     * 已识别档位并解码首组的载体。
     *
     * @param raster 亮度栅格
     * @param profile 抗干扰强度
     * @param frame 外层协议头
     * @param firstGroup 已解码首组
     */
    private record DecodedCarrier(RobustRaster raster, ImageCryptRobustness profile,
                                  ImageCryptFrame frame, GroupResult firstGroup) {
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

        /** 当前抗干扰强度。 */
        private final ImageCryptRobustness profile;

        /** 当前 Reed-Solomon 编解码器。 */
        private final Fec fec;

        /** 尚未读取的逻辑字节数。 */
        private long remaining;

        /** 当前交织组。 */
        private final byte[] encoded;

        /** 当前交织组读取位置。 */
        private int cursor;

        /** 是否已经验证逻辑输入末尾。 */
        private boolean finished;

        /**
         * 创建编码流。
         *
         * @param logical 逻辑输入
         * @param logicalLength 精确长度
         * @param profile 抗干扰强度
         */
        private EncodingInputStream(final InputStream logical, final long logicalLength,
                                    final ImageCryptRobustness profile) {
            if (logicalLength <= 0) {
                throw new IllegalArgumentException("逻辑帧长度必须为正");
            }
            this.logical = logical;
            this.remaining = logicalLength;
            this.profile = profile;
            this.fec = FEC_BY_PROFILE.get(profile);
            this.encoded = new byte[profile.codeBytes() * profile.interleave()];
            this.cursor = encoded.length;
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
            byte[][] codewords = new byte[profile.interleave()][];
            for (int block = 0; block < profile.interleave(); block++) {
                byte[] data = new byte[profile.dataBytes()];
                int wanted = (int) Math.min((long) profile.dataBytes(), remaining);
                readFully(data, wanted);
                remaining -= wanted;
                codewords[block] = ReedSolomon.encode(fec, data);
            }
            int output = 0;
            for (int column = 0; column < profile.codeBytes(); column++) {
                for (int block = 0; block < profile.interleave(); block++) {
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
