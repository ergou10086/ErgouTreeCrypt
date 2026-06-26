package hbnu.project.ergoutreecrypt.mediacrypt.mp3;

/**
 * MPEG Audio 帧头查表与帧长计算（覆盖 MPEG-1 / MPEG-2 / MPEG-2.5，Layer I/II/III）。
 *
 * <p>MP3 帧头为 4 字节，结构（高位在前）：
 * <pre>
 * AAAAAAAA AAABBCCD EEEEFFGH IIJJKLMM
 *   A(11) 同步字 = 0x7FF
 *   B(2)  MPEG 版本 ID：00=2.5, 10=2, 11=1（01 保留）
 *   C(2)  Layer：01=III, 10=II, 11=I（00 保留）
 *   D(1)  保护位（0=有 16-bit CRC 跟在帧头后）
 *   E(4)  比特率索引
 *   F(2)  采样率索引
 *   G(1)  padding（1=该帧多 1 字节(Layer III/II) 或 4 字节(Layer I)）
 *   H(1)  private
 *   I(2)  声道模式：11=单声道，其余为立体声类
 *   ...
 * </pre>
 *
 * <p>帧长公式（字节，向下取整）：
 * <ul>
 *   <li>Layer I：{@code (12 * bitrate / sampleRate + padding) * 4}</li>
 *   <li>Layer II/III：{@code 144 * bitrate / sampleRate + padding}（MPEG-2/2.5 Layer III 系数为 72）</li>
 * </ul>
 *
 * <p>本类是纯查表/计算工具，是 MP3 帧扫描正确性的基石，因此配有针对真实参数的单测。
 *
 * @author ErgouTree
 */
public final class Mp3HeaderTables {

    public static final int MPEG_25 = 0;
    public static final int MPEG_RESERVED = 1;
    public static final int MPEG_2 = 2;
    public static final int MPEG_1 = 3;
    public static final int LAYER_RESERVED = 0;
    public static final int LAYER_3 = 1;
    public static final int LAYER_2 = 2;
    public static final int LAYER_1 = 3;
    /**
     * 比特率表 [versionGroup][layerIndex][bitrateIndex]（单位 bps）。
     * versionGroup：0 = MPEG-1，1 = MPEG-2/2.5。
     * layerIndex：0=LayerI,1=LayerII,2=LayerIII。
     * bitrateIndex 0 表示 free，15 为非法。值为 0 表示 free/非法。
     */
    private static final int[][][] BITRATE = {
            { // MPEG-1
                    {0, 32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448, 0}, // I
                    {0, 32, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384, 0},    // II
                    {0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 0}      // III
            },
            { // MPEG-2 / 2.5
                    {0, 32, 48, 56, 64, 80, 96, 112, 128, 144, 160, 176, 192, 224, 256, 0},    // I
                    {0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160, 0},         // II
                    {0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160, 0}          // III
            }
    };
    /**
     * 采样率表 [versionId][sampleRateIndex]（单位 Hz）。索引 3 非法。
     */
    private static final int[][] SAMPLE_RATE = {
            {11025, 12000, 8000, 0},  // MPEG-2.5
            {0, 0, 0, 0},             // 保留
            {22050, 24000, 16000, 0}, // MPEG-2
            {44100, 48000, 32000, 0}  // MPEG-1
    };
    /**
     * 非法帧头单例。
     */
    private static final FrameHeader INVALID =
            new FrameHeader(false, 0, 0, false, 0, 0, 0, 0, 0);

    private Mp3HeaderTables() {
    }

    /**
     * 解析 4 字节帧头（大端）。
     *
     * @param b0 b1 b2 b3 帧头 4 字节
     * @return 解析结果；非法帧头返回 {@code valid=false}
     */
    public static FrameHeader parse(int b0, int b1, int b2, int b3) {
        b0 &= 0xff;
        b1 &= 0xff;
        b2 &= 0xff;
        b3 &= 0xff;

        // 同步字：11 位全 1。
        if (b0 != 0xFF || (b1 & 0xE0) != 0xE0) {
            return INVALID;
        }

        int version = (b1 >> 3) & 0x03;
        int layer = (b1 >> 1) & 0x03;
        boolean hasCrc = (b1 & 0x01) == 0;
        if (version == MPEG_RESERVED || layer == LAYER_RESERVED) {
            return INVALID;
        }

        int bitrateIdx = (b2 >> 4) & 0x0F;
        int sampleIdx = (b2 >> 2) & 0x03;
        int padding = (b2 >> 1) & 0x01;
        int channelMode = (b3 >> 6) & 0x03;

        if (bitrateIdx == 0 || bitrateIdx == 15 || sampleIdx == 3) {
            // free 格式与非法索引不在 MVP 支持范围。
            return INVALID;
        }

        int versionGroup = (version == MPEG_1) ? 0 : 1;
        int layerIndex = LAYER_1 - layer; // LAYER_1=3→0, II=2→1, III=1→2
        int bitrate = BITRATE[versionGroup][layerIndex][bitrateIdx] * 1000;
        int sampleRate = SAMPLE_RATE[version][sampleIdx];
        if (bitrate == 0 || sampleRate == 0) {
            return INVALID;
        }

        int frameLength = computeFrameLength(version, layer, bitrate, sampleRate, padding);
        if (frameLength <= 4) {
            return INVALID;
        }

        return new FrameHeader(true, version, layer, hasCrc, bitrate, sampleRate,
                padding, channelMode, frameLength);
    }

    /**
     * 计算帧长（字节）。
     */
    public static int computeFrameLength(int version, int layer, int bitrate, int sampleRate,
                                         int padding) {
        if (layer == LAYER_1) {
            return (12 * bitrate / sampleRate + padding) * 4;
        }
        // Layer II 始终系数 144；Layer III 在 MPEG-2/2.5 下为 72。
        int coeff = 144;
        if (layer == LAYER_3 && version != MPEG_1) {
            coeff = 72;
        }
        return coeff * bitrate / sampleRate + padding;
    }

    /**
     * 计算 Layer III 的 side info 长度（字节）。
     * <ul>
     *   <li>MPEG-1：单声道 17，立体声 32</li>
     *   <li>MPEG-2/2.5：单声道 9，立体声 17</li>
     * </ul>
     */
    public static int sideInfoLength(int version, int channelMode) {
        boolean mono = channelMode == 3;
        if (version == MPEG_1) {
            return mono ? 17 : 32;
        }
        return mono ? 9 : 17;
    }

    /**
     * 解析后的帧头信息。{@code valid=false} 表示不是合法帧头。
     */
    public record FrameHeader(boolean valid, int version, int layer, boolean hasCrc,
                              int bitrate, int sampleRate, int padding, int channelMode,
                              int frameLength) {
        /**
         * 单声道（声道模式 = 11）。
         */
        public boolean isMono() {
            return channelMode == 3;
        }
    }
}
