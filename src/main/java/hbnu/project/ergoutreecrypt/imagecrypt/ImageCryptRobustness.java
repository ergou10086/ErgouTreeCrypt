package hbnu.project.ergoutreecrypt.imagecrypt;

/**
 * 图片密文载体的抗干扰强度。
 *
 * <p>更高强度会依次增加 Reed-Solomon 冗余、扩大灰度量化间隔，并在极强档中使用
 * 2×2 像素块重复。代价是可承载的恢复副本更小，超过上限的原图会先转成有损 JPEG。
 *
 * @author ErgouTree
 * @since 2026/9/18
 */
public enum ImageCryptRobustness {

    /** 不使用抗重编码载体，保持普通无损 RGB 密文图。 */
    NONE(0, 0, 0, 0, 0, Long.MAX_VALUE),

    /** 兼容既有纠错载体，使用 RS(192,128)、8 级灰度和 16 路交织。 */
    BALANCED(128, 192, 16, 3, 1, 800_000L),

    /** 使用 RS(192,96)、4 级灰度和 16 路交织，适合更强 JPEG 重编码。 */
    STRONG(96, 192, 16, 2, 1, 380_000L),

    /** 使用 RS(192,96)、二值灰度、2×2 重复块和归一化采样。 */
    EXTREME(96, 192, 16, 1, 2, 45_000L);

    /** 单个 Reed-Solomon 码字的数据字节数。 */
    private final int dataBytes;

    /** 单个 Reed-Solomon 码字的编码字节数。 */
    private final int codeBytes;

    /** 一个交织组包含的码字数。 */
    private final int interleave;

    /** 每个灰度符号携带的位数。 */
    private final int bitsPerSymbol;

    /** 一个符号在横向和纵向重复的像素数。 */
    private final int moduleSize;

    /** 保留原文件字节而不转码的安全上限。 */
    private final long sourceBytesLimit;

    /**
     * 创建一个抗干扰强度定义。
     *
     * @param dataBytes 单码字数据字节数
     * @param codeBytes 单码字编码字节数
     * @param interleave 交织路数
     * @param bitsPerSymbol 单灰度符号位数
     * @param moduleSize 符号像素块边长
     * @param sourceBytesLimit 原文件免转码上限
     */
    ImageCryptRobustness(final int dataBytes, final int codeBytes, final int interleave,
                         final int bitsPerSymbol, final int moduleSize,
                         final long sourceBytesLimit) {
        this.dataBytes = dataBytes;
        this.codeBytes = codeBytes;
        this.interleave = interleave;
        this.bitsPerSymbol = bitsPerSymbol;
        this.moduleSize = moduleSize;
        this.sourceBytesLimit = sourceBytesLimit;
    }

    /**
     * 判断是否启用抗重编码载体。
     *
     * @return true 表示启用纠错载体
     */
    public boolean enabled() {
        return this != NONE;
    }

    /**
     * 返回单个 Reed-Solomon 码字的数据字节数。
     *
     * @return 数据字节数
     */
    public int dataBytes() {
        return dataBytes;
    }

    /**
     * 返回单个 Reed-Solomon 码字的编码字节数。
     *
     * @return 编码字节数
     */
    public int codeBytes() {
        return codeBytes;
    }

    /**
     * 返回交织路数。
     *
     * @return 交织路数
     */
    public int interleave() {
        return interleave;
    }

    /**
     * 返回单个灰度符号携带的位数。
     *
     * @return 每符号位数
     */
    public int bitsPerSymbol() {
        return bitsPerSymbol;
    }

    /**
     * 返回符号像素块边长。
     *
     * @return 像素块边长
     */
    public int moduleSize() {
        return moduleSize;
    }

    /**
     * 返回保留原文件字节而不转码的安全上限。
     *
     * @return 字节上限
     */
    public long sourceBytesLimit() {
        return sourceBytesLimit;
    }
}
