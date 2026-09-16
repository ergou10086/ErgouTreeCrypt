package hbnu.project.ergoutreecrypt.imagecrypt;

/**
 * 只读探测出的 EGTC-IMG 元数据。
 *
 * <h3>可信范围</h3>
 * <p>本记录的全部字段都来自<b>外层 PNG 的前 184 字节协议头</b>，只经过结构合法性与 CRC 校验，
 * <b>尚未经过任何认证</b>。公开恢复模式里这些字段本就明文可见；密码保护模式里它们也必须在
 * 解密前展示（UI 需要据此提示"该文件需要密码""需要 64 MiB 内存"），因此同样不能承载秘密。
 *
 * <p>原始文件名、MIME 与真实扩展名位于加密区内，{@link ImageCryptCodec#peekMetadata} 不会
 * 也不会尝试读出它们；只有完整认证通过后，{@link ImageCryptCodec#decrypt} 才可能返回清单。
 *
 * <h3>恢复大小的区间性</h3>
 * <p>待解密的封装区长度 {@link #payloadLength()} 可以精确读出，但其中清单描述区的长度取决于
 * 原始文件名与 MIME 的字节数，只有解密后才能确定。因此恢复文件大小只能给出上下界，见
 * {@link #minRestoredBytes()} 与 {@link #maxRestoredBytes()}。
 *
 * @param protocolVersion   协议版本，v1 为 1
 * @param mode              保护模式
 * @param canvasWidth       外层 PNG 画布宽度
 * @param canvasHeight      外层 PNG 画布高度
 * @param payloadLength     加密封装区长度（清单描述区 + 原文件字节）
 * @param sourceWidthHint   原图宽度提示，未知为 0
 * @param sourceHeightHint  原图高度提示，未知为 0
 * @param argon2MemoryKiB   Argon2id 内存参数（KiB）；公开恢复模式为 0
 * @param argon2Passes      Argon2id 迭代次数；公开恢复模式为 0
 * @param argon2Lanes       Argon2id lane 并行度；公开恢复模式为 0
 *
 * @author ErgouTree
 * @since 2026/9/16
 */
public record ImageCryptMetadata(int protocolVersion, ImageCryptMode mode,
                                 int canvasWidth, int canvasHeight, long payloadLength,
                                 int sourceWidthHint, int sourceHeightHint,
                                 int argon2MemoryKiB, int argon2Passes, int argon2Lanes) {

    /**
     * 由协议头构造元数据。
     *
     * @param frame 已通过结构校验的外层协议头
     * @return 元数据实例
     */
    static ImageCryptMetadata from(final ImageCryptFrame frame) {
        return new ImageCryptMetadata(ImageCryptProtocol.VERSION, frame.protectionMode(),
                frame.canvasWidth(), frame.canvasHeight(), frame.innerPlainLength(),
                frame.sourceWidthHint(), frame.sourceHeightHint(),
                frame.argon2MemoryKiB(), frame.argon2Passes(), frame.argon2Lanes());
    }

    /**
     * 判断恢复该文件是否需要密码。
     *
     * @return true 表示密码保护模式
     */
    public boolean requiresPassword() {
        return mode == ImageCryptMode.PASSWORD;
    }

    /**
     * 是否携带原图尺寸提示。
     *
     * @return true 表示原图宽高均已知
     */
    public boolean hasSourceSizeHint() {
        return sourceWidthHint > 0 && sourceHeightHint > 0;
    }

    /**
     * 恢复文件大小的下界。
     *
     * <p>极端情况下清单描述区占满 {@link ImageCryptProtocol#LIMIT_MANIFEST_BYTES}，此时封装区
     * 几乎全是描述区，恢复出的原文件最小。
     *
     * @return 下界字节数，恒不为负
     */
    public long minRestoredBytes() {
        return Math.max(0L, payloadLength - ImageCryptProtocol.LIMIT_MANIFEST_BYTES);
    }

    /**
     * 恢复文件大小的上界。
     *
     * <p>描述区最短为 {@link ImageCryptProtocol#INNER_MANIFEST_FIXED_LENGTH}，此时其余载荷全是
     * 原文件字节。UI 若要给出单一"预估大小"，应使用该上界，避免低估导致用户以为恢复失败。
     *
     * @return 上界字节数，恒不为负
     */
    public long maxRestoredBytes() {
        return Math.max(0L, payloadLength - ImageCryptProtocol.INNER_MANIFEST_FIXED_LENGTH);
    }

    /**
     * 返回不含敏感材料的诊断描述。
     *
     * @return 描述文本
     */
    @Override
    public String toString() {
        return "ImageCryptMetadata{v" + protocolVersion
                + ", mode=" + mode
                + ", canvas=" + canvasWidth + "x" + canvasHeight
                + ", payloadLength=" + payloadLength + '}';
    }
}
