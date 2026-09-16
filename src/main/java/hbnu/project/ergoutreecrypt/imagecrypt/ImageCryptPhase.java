package hbnu.project.ergoutreecrypt.imagecrypt;

/**
 * 图片加解密流程的阶段标识。
 *
 * <p>由 {@link ImageCryptProgress#onPhase(ImageCryptPhase)} 回传，供两端 UI 显示当前阶段
 * 文案并决定进度条的呈现方式（KDF 阶段无线性进度，载荷阶段按字节推进）。
 *
 * <p>枚举名为稳定契约：UI 按名称映射 i18n key，发布后不可随意改名。
 *
 * @author ErgouTree
 * @since 2026/9/15
 */
public enum ImageCryptPhase {

    /**
     * 有界只读探测：魔数、格式身份与尺寸提示。
     */
    PROBE("imageCrypt.phase.probe"),

    /**
     * 读取输入并统计长度。
     */
    READING("imageCrypt.phase.reading"),

    /**
     * 密码模式密钥派生（Argon2id）与 keyConfirm 校验。
     */
    KDF("imageCrypt.phase.kdf"),

    /**
     * 内容变换（XChaCha20 流式加解密）。
     */
    ENCRYPTING("imageCrypt.phase.encrypting"),

    /**
     * 密文像素映射与 PNG 写出。
     */
    PNG_WRITING("imageCrypt.phase.pngWriting"),

    /**
     * PNG 读取、反滤波与载荷抽取。
     */
    PNG_READING("imageCrypt.phase.pngReading"),

    /**
     * 完整认证标签校验。
     */
    MAC_VERIFY("imageCrypt.phase.macVerify"),

    /**
     * 临时文件提交到最终位置。
     */
    COMMITTING("imageCrypt.phase.committing"),

    /**
     * 流程完成。
     */
    DONE("imageCrypt.phase.done");

    /**
     * 双端共享的阶段文案资源键。
     */
    private final String i18nKey;

    /**
     * 创建图片加解密阶段。
     *
     * @param i18nKey 双语文案资源键
     */
    ImageCryptPhase(final String i18nKey) {
        this.i18nKey = i18nKey;
    }

    /**
     * 返回双端 UI 应使用的阶段文案资源键。
     *
     * @return {@code messages_*.properties} 中的稳定资源键
     */
    public String i18nKey() {
        return i18nKey;
    }
}
