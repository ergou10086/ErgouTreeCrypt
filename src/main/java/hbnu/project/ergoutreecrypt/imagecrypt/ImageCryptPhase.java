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
    PROBE,

    /**
     * 读取输入并统计长度。
     */
    READING,

    /**
     * 密码模式密钥派生（Argon2id）与 keyConfirm 校验。
     */
    KDF,

    /**
     * 内容变换（XChaCha20 流式加解密）。
     */
    ENCRYPTING,

    /**
     * 密文像素映射与 PNG 写出。
     */
    PNG_WRITING,

    /**
     * PNG 读取、反滤波与载荷抽取。
     */
    PNG_READING,

    /**
     * 完整认证标签校验。
     */
    MAC_VERIFY,

    /**
     * 临时文件提交到最终位置。
     */
    COMMITTING,

    /**
     * 流程完成。
     */
    DONE
}
