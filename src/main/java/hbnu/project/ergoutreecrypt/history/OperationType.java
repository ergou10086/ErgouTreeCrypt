package hbnu.project.ergoutreecrypt.history;

/**
 * 加密操作类型枚举。
 *
 * <p>定义操作历史支持的全部操作类型。新增操作类型时只需追加枚举值，
 * 历史记录的持久化格式（按枚举名序列化）与展示逻辑无需改动；
 * 旧版本应用读取包含未知类型的历史文件时，会跳过无法识别的记录行，不影响其余记录。
 *
 * @author ErgouTree
 * @since 2026/8/14
 */
public enum OperationType {

    /** 通用加密 */
    GENERIC_ENCRYPT("通用加密", "history.type.genericEncrypt"),

    /** 通用解密 */
    GENERIC_DECRYPT("通用解密", "history.type.genericDecrypt"),

    /** 格式保持加密 */
    FPE_ENCRYPT("格式保持加密", "history.type.fpeEncrypt"),

    /** 格式保持解密 */
    FPE_DECRYPT("格式保持解密", "history.type.fpeDecrypt"),

    /** 隐写加密 */
    STEGO_ENCODE("隐写加密", "history.type.stegoEncode"),

    /** 隐写提取 */
    STEGO_EXTRACT("隐写提取", "history.type.stegoExtract");

    /** 默认显示名（中文），供未接入 i18n 的平台（如移动端）直接使用 */
    private final String defaultLabel;

    /** i18n 资源键，桌面端通过 Messages 按当前语言解析显示名 */
    private final String i18nKey;

    /**
     * 构造操作类型枚举值。
     *
     * @param defaultLabel 默认显示名
     * @param i18nKey     i18n 资源键
     */
    OperationType(String defaultLabel, String i18nKey) {
        this.defaultLabel = defaultLabel;
        this.i18nKey = i18nKey;
    }

    /**
     * 获取默认显示名。
     *
     * @return 默认显示名（中文）
     */
    public String getDefaultLabel() {
        return defaultLabel;
    }

    /**
     * 获取 i18n 资源键。
     *
     * @return i18n 资源键
     */
    public String getI18nKey() {
        return i18nKey;
    }
}
