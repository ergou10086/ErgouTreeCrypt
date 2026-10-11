package hbnu.project.ergoutreecrypt.volume;

/** 通用文件加密模式；请求默认保持原标准格式。 */
public enum EncryptionMode {
    /** 原 XChaCha20 及现有高级选项。 */
    STANDARD,
    /** FAST-v1 官方流式认证加密，仅允许独立归档操作。 */
    FAST;

    /** @return 当前模式是否允许归档之外的高级加密选项 */
    public boolean allowsAdvancedOptions() {
        return this == STANDARD;
    }
}
