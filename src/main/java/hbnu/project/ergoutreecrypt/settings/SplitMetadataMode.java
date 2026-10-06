package hbnu.project.ergoutreecrypt.settings;

/** 分卷完整性信息的存储方式；读取端始终自动识别两种格式。 */
public enum SplitMetadataMode {
    EMBEDDED("settings.splitMetadata.embedded"),
    MANIFEST("settings.splitMetadata.manifest");

    private final String labelKey;

    /** @param labelKey 界面文案的资源键 */
    SplitMetadataMode(String labelKey) {
        this.labelKey = labelKey;
    }

    /** @return 界面文案的资源键 */
    public String getLabelKey() {
        return labelKey;
    }

    /** @param key 持久化值，可为空 @return 有效方式，未知值回退到公开尾部 */
    public static SplitMetadataMode fromKey(String key) {
        return MANIFEST.name().equals(key) ? MANIFEST : EMBEDDED;
    }
}
