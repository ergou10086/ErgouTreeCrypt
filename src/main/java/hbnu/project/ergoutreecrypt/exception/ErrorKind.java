package hbnu.project.ergoutreecrypt.exception;

/**
 * 错误分类枚举，作为「底层异常 → 友好文案」的映射键。
 *
 * <p>所有子系统的可预期错误统一归入此枚举，前端据此把 {@link CryptoException} 映射为
 * 对应语言的友好提示，从而彻底取代「按字符串包含关系猜测错误类型」的做法。
 *
 * <p>枚举名是稳定契约：一旦发布不可随意改名或删除，否则前端按类型映射会失效。
 * {@link #i18nKey()} 返回的 key 需在 {@code messages_*.properties} 中同步补充。
 *
 * @author ErgouTree
 * @since 2026/9/13
 */
public enum ErrorKind {

    /**
     * 密码错误或卷头认证失败。
     */
    WRONG_PASSWORD("error.password"),

    /**
     * 密钥文件错误、顺序错误或重复抵消。
     */
    KEYFILE_MISMATCH("error.keyfile"),

    /**
     * MAC 校验失败 / RS 无法修复 / 数据被篡改。
     */
    TAMPERED_DATA("error.tampered"),

    /**
     * 解密失败次数超过阈值，文件被暂时锁定。
     */
    BRUTE_FORCE_LOCKED("error.bruteforceLocked"),

    /**
     * 用户主动取消。
     */
    CANCELLED("error.cancelled"),

    /**
     * 输入文件不存在或被移动。
     */
    INPUT_NOT_FOUND("error.notFound"),

    /**
     * 无读写权限。
     */
    ACCESS_DENIED("error.accessDenied"),

    /**
     * 磁盘空间不足。
     */
    DISK_FULL("error.diskFull"),

    /**
     * 内存不足。
     */
    OUT_OF_MEMORY("error.outOfMemory"),

    /**
     * 格式或扩展名不支持。
     */
    UNSUPPORTED_FORMAT("error.unsupportedFormat"),

    /**
     * 文件被其它程序占用。
     */
    FILE_IN_USE("error.fileInUse"),

    /**
     * 卷头损坏、非法 version 或注释长度非法。
     */
    INVALID_HEADER("error.invalidHeader"),

    /**
     * 压缩包密码错误。
     */
    ARCHIVE_PASSWORD("error.archivePassword"),

    /**
     * 压缩包格式不支持。
     */
    ARCHIVE_UNSUPPORTED("error.archiveUnsupported"),

    /**
     * 载体容量不足。
     */
    CAPACITY_INSUFFICIENT("error.capacity"),

    /**
     * 未检测到隐写数据。
     */
    NO_STEGO_DATA("error.noStegoData"),

    /**
     * 载体格式非法。
     */
    CARRIER_INVALID("error.carrierInvalid"),

    /**
     * 隐写 payload 无效或已损坏。
     */
    PAYLOAD_INVALID("error.payloadInvalid"),

    /**
     * 兜底 I/O 错误。
     */
    IO_ERROR("error.io"),

    /**
     * 编程错误或非法参数。
     */
    INTERNAL_ERROR("error.internal");

    /**
     * 该错误分类对应的 i18n key。
     */
    private final String i18nKey;

    /**
     * @param i18nKey 对应 {@code messages_*.properties} 中的 key
     */
    ErrorKind(String i18nKey) {
        this.i18nKey = i18nKey;
    }

    /**
     * 返回该错误分类对应的 i18n key。
     *
     * @return i18n key（如 {@code error.password}）
     */
    public String i18nKey() {
        return i18nKey;
    }
}
