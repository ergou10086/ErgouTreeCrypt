package hbnu.project.ergoutreecrypt.fileops;

/**
 * 共享 Java 核心能够写入的 ZIPX 压缩方法。
 */
public enum ZipxMethod {
    /**
     * BZip2，对应 ZIP 方法十二。
     */
    BZIP2(12),
    /**
     * 带 ZIP 属性头的 LZMA，对应 ZIP 方法十四。
     */
    LZMA(14),
    /**
     * 使用 LZMA2 的 XZ，对应 ZIP 方法九十五，是新 ZIPX 归档的默认值。
     */
    XZ(95);

    private final int code;

    /**
     * 记录标准 ZIP 方法编号。
     *
     * @param code ZIP 压缩方法
     */
    ZipxMethod(int code) {
        this.code = code;
    }

    /**
     * 返回标准 ZIP 方法编号。
     *
     * @return 方法编号
     */
    public int code() {
        return code;
    }
}
