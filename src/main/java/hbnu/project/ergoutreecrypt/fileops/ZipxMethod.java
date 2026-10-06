package hbnu.project.ergoutreecrypt.fileops;

/** ZIPX compression methods that can be produced by the shared Java core. */
public enum ZipxMethod {
    /** BZip2, ZIP method 12. */
    BZIP2(12),
    /** LZMA with the ZIP properties header, ZIP method 14. */
    LZMA(14),
    /** XZ with LZMA2, ZIP method 95; the default for new ZIPX archives. */
    XZ(95);

    private final int code;

    /**
     * Records the standard ZIP method number.
     * @param code ZIP compression method
     */
    ZipxMethod(int code) {
        this.code = code;
    }

    /**
     * Returns the standard ZIP method number.
     * @return method number
     */
    public int code() {
        return code;
    }
}
