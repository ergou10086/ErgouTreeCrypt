package hbnu.project.ergoutreecrypt.filestego.api;

/**
 * 文件隐写选项——用户层调用 {@code FileStegoCodec.hide} 时的完整可选参数。
 *
 * <p>包含加密相关选项和载体嵌入相关选项，由门面方法内部拆分为
 * {@link StegoEncodeOptions}（传递给 PayloadCodec）和 {@link EmbedOptions}
 * （传递给 CarrierAdapter）。
 *
 * @author ErgouTree
 * @since 2026/8/5
 */
public final class FileStegoOptions {

    /** 是否启用 paranoid 模式（Serpent + XChaCha20 双层加密）。 */
    private final boolean paranoid;

    /** 是否在加密前对原始文件进行 Zstandard 压缩。 */
    private final boolean compressed;

    /** 是否存储完整性校验（Payload MAC + Header MAC）。 */
    private final boolean storeIntegrity;

    /** 是否启用隐蔽模式（HMAC 派生魔数）。 */
    private final boolean stealth;

    /** 是否混淆输出文件大小。 */
    private final boolean obfuscateSize;

    /** 目标文件大小（字节），仅在 obfuscateSize=true 时有效。 */
    private final long targetSizeBytes;

    /** 是否启用防暴力破解。 */
    private final boolean bruteForceGuard;

    /** 是否优先使用自定义区域嵌入（如 PNG stEG chunk）。 */
    private final boolean preferChunk;

    private FileStegoOptions(final Builder builder) {
        this.paranoid = builder.paranoid;
        this.compressed = builder.compressed;
        this.storeIntegrity = builder.storeIntegrity;
        this.stealth = builder.stealth;
        this.obfuscateSize = builder.obfuscateSize;
        this.targetSizeBytes = builder.targetSizeBytes;
        this.bruteForceGuard = builder.bruteForceGuard;
        this.preferChunk = builder.preferChunk;
    }

    /**
     * @return 是否 paranoid 模式
     */
    public boolean isParanoid() {
        return paranoid;
    }

    /**
     * @return 是否加密前压缩
     */
    public boolean isCompressed() {
        return compressed;
    }

    /**
     * @return 是否存储完整性校验
     */
    public boolean isStoreIntegrity() {
        return storeIntegrity;
    }

    /**
     * @return 是否隐蔽模式
     */
    public boolean isStealth() {
        return stealth;
    }

    /**
     * @return 是否混淆文件大小
     */
    public boolean isObfuscateSize() {
        return obfuscateSize;
    }

    /**
     * @return 目标文件大小（字节）
     */
    public long targetSizeBytes() {
        return targetSizeBytes;
    }

    /**
     * @return 是否启用防暴力破解
     */
    public boolean isBruteForceGuard() {
        return bruteForceGuard;
    }

    /**
     * @return 是否优先使用自定义区域嵌入
     */
    public boolean preferChunk() {
        return preferChunk;
    }

    /**
     * 从当前选项构建 {@link StegoEncodeOptions}（Payload 层使用）。
     *
     * @return Payload 编码选项
     */
    public StegoEncodeOptions toEncodeOptions() {
        return StegoEncodeOptions.builder()
                .paranoid(paranoid)
                .compressed(compressed)
                .hasIntegrity(storeIntegrity)
                .hasHeaderMac(storeIntegrity)
                .build();
    }

    /**
     * 从当前选项构建 {@link EmbedOptions}（Adapter 层使用）。
     *
     * @return 嵌入选项
     */
    public EmbedOptions toEmbedOptions() {
        return EmbedOptions.builder()
                .paranoid(paranoid)
                .hasIntegrity(storeIntegrity)
                .stealth(stealth)
                .preferChunk(preferChunk)
                .build();
    }

    /**
     * @return 返回默认选项的构建器
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * @return 默认选项
     */
    public static FileStegoOptions defaults() {
        return builder().build();
    }

    /**
     * {@link FileStegoOptions} 的构建器。
     */
    public static final class Builder {
        private boolean paranoid;
        private boolean compressed;
        private boolean storeIntegrity = true;
        private boolean stealth;
        private boolean obfuscateSize;
        private long targetSizeBytes;
        private boolean bruteForceGuard = true;
        private boolean preferChunk = true;

        /**
         * 设置 paranoid 模式。
         *
         * @param p 是否启用
         * @return this
         */
        public Builder paranoid(final boolean p) {
            this.paranoid = p;
            return this;
        }

        /**
         * 设置是否加密前压缩。
         *
         * @param c 是否压缩
         * @return this
         */
        public Builder compressed(final boolean c) {
            this.compressed = c;
            return this;
        }

        /**
         * 设置是否存储完整性校验。
         *
         * @param store 是否存储
         * @return this
         */
        public Builder storeIntegrity(final boolean store) {
            this.storeIntegrity = store;
            return this;
        }

        /**
         * 设置隐蔽模式。
         *
         * @param s 是否启用
         * @return this
         */
        public Builder stealth(final boolean s) {
            this.stealth = s;
            return this;
        }

        /**
         * 设置是否混淆文件大小。
         *
         * @param o 是否混淆
         * @return this
         */
        public Builder obfuscateSize(final boolean o) {
            this.obfuscateSize = o;
            return this;
        }

        /**
         * 设置目标文件大小（字节）。
         *
         * @param bytes 目标字节数
         * @return this
         */
        public Builder targetSizeBytes(final long bytes) {
            this.targetSizeBytes = bytes;
            return this;
        }

        /**
         * 设置是否启用防暴力破解。
         *
         * @param b 是否启用
         * @return this
         */
        public Builder bruteForceGuard(final boolean b) {
            this.bruteForceGuard = b;
            return this;
        }

        /**
         * 设置是否优先使用自定义区域嵌入。
         *
         * @param prefer 是否优先
         * @return this
         */
        public Builder preferChunk(final boolean prefer) {
            this.preferChunk = prefer;
            return this;
        }

        /**
         * @return 构建 {@link FileStegoOptions} 实例
         */
        public FileStegoOptions build() {
            return new FileStegoOptions(this);
        }
    }
}
