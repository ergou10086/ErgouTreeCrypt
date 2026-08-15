package hbnu.project.ergoutreecrypt.filestego.api;

/**
 * Payload 编码选项——传递给 {@code PayloadCodec.encode} 的加密相关可选参数。
 *
 * <p>与 {@link FileStegoOptions}（用户层）和 {@link EmbedOptions}（Adapter 层）不同，
 * StegoEncodeOptions 仅包含 Payload 编码/加密直接需要的选项。
 *
 * @author ErgouTree
 * @since 2026/8/5
 */
public final class StegoEncodeOptions {

    /** 是否启用 paranoid 模式（Serpent + XChaCha20 双层加密）。 */
    private final boolean paranoid;

    /** 是否在加密前对原始文件进行压缩。 */
    private final boolean compressed;

    /** 是否存储完整性校验（Payload MAC）。 */
    private final boolean hasIntegrity;

    /** 是否存储 Header MAC（快速密码验证）。 */
    private final boolean hasHeaderMac;

    /**
     * Argon2id 参数覆写（null 表示使用默认参数，如 Android 低内存档位）。
     */
    private final Argon2Params argon2Params;

    private StegoEncodeOptions(final Builder builder) {
        this.paranoid = builder.paranoid;
        this.compressed = builder.compressed;
        this.hasIntegrity = builder.hasIntegrity;
        this.hasHeaderMac = builder.hasHeaderMac;
        this.argon2Params = builder.argon2Params;
    }

    /** @return 是否 paranoid 模式 */
    public boolean isParanoid() {
        return paranoid;
    }

    /** @return 是否加密前压缩 */
    public boolean isCompressed() {
        return compressed;
    }

    /** @return 是否存储完整性校验 */
    public boolean hasIntegrity() {
        return hasIntegrity;
    }

    /** @return 是否存储 Header MAC */
    public boolean hasHeaderMac() {
        return hasHeaderMac;
    }

    /** @return Argon2id 参数覆写（null 表示使用默认参数） */
    public Argon2Params argon2Params() {
        return argon2Params;
    }

    /** @return 返回默认选项的构建器 */
    public static Builder builder() {
        return new Builder();
    }

    /** @return 默认编码选项 */
    public static StegoEncodeOptions defaults() {
        return builder().build();
    }

    /**
     * {@link StegoEncodeOptions} 的构建器。
     */
    public static final class Builder {
        private boolean paranoid;
        private boolean compressed;
        private boolean hasIntegrity = true;
        private boolean hasHeaderMac = true;
        private Argon2Params argon2Params;

        /** 设置 paranoid 模式。 */
        public Builder paranoid(final boolean p) {
            this.paranoid = p;
            return this;
        }

        /** 设置是否加密前压缩。 */
        public Builder compressed(final boolean c) {
            this.compressed = c;
            return this;
        }

        /** 设置是否存储完整性校验。 */
        public Builder hasIntegrity(final boolean has) {
            this.hasIntegrity = has;
            return this;
        }

        /** 设置是否存储 Header MAC。 */
        public Builder hasHeaderMac(final boolean has) {
            this.hasHeaderMac = has;
            return this;
        }

        /**
         * 设置 Argon2id 参数覆写（null 表示使用默认参数）。
         *
         * <p>移动端应传入低内存档位参数；该参数会持久化到载体元数据，
         * 解码侧必须读取同一参数进行派生。
         *
         * @param params Argon2 参数覆写，可为 null
         * @return this
         */
        public Builder argon2Params(final Argon2Params params) {
            this.argon2Params = params;
            return this;
        }

        /** @return 构建 {@link StegoEncodeOptions} 实例 */
        public StegoEncodeOptions build() {
            return new StegoEncodeOptions(this);
        }
    }
}
