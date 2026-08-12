package hbnu.project.ergoutreecrypt.filestego.api;

/**
 * 载体嵌入选项——传递给 {@code CarrierAdapter.embed} 的格式相关可选参数。
 *
 * <p>与 {@link FileStegoOptions} 不同，EmbedOptions 仅包含 Adapter 层关心的选项：
 * <ul>
 *   <li>是否为 paranoid 模式（影响 CarrierMetadata FLAGS）</li>
 *   <li>是否使用隐蔽模式（影响魔数派生）</li>
 *   <li>是否优先使用自定义 Chunk/Box 嵌入（vs 末尾追加）</li>
 * </ul>
 *
 * @author ErgouTree
 * @since 2026/8/5
 */
public final class EmbedOptions {

    /** 是否为 paranoid 模式。 */
    private final boolean paranoid;

    /** 是否存储完整性校验（影响 CarrierMetadata FLAGS）。 */
    private final boolean hasIntegrity;

    /** 是否使用隐蔽模式。 */
    private final boolean stealth;

    /** 是否优先使用自定义区域嵌入（如 PNG stEG chunk、WAV STEG chunk）。 */
    private final boolean preferChunk;

    private EmbedOptions(final Builder builder) {
        this.paranoid = builder.paranoid;
        this.hasIntegrity = builder.hasIntegrity;
        this.stealth = builder.stealth;
        this.preferChunk = builder.preferChunk;
    }

    /**
     * @return 是否为 paranoid 模式
     */
    public boolean isParanoid() {
        return paranoid;
    }

    /**
     * @return 是否存储完整性校验
     */
    public boolean hasIntegrity() {
        return hasIntegrity;
    }

    /**
     * @return 是否使用隐蔽模式
     */
    public boolean isStealth() {
        return stealth;
    }

    /**
     * @return 是否优先使用自定义区域嵌入
     */
    public boolean preferChunk() {
        return preferChunk;
    }

    /**
     * @return 返回默认选项的构建器
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * @return 默认嵌入选项
     */
    public static EmbedOptions defaults() {
        return builder().build();
    }

    /**
     * {@link EmbedOptions} 的构建器。
     */
    public static final class Builder {
        private boolean paranoid;
        private boolean hasIntegrity = true;
        private boolean stealth;
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
         * 设置是否存储完整性校验。
         *
         * @param has 是否存储
         * @return this
         */
        public Builder hasIntegrity(final boolean has) {
            this.hasIntegrity = has;
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
         * @return 构建 {@link EmbedOptions} 实例
         */
        public EmbedOptions build() {
            return new EmbedOptions(this);
        }
    }
}
