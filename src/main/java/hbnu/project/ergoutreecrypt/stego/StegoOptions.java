package hbnu.project.ergoutreecrypt.stego;

/**
 * 图像隐写选项。
 *
 * <p>采用构建器模式，提供 LSB 深度、paranoid 模式、完整性校验等可选项。
 *
 * @author ErgouTree
 */
public final class StegoOptions {

    /**
     * LSB 深度（1–4），默认 1。
     */
    private final int lsbDepth;

    /**
     * 是否启用 paranoid 模式（Serpent + XChaCha20 双层加密）。
     */
    private final boolean paranoid;

    /**
     * 是否存储原文 MAC（BLAKE2b-512）用于提取后完整性校验。
     */
    private final boolean storeMac;

    private StegoOptions(final Builder builder) {
        this.lsbDepth = builder.lsbDepth;
        this.paranoid = builder.paranoid;
        this.storeMac = builder.storeMac;
    }

    /**
     * @return LSB 深度（1–4）
     */
    public int lsbDepth() {
        return lsbDepth;
    }

    /**
     * @return 是否 paranoid 模式
     */
    public boolean isParanoid() {
        return paranoid;
    }

    /**
     * @return 是否存储原文 MAC
     */
    public boolean isStoreMac() {
        return storeMac;
    }

    /**
     * @return 返回默认选项的构建器
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * @return 默认选项（1 LSB、非 paranoid、存 MAC）
     */
    public static StegoOptions defaults() {
        return builder().build();
    }

    /**
     * {@link StegoOptions} 的构建器。
     */
    public static final class Builder {

        private int lsbDepth = 1;
        private boolean paranoid;
        private boolean storeMac = true;

        /**
         * 设置 LSB 深度（1–4）。
         *
         * @param depth 深度值
         * @return 当前构建器
         */
        public Builder lsbDepth(final int depth) {
            if (depth < 1 || depth > 4) {
                throw new IllegalArgumentException("LSB 深度必须在 1–4 之间");
            }
            this.lsbDepth = depth;
            return this;
        }

        /**
         * 设置 paranoid 模式。
         *
         * @param p true 启用 Serpent 双层加密
         * @return 当前构建器
         */
        public Builder paranoid(final boolean p) {
            this.paranoid = p;
            return this;
        }

        /**
         * 设置是否存储原文 MAC。
         *
         * @param store true 存储 MAC
         * @return 当前构建器
         */
        public Builder storeMac(final boolean store) {
            this.storeMac = store;
            return this;
        }

        /**
         * @return 构建 {@link StegoOptions} 实例
         */
        public StegoOptions build() {
            return new StegoOptions(this);
        }
    }
}
