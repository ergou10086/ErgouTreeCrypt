package hbnu.project.ergoutreecrypt.stego;

/**
 * 图像隐写选项。
 *
 * <p>采用构建器模式，提供 LSB 深度、paranoid 模式、完整性校验、隐蔽模式、
 * 文件大小混淆、防暴力破解等可选项。
 *
 * @author ErgouTree
 */
public final class StegoOptions {

    /** LSB 深度（1–4），默认 1。 */
    private final int lsbDepth;

    /** 是否启用 paranoid 模式（Serpent + XChaCha20 双层加密）。 */
    private final boolean paranoid;

    /** 是否存储原文 MAC（BLAKE2b-512）用于提取后完整性校验。 */
    private final boolean storeMac;

    /** 是否启用隐蔽模式（HMAC 派生魔数，避免 strings 检测）。 */
    private final boolean stealth;

    /** 是否混淆输出文件大小。 */
    private final boolean obfuscateSize;

    /** 目标文件大小（字节），仅在 obfuscateSize=true 时有效。 */
    private final long targetSizeBytes;

    /** 是否启用防暴力破解。 */
    private final boolean bruteForceGuard;

    private StegoOptions(final Builder builder) {
        this.lsbDepth = builder.lsbDepth;
        this.paranoid = builder.paranoid;
        this.storeMac = builder.storeMac;
        this.stealth = builder.stealth;
        this.obfuscateSize = builder.obfuscateSize;
        this.targetSizeBytes = builder.targetSizeBytes;
        this.bruteForceGuard = builder.bruteForceGuard;
    }

    /** @return LSB 深度（1–4） */
    public int lsbDepth() { return lsbDepth; }

    /** @return 是否 paranoid 模式 */
    public boolean isParanoid() { return paranoid; }

    /** @return 是否存储原文 MAC */
    public boolean isStoreMac() { return storeMac; }

    /** @return 是否启用隐蔽模式 */
    public boolean isStealth() { return stealth; }

    /** @return 是否混淆文件大小 */
    public boolean isObfuscateSize() { return obfuscateSize; }

    /** @return 目标文件大小（字节），仅在 obfuscateSize=true 时有效 */
    public long targetSizeBytes() { return targetSizeBytes; }

    /** @return 是否启用防暴力破解 */
    public boolean isBruteForceGuard() { return bruteForceGuard; }

    /** @return 返回默认选项的构建器 */
    public static Builder builder() { return new Builder(); }

    /** @return 默认选项 */
    public static StegoOptions defaults() { return builder().build(); }

    /**
     * {@link StegoOptions} 的构建器。
     */
    public static final class Builder {
        private int lsbDepth = 1;
        private boolean paranoid;
        private boolean storeMac = true;
        private boolean stealth;
        private boolean obfuscateSize;
        private long targetSizeBytes;
        private boolean bruteForceGuard = true;

        /** 设置 LSB 深度（1–4）。 */
        public Builder lsbDepth(final int depth) {
            if (depth < 1 || depth > 4) {
                throw new IllegalArgumentException("LSB 深度必须在 1–4 之间");
            }
            this.lsbDepth = depth;
            return this;
        }

        /** 设置 paranoid 模式（Serpent + XChaCha20 双层加密）。 */
        public Builder paranoid(final boolean p) {
            this.paranoid = p;
            return this;
        }

        /** 设置是否存储原文 MAC。 */
        public Builder storeMac(final boolean store) {
            this.storeMac = store;
            return this;
        }

        /** 设置隐蔽模式（HMAC 派生魔数）。 */
        public Builder stealth(final boolean s) {
            this.stealth = s;
            return this;
        }

        /** 设置是否混淆文件大小。 */
        public Builder obfuscateSize(final boolean o) {
            this.obfuscateSize = o;
            return this;
        }

        /** 设置目标文件大小（字节）。 */
        public Builder targetSizeBytes(final long bytes) {
            this.targetSizeBytes = bytes;
            return this;
        }

        /** 设置是否启用防暴力破解。 */
        public Builder bruteForceGuard(final boolean b) {
            this.bruteForceGuard = b;
            return this;
        }

        /** @return 构建 {@link StegoOptions} 实例 */
        public StegoOptions build() { return new StegoOptions(this); }
    }
}
