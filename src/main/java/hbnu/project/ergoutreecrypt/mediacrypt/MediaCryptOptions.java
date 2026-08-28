package hbnu.project.ergoutreecrypt.mediacrypt;

/**
 * 音视频加密选项。
 *
 * <p>仅在<b>加密</b>时由调用方提供；解密所需的全部参数都从密文容器内的元数据
 * （{@link MediaMetadata}）读取，因此解密不需要本类。
 *
 * <p>使用 Builder 构造，未显式设置项采用安全默认值：
 * <ul>
 *   <li>{@code profile}：按格式取推荐安全档（{@link MediaCryptProfile#defaultFor}）；</li>
 *   <li>{@code paranoid}：false（普通 Argon2 / BLAKE2b）；</li>
 *   <li>{@code storeIntegrity}：true（在元数据存原文 MAC，供解密后校验）。</li>
 * </ul>
 *
 * @author ErgouTree
 */
public final class MediaCryptOptions {

    private final MediaCryptProfile profile;
    private final boolean paranoid;
    private final boolean storeIntegrity;
    private final Integer argon2MemoryKib;
    private final Integer argon2Passes;
    private final Integer argon2Threads;

    private MediaCryptOptions(Builder b) {
        this.profile = b.profile;
        this.paranoid = b.paranoid;
        this.storeIntegrity = b.storeIntegrity;
        this.argon2MemoryKib = b.argon2MemoryKib;
        this.argon2Passes = b.argon2Passes;
        this.argon2Threads = b.argon2Threads;
    }

    /**
     * 返回某格式的默认选项。
     */
    public static MediaCryptOptions defaults() {
        return new Builder().build();
    }

    public static Builder builder() {
        return new Builder();
    }

    /**
     * 加密档位；{@code null} 表示"按格式取默认安全档"。
     */
    public MediaCryptProfile profile() {
        return profile;
    }

    /**
     * 是否使用偏执模式（Argon2 8 passes + HMAC-SHA3-512）。
     */
    public boolean paranoid() {
        return paranoid;
    }

    /**
     * 是否在元数据中存储原文完整性 MAC（解密后校验是否正确还原）。
     */
    public boolean storeIntegrity() {
        return storeIntegrity;
    }

    /**
     * 覆写 Argon2id 内存参数（KiB），null 表示使用默认值。
     *
     * @return 内存参数（KiB），可能为 null
     */
    public Integer argon2MemoryKib() {
        return argon2MemoryKib;
    }

    /**
     * 覆写 Argon2id 迭代次数，null 表示使用默认值。
     *
     * @return 迭代次数，可能为 null
     */
    public Integer argon2Passes() {
        return argon2Passes;
    }

    /**
     * 覆写 Argon2id 并行线程数，null 表示使用默认值。
     *
     * @return 线程数，可能为 null
     */
    public Integer argon2Threads() {
        return argon2Threads;
    }

    /**
     * 解析出针对指定格式实际生效的档位（处理 {@code null} 默认值并校验归属）。
     *
     * @throws IllegalArgumentException 指定档位不属于该格式
     */
    public MediaCryptProfile resolveProfile(MediaFormat format) {
        if (profile == null) {
            return MediaCryptProfile.defaultFor(format);
        }
        if (profile.format() != format) {
            throw new IllegalArgumentException(
                    "档位 " + profile + " 不适用于格式 " + format);
        }
        return profile;
    }

    /**
     * {@link MediaCryptOptions} 构造器。
     */
    public static final class Builder {
        private MediaCryptProfile profile = null;
        private boolean paranoid = false;
        private boolean storeIntegrity = true;
        private Integer argon2MemoryKib = null;
        private Integer argon2Passes = null;
        private Integer argon2Threads = null;

        public Builder profile(MediaCryptProfile profile) {
            this.profile = profile;
            return this;
        }

        public Builder paranoid(boolean paranoid) {
            this.paranoid = paranoid;
            return this;
        }

        public Builder storeIntegrity(boolean storeIntegrity) {
            this.storeIntegrity = storeIntegrity;
            return this;
        }

        /**
         * 覆写 Argon2id 内存参数（KiB）。
         *
         * @param argon2MemoryKib 内存参数（KiB），null 表示默认
         */
        public Builder argon2MemoryKib(Integer argon2MemoryKib) {
            this.argon2MemoryKib = argon2MemoryKib;
            return this;
        }

        /**
         * 覆写 Argon2id 迭代次数。
         *
         * @param argon2Passes 迭代次数，null 表示默认
         */
        public Builder argon2Passes(Integer argon2Passes) {
            this.argon2Passes = argon2Passes;
            return this;
        }

        /**
         * 覆写 Argon2id 并行线程数。
         *
         * @param argon2Threads 线程数，null 表示默认
         */
        public Builder argon2Threads(Integer argon2Threads) {
            this.argon2Threads = argon2Threads;
            return this;
        }

        public MediaCryptOptions build() {
            return new MediaCryptOptions(this);
        }
    }
}
