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

    private MediaCryptOptions(Builder b) {
        this.profile = b.profile;
        this.paranoid = b.paranoid;
        this.storeIntegrity = b.storeIntegrity;
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

        public MediaCryptOptions build() {
            return new MediaCryptOptions(this);
        }
    }
}
