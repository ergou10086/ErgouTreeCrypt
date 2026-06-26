package hbnu.project.ergoutreecrypt.mediacrypt;

/**
 * 加密档位（profile）枚举，对应 {@code docs/AV_ENCRYPTION.md} 中各格式的强度/兼容档位。
 *
 * <p>档位决定"加密哪一部分 payload"。{@link #code} 写入元数据，解密时据此还原相同区间，
 * <b>数值一经发布不得更改</b>。
 *
 * <p>已落地档位：
 * <ul>
 *   <li>WAV → {@link #W_FULL}（安全）、{@link #W_SEL}（性能/预览，pattern 选择性加密）</li>
 *   <li>MP3 → {@link #M_BODY}（安全）、{@link #M_SAFE}（兼容增强，仅 MainData）</li>
 *   <li>MP4 → {@link #V_MDAT}（安全）</li>
 * </ul>
 * MP4 的 {@link #V_SAMPLE} / {@link #V_PATTERN} 为后续迭代预留枚举值。
 *
 * @author ErgouTree
 */
public enum MediaCryptProfile {

    // ---- WAV ----
    /**
     * WAV 安全档：加密整个 {@code data} chunk payload。
     */
    W_FULL((byte) 10, MediaFormat.WAV),
    /**
     * WAV 性能/预览档：对 {@code data} payload 做 pattern 选择性加密（每 8KB 加密前 4KB）。
     * 速度更快，但机密性弱于 {@link #W_FULL}，仅适用于预览保护 / 访问控制。
     */
    W_SEL((byte) 11, MediaFormat.WAV),

    // ---- MP3 ----
    /**
     * MP3 安全档（MVP）：加密每帧 Header 之后的全部字节（SideInfo + MainData）。
     */
    M_BODY((byte) 20, MediaFormat.MP3),
    /**
     * MP3 兼容增强档（预留）：仅加密 MainData，保留 Side Info。
     */
    M_SAFE((byte) 21, MediaFormat.MP3),

    // ---- MP4 ----
    /**
     * MP4 安全档（MVP）：加密整个 {@code mdat} payload。
     */
    V_MDAT((byte) 30, MediaFormat.MP4),
    /**
     * MP4 兼容增强档（预留）：按采样表保留 NAL 头，仅加密 slice 数据。
     */
    V_SAMPLE((byte) 31, MediaFormat.MP4),
    /**
     * MP4 性能档（预留）：V_SAMPLE 基础上按 1:9 pattern 加密。
     */
    V_PATTERN((byte) 32, MediaFormat.MP4);

    private final byte code;
    private final MediaFormat format;

    MediaCryptProfile(byte code, MediaFormat format) {
        this.code = code;
        this.format = format;
    }

    /**
     * 返回某格式的默认（推荐）档位。
     */
    public static MediaCryptProfile defaultFor(MediaFormat format) {
        return switch (format) {
            case WAV -> W_FULL;
            case MP3 -> M_BODY;
            case MP4 -> V_MDAT;
        };
    }

    /**
     * 根据元数据中的档位编码反查枚举。
     *
     * @throws IllegalArgumentException 未知编码
     */
    public static MediaCryptProfile fromCode(byte code) {
        for (MediaCryptProfile p : values()) {
            if (p.code == code) {
                return p;
            }
        }
        throw new IllegalArgumentException("未知加密档位编码: " + code);
    }

    /**
     * 写入元数据的稳定档位编码。
     */
    public byte code() {
        return code;
    }

    /**
     * 该档位所属的媒体格式。
     */
    public MediaFormat format() {
        return format;
    }
}
