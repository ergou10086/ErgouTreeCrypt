package hbnu.project.ergoutreecrypt.mediacrypt;

import java.nio.file.Path;
import java.util.Locale;

/**
 * 音视频加密子系统支持的媒体格式枚举。
 *
 * <p>每种格式对应一套"格式保持加密"实现：加密后文件仍是合法、可被播放器打开的媒体，但内容为噪声，解密后无损还原。详见 {@code docs/AV_ENCRYPTION.md}。
 *
 * <p>{@link #formatId} 是写入元数据的稳定数值标识，<b>一经发布不得更改</b>，否则旧密文无法识别。
 *
 * @author ErgouTree
 */
public enum MediaFormat {

    /**
     * WAV / RIFF 容器（PCM 等），加密 {@code data} chunk。
     */
    WAV((byte) 1, "wav"),

    /**
     * MP3 / MPEG-1 Layer III，加密各音频帧的帧体。
     */
    MP3((byte) 2, "mp3"),

    /**
     * MP4 / ISO-BMFF 容器，加密 {@code mdat} 媒体数据。
     */
    MP4((byte) 3, "mp4", "m4a", "m4v", "mov");

    private final byte formatId;
    private final String[] extensions;

    MediaFormat(byte formatId, String... extensions) {
        this.formatId = formatId;
        this.extensions = extensions;
    }

    /**
     * 根据元数据中的 {@code formatId} 反查格式。
     *
     * @throws IllegalArgumentException 未知 formatId
     */
    public static MediaFormat fromId(byte id) {
        for (MediaFormat f : values()) {
            if (f.formatId == id) {
                return f;
            }
        }
        throw new IllegalArgumentException("未知媒体格式 id: " + id);
    }

    /**
     * 根据文件扩展名嗅探格式。
     *
     * @return 匹配的格式；无法识别返回 {@code null}
     */
    public static MediaFormat fromExtension(Path path) {
        if (path == null) {
            return null;
        }
        String name = path.getFileName().toString().toLowerCase(Locale.ROOT);
        int dot = name.lastIndexOf('.');
        if (dot < 0 || dot == name.length() - 1) {
            return null;
        }
        String ext = name.substring(dot + 1);
        for (MediaFormat f : values()) {
            for (String e : f.extensions) {
                if (e.equals(ext)) {
                    return f;
                }
            }
        }
        return null;
    }

    /**
     * 写入元数据的稳定数值标识。
     */
    public byte formatId() {
        return formatId;
    }

    /**
     * 该格式的主扩展名（不含点），用于命名建议。
     */
    public String primaryExtension() {
        return extensions[0];
    }
}
