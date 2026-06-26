package hbnu.project.ergoutreecrypt.mediacrypt;

import hbnu.project.ergoutreecrypt.mediacrypt.mp3.Mp3Cipher;
import hbnu.project.ergoutreecrypt.mediacrypt.mp4.Mp4Cipher;
import hbnu.project.ergoutreecrypt.mediacrypt.wav.WavCipher;

import java.io.IOException;
import java.nio.file.Path;
import java.util.EnumMap;
import java.util.Map;

/**
 * 音视频加密子系统统一入口：按媒体格式分发到对应的 {@link MediaCipher} 实现。
 *
 * <p>这是 UI / 上层调用的门面。加密时按文件扩展名嗅探格式；解密时同样按扩展名定位实现，再由实现内部从元数据校验格式。
 *
 * @author ErgouTree
 */
public final class MediaCryptCodec {

    private final Map<MediaFormat, MediaCipher> ciphers = new EnumMap<>(MediaFormat.class);

    public MediaCryptCodec() {
        register(new WavCipher());
        register(new Mp3Cipher());
        register(new Mp4Cipher());
    }

    private void register(MediaCipher cipher) {
        ciphers.put(cipher.format(), cipher);
    }

    /**
     * 加密媒体文件（无进度回调）。格式按 {@code input} 扩展名嗅探。
     */
    public void encrypt(Path input, Path output, byte[] password, MediaCryptOptions options)
            throws MediaCryptException, IOException {
        encrypt(input, output, password, options, MediaProgress.NONE);
    }

    /**
     * 加密媒体文件。格式按 {@code input} 扩展名嗅探。
     *
     * @param progress 进度/取消回调
     * @throws MediaCryptException 无法识别格式 / 容器非法 / 被取消
     */
    public void encrypt(Path input, Path output, byte[] password, MediaCryptOptions options,
                        MediaProgress progress) throws MediaCryptException, IOException {
        resolve(input).encrypt(input, output, password, options, progress);
    }

    /**
     * 解密媒体文件（无进度回调）。格式按 {@code input} 扩展名嗅探。
     */
    public void decrypt(Path input, Path output, byte[] password)
            throws MediaCryptException, IOException {
        decrypt(input, output, password, MediaProgress.NONE);
    }

    /**
     * 解密媒体文件。格式按 {@code input} 扩展名嗅探，并由实现从元数据二次校验。
     *
     * @param progress 进度/取消回调
     * @throws MediaCryptException 无法识别格式 / 密码错误 / 容器损坏 / 被取消
     */
    public void decrypt(Path input, Path output, byte[] password, MediaProgress progress)
            throws MediaCryptException, IOException {
        resolve(input).decrypt(input, output, password, progress);
    }

    /**
     * 校验已加密媒体文件的完整性（不解密输出）。
     *
     * <p>仅在加密时开启了"存储完整性校验"的文件上有效。
     *
     * @param input    加密后的媒体文件
     * @param password 已归一化的密码 UTF-8 字节
     * @param progress 进度 / 取消回调
     * @return true 若完整性校验通过；若文件未存储完整性数据则返回 false
     * @throws MediaCryptException 密码错误、完整性失败或格式不识别
     * @throws IOException         读写错误
     */
    public boolean verifyIntegrity(Path input, byte[] password, MediaProgress progress)
            throws MediaCryptException, IOException {
        return resolve(input).verifyIntegrity(input, password, progress);
    }

    /**
     * 检测文件是否由本工具加密。无法识别格式时返回 false。
     */
    public boolean isEncrypted(Path input) throws IOException {
        MediaFormat format = MediaFormat.fromExtension(input);
        if (format == null) {
            return false;
        }
        return ciphers.get(format).isEncrypted(input);
    }

    /**
     * 该文件扩展名是否属于受支持的音视频格式。
     */
    public boolean isSupported(Path input) {
        return MediaFormat.fromExtension(input) != null;
    }

    private MediaCipher resolve(Path input) throws MediaCryptException {
        MediaFormat format = MediaFormat.fromExtension(input);
        if (format == null) {
            throw new MediaCryptException("无法识别的音视频格式（按扩展名）: " + input.getFileName());
        }
        return ciphers.get(format);
    }
}
