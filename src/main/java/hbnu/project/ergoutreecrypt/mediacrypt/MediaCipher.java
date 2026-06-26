package hbnu.project.ergoutreecrypt.mediacrypt;

import java.io.IOException;
import java.nio.file.Path;

/**
 * 单一媒体格式的加解密器接口。
 *
 * <p>每种格式（WAV/MP3/MP4）实现一个 {@code MediaCipher}，负责：
 * <ul>
 *   <li>解析容器、定位可加密 payload 区间（{@link ByteRange}）；</li>
 *   <li>读写格式专属的元数据载体（WAV chunk / MP3 PRIV 帧 / MP4 uuid box）；</li>
 *   <li>对 payload 区间做等长流加密，保持容器结构与文件可播放性。</li>
 * </ul>
 *
 * <p>具体加解密的通用流程（密钥派生、流式 XOR、完整性 MAC）由 {@link AbstractMediaCipher} 模板实现，子类只需提供格式相关的解析与元数据读写。
 *
 * @author ErgouTree
 */
public interface MediaCipher {

    /**
     * 该实现处理的媒体格式。
     */
    MediaFormat format();

    /**
     * 加密：读取 {@code input} 媒体文件，输出格式保持加密后的合法媒体文件到 {@code output}。
     *
     * @param input    源媒体文件
     * @param output   输出文件（将被覆盖）
     * @param password 已归一化的密码 UTF-8 字节（调用方负责清零）
     * @param options  加密选项
     * @param progress 进度/取消回调（{@code null} 视为 {@link MediaProgress#NONE}）
     * @throws MediaCryptException 容器非法、不支持的变体或被取消
     * @throws IOException         读写错误
     */
    void encrypt(Path input, Path output, byte[] password, MediaCryptOptions options,
                 MediaProgress progress) throws MediaCryptException, IOException;

    /**
     * 解密：从 {@code input} 读取元数据并还原原始媒体到 {@code output}。
     *
     * @param input    加密后的媒体文件
     * @param output   输出文件（将被覆盖）
     * @param password 已归一化的密码 UTF-8 字节（调用方负责清零）
     * @param progress 进度/取消回调（{@code null} 视为 {@link MediaProgress#NONE}）
     * @throws MediaCryptException 非本工具加密、密码错误（完整性校验失败）、容器损坏或被取消
     * @throws IOException         读写错误
     */
    void decrypt(Path input, Path output, byte[] password, MediaProgress progress)
            throws MediaCryptException, IOException;

    /**
     * 检测文件是否由本工具加密（按格式专属载体探测元数据魔数）。
     *
     * @return true 若识别到本工具的加密元数据
     */
    boolean isEncrypted(Path input) throws IOException;

    /**
     * 校验已加密媒体文件的完整性（不解密输出）。
     *
     * <p>仅在加密时开启了 {@code storeIntegrity} 的文件上有效；
     * 若未存储完整性数据则返回 {@code false}。
     *
     * <p>默认实现返回 {@code false}（子类可覆写以提供真实校验）。
     *
     * @param input    加密后的媒体文件
     * @param password 已归一化的密码 UTF-8 字节
     * @param progress 进度 / 取消回调
     * @return true 若完整性校验通过
     * @throws MediaCryptException 非本工具加密、密码错误、容器损坏
     * @throws IOException         读写错误
     */
    default boolean verifyIntegrity(Path input, byte[] password, MediaProgress progress)
            throws MediaCryptException, IOException {
        return false;
    }
}
