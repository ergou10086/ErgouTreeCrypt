package hbnu.project.ergoutreecrypt.imagecrypt;

import hbnu.project.ergoutreecrypt.crypto.RandomBytes;

/**
 * EGTC-IMG 随机字节来源。
 *
 * <p>协议需要每文件独立的 argon2Salt、hkdfSalt、nonce、公开模式主密钥，以及画布尾部
 * 的展示填充。生产路径<b>只能</b>使用 {@link #secure()}；测试路径通过包内可见的确定性
 * 实现注入固定字节，从而把协议字段与密钥中间值冻结成可复现的黄金向量。
 *
 * <p>注入点不经过 {@code ImageCryptCodec} 的公开 API，因此 UI 层无法替换随机源。
 *
 * @author ErgouTree
 * @since 2026/9/15
 */
public interface ImageCryptRandomSource {

    /**
     * 返回使用 {@link java.security.SecureRandom} 的生产实现。
     *
     * @return 密码学安全随机源
     */
    static ImageCryptRandomSource secure() {
        return RandomBytes::generate;
    }

    /**
     * 生成指定长度的随机字节。
     *
     * @param length 需要的字节数
     * @return 长度为 {@code length} 的随机数组
     */
    byte[] nextBytes(int length);
}
