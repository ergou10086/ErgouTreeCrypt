package hbnu.project.ergoutreecrypt.imagecrypt;

import hbnu.project.ergoutreecrypt.exception.ErrorKind;
import hbnu.project.ergoutreecrypt.password.PasswordNormalizer;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CharsetEncoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;

/**
 * EGTC-IMG 密码字节的<b>唯一</b>规范化入口。
 *
 * <h3>为什么必须集中</h3>
 * <p>密码只有经过"有效 Unicode 检查 → NFC → UTF-8"这条固定链路，桌面端与 Android 端才能
 * 派生出同一把密钥。若由 JavaFX Controller 或 Android ViewModel 各自调用平台默认编码，
 * 两端在组合字符、代理对与默认字符集不一致时会导出不同密钥，直接破坏"任意端生成、
 * 任意端恢复"的硬约束。
 *
 * <h3>规范化口径</h3>
 * <ol>
 *   <li>拒绝 {@code null} 与空串：空密码在 v1 中表示"未选择密码模式"，应由调用方改用
 *       {@link ImageCryptMode#PUBLIC_RECOVERY}，而不是派生一把空口令密钥；</li>
 *   <li>以 {@link CodingErrorAction#REPORT} 做 UTF-8 编码，未配对的代理对（无效 Unicode）
 *       会立即失败，而不是被替换字符悄悄改写；</li>
 *   <li>先做 NFC 归一化（{@link PasswordNormalizer#normalize(String)}），保证 macOS 的 NFD
 *       输入与 Windows 的 NFC 输入得到相同字节；</li>
 *   <li>不做兼容归一（NFKC/NFKD）、不做大小写折叠、不做空白裁剪，避免降低密码熵。</li>
 * </ol>
 *
 * <p>密码模式<b>不</b>沿用 {@link PasswordNormalizer#candidates(String)} 的多形态尝试：
 * v1 是全新协议，不存在历史卷的 NFD/raw 兼容负担，只接受唯一规范形态。
 *
 * <h3>生命周期</h3>
 * <p>返回的 {@code byte[]} 由调用方负责在 finally 中清零；核心内部在使用完毕后同样清零。
 *
 * @author ErgouTree
 * @since 2026/9/15
 */
public final class ImageCryptPassword {

    private ImageCryptPassword() {
    }

    /**
     * 把口令文本规范化为 EGTC-IMG v1 的 KDF 输入字节。
     *
     * @param password 用户输入的口令文本
     * @return NFC 归一化后的 UTF-8 字节
     * @throws ImageCryptException 口令为 null/空串、含无效 Unicode，或 UTF-8 字节数超过
     *                             {@link ImageCryptProtocol#LIMIT_PASSWORD_BYTES} 上限
     */
    public static byte[] encodeForV1(final String password) throws ImageCryptException {
        if (password == null || password.isEmpty()) {
            throw new ImageCryptException(ErrorKind.INTERNAL_ERROR,
                    "密码保护模式必须提供非空密码；空密码请改用公开恢复模式");
        }
        String normalized = PasswordNormalizer.normalize(password);
        CharsetEncoder encoder = StandardCharsets.UTF_8.newEncoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT);
        try {
            ByteBuffer encoded = encoder.encode(CharBuffer.wrap(normalized));
            byte[] bytes = new byte[encoded.remaining()];
            encoded.get(bytes);
            if (bytes.length > ImageCryptProtocol.LIMIT_PASSWORD_BYTES) {
                throw new ImageCryptException(ErrorKind.INTERNAL_ERROR,
                        "密码超过 " + ImageCryptProtocol.LIMIT_PASSWORD_BYTES + " 字节上限");
            }
            return bytes;
        } catch (CharacterCodingException e) {
            throw new ImageCryptException(ErrorKind.INTERNAL_ERROR,
                    "密码包含无效 Unicode 字符（如未配对的代理对）", e);
        }
    }
}
