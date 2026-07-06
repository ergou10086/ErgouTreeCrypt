package hbnu.project.ergoutreecrypt.classical;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;

/**
 * 异或密码（XOR Cipher）。
 *
 * <p>一种字节级密码，将文本的 UTF-8 字节与密钥字节逐字节异或。
 * 加密结果为 Base64 编码字符串，解密时从 Base64 解码后再异或还原。
 * 支持所有 Unicode 字符（通过 UTF-8 编码 → XOR → Base64 路径）。
 *
 * <p>参数：
 * <ul>
 *   <li>{@code key} — 异或密钥字符串，默认为空</li>
 * </ul>
 *
 * @author ErgouTree
 */
public final class XorCipher implements ClassicalCipher {

    private static final CipherInfo INFO = new CipherInfo(
            "xor",
            "cc.xor.name",
            "cc.xor.desc",
            List.of(new CipherInfo.ParamDef("key", "cc.param.key", "text", ""))
    );

    @Override
    public String encrypt(final String plaintext, final Map<String, String> params) {
        String key = getKey(params);
        if (plaintext == null || plaintext.isEmpty()) {
            return "";
        }
        byte[] data = plaintext.getBytes(StandardCharsets.UTF_8);
        byte[] keyBytes = keyBytes(key, data.length);
        byte[] result = xor(data, keyBytes);
        return Base64.getEncoder().encodeToString(result);
    }

    @Override
    public String decrypt(final String ciphertext, final Map<String, String> params) {
        String key = getKey(params);
        if (ciphertext == null || ciphertext.isEmpty()) {
            return "";
        }
        byte[] data;
        try {
            data = Base64.getDecoder().decode(ciphertext);
        } catch (IllegalArgumentException e) {
            // 输入不是有效 Base64，尝试直接当原始异或结果处理
            data = ciphertext.getBytes(StandardCharsets.ISO_8859_1);
        }
        byte[] keyBytes = keyBytes(key, data.length);
        byte[] result = xor(data, keyBytes);
        return new String(result, StandardCharsets.UTF_8);
    }

    @Override
    public CipherInfo getInfo() {
        return INFO;
    }

    /**
     * 从参数中获取异或密钥。
     *
     * @param params 算法参数
     * @return 密钥字符串
     */
    private static String getKey(final Map<String, String> params) {
        if (params != null && params.containsKey("key")) {
            return params.get("key");
        }
        return "";
    }

    /**
     * 生成与数据等长的密钥字节数组，循环使用密钥字符串的 UTF-8 字节。
     *
     * @param key    密钥字符串
     * @param length 需要的长度
     * @return 密钥字节数组
     */
    private static byte[] keyBytes(final String key, final int length) {
        byte[] keyUtf8 = (key != null && !key.isEmpty())
                ? key.getBytes(StandardCharsets.UTF_8)
                : new byte[]{0};
        if (keyUtf8.length == 0) {
            return new byte[length];
        }
        byte[] result = new byte[length];
        for (int i = 0; i < length; i++) {
            result[i] = keyUtf8[i % keyUtf8.length];
        }
        return result;
    }

    /**
     * 逐字节异或。
     *
     * @param data    数据字节
     * @param keyBytes 密钥字节（需与数据等长）
     * @return 异或结果
     */
    private static byte[] xor(final byte[] data, final byte[] keyBytes) {
        byte[] result = new byte[data.length];
        for (int i = 0; i < data.length; i++) {
            result[i] = (byte) (data[i] ^ keyBytes[i]);
        }
        return result;
    }
}
