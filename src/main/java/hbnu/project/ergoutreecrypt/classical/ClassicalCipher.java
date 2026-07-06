package hbnu.project.ergoutreecrypt.classical;

import java.util.Map;

/**
 * 古典密码算法统一接口。
 *
 * <p>所有古典密码实现此接口，提供加密与解密方法。每个实现通过 {@link #getInfo()} 暴露元数据供 UI 使用。
 *
 * @author ErgouTree
 */
public interface ClassicalCipher {

    /**
     * 使用指定参数对明文进行加密。
     *
     * @param plaintext 明文字符串
     * @param params    算法参数，键值对形式
     * @return 密文字符串
     */
    String encrypt(String plaintext, Map<String, String> params);

    /**
     * 使用指定参数对密文进行解密。
     *
     * @param ciphertext 密文字符串
     * @param params     算法参数，键值对形式
     * @return 明文字符串
     */
    String decrypt(String ciphertext, Map<String, String> params);

    /**
     * 返回该算法的元数据信息。
     *
     * @return 包含 id、名称、描述及参数定义的 {@link CipherInfo}
     */
    CipherInfo getInfo();
}
