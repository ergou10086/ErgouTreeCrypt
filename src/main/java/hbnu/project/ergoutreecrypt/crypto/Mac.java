package hbnu.project.ergoutreecrypt.crypto;

/**
 * 统一的消息认证码（MAC）接口。
 *
 * <p>屏蔽 BLAKE2b 与 HMAC-SHA3 的实现差异，供 {@link CipherSuite} 以一致方式累积密文并产出最终认证标签。
 *
 * @author ErgouTree
 */
public interface Mac {

    /**
     * 向 MAC 累积数据。
     *
     * @param data 输入数据
     * @param len  有效字节数
     */
    void update(byte[] data, int len);

    /**
     * 产出最终的 MAC 认证标签。
     *
     * @return MAC 值（长度取决于具体实现）
     */
    byte[] doFinal();

    /**
     * 清零内部密钥材料与状态，释放后不应再调用其他方法。
     */
    void close();
}
