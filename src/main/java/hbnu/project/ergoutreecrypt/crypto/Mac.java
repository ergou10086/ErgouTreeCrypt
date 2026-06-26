package hbnu.project.ergoutreecrypt.crypto;

/**
 * 统一的消息认证码（MAC）接口，屏蔽 BLAKE2b 与 HMAC-SHA3 的差异，
 * 供 {@link CipherSuite} 以一致方式累积密文并产出最终标签。
 *
 * <p>对应原项目中以 {@code hash.Hash} 形式传递的载荷 MAC。
 *
 * @author ErgouTree
 */
public interface Mac {

    /**
     * 向 MAC 追加数据
     */
    void update(byte[] data, int len);

    /**
     * 产出最终 MAC 值
     */
    byte[] doFinal();

    /**
     * 清零内部密钥/状态。
     */
    void close();
}
