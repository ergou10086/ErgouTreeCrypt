package hbnu.project.ergoutreecrypt.crypto.fast;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.RegistryConfiguration;
import com.google.crypto.tink.StreamingAead;
import com.google.crypto.tink.streamingaead.AesGcmHkdfStreamingKey;
import com.google.crypto.tink.streamingaead.PredefinedStreamingAeadParameters;
import com.google.crypto.tink.streamingaead.StreamingAeadConfig;
import com.google.crypto.tink.util.SecretBytes;

import hbnu.project.ergoutreecrypt.header.FastHeader;
import hbnu.project.ergoutreecrypt.header.FastHeaderReaderWriter;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;

/** 唯一的 Tink 密钥导入边界，固定 AES256、RAW 输出及 1 MiB 密文分段。 */
public final class FastStreamingAeadFactory {
    private static boolean registered;

    /** 禁止实例化工具类。 */
    private FastStreamingAeadFactory() {}

    /**
     * 使用官方公共 API 导入每文件子密钥，不保存或序列化明文 keyset。
     *
     * @param key 32 字节每文件流子密钥
     * @return 官方认证流实例，其内部密钥副本由 Tink 管理
     * @throws GeneralSecurityException 初始化失败
     */
    @AccessesPartialKey
    public static StreamingAead create(byte[] key) throws GeneralSecurityException {
        if (key == null || key.length != 32)
            throw new GeneralSecurityException("FAST 流密钥必须为 32 字节");
        register();
        var imported =
                AesGcmHkdfStreamingKey.create(
                        PredefinedStreamingAeadParameters.AES256_GCM_HKDF_1MB,
                        SecretBytes.copyFrom(key, InsecureSecretKeyAccess.get()));
        return KeysetHandle.newBuilder()
                .addEntry(KeysetHandle.importKey(imported).withFixedId(1).makePrimary())
                .build()
                .getPrimitive(RegistryConfiguration.get(), StreamingAead.class);
    }

    /**
     * 幂等注册官方流原语，失败时不标记为完成。
     *
     * @throws GeneralSecurityException 注册失败
     */
    private static synchronized void register() throws GeneralSecurityException {
        if (!registered) {
            StreamingAeadConfig.register();
            registered = true;
        }
    }

    /**
     * 将精确的完整外头绑定至载荷，不重序列化解析结果。
     *
     * @param header 结构有效且已计算 HMAC 的外头
     * @return 协议域与完整 160 字节头的拼接
     */
    public static byte[] associatedData(FastHeader header) {
        byte[] domain = FastHeaderReaderWriter.PAYLOAD_DOMAIN.getBytes(StandardCharsets.US_ASCII);
        return ByteBuffer.allocate(domain.length + FastHeaderReaderWriter.HEADER_LENGTH)
                .put(domain)
                .put(header.bytes())
                .array();
    }
}
