package hbnu.project.ergoutreecrypt.volume;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.RegistryConfiguration;
import com.google.crypto.tink.StreamingAead;
import com.google.crypto.tink.streamingaead.AesGcmHkdfStreamingKey;
import com.google.crypto.tink.streamingaead.PredefinedStreamingAeadParameters;
import com.google.crypto.tink.streamingaead.StreamingAeadConfig;
import com.google.crypto.tink.util.SecretBytes;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.util.Arrays;

/** P0 专用的官方 Tink 原型，供桌面 JVM 和 Android ART 使用相同测试入口。 */
public final class FastPrototypeSupport {
    private FastPrototypeSupport() { }

    /**
     * 从测试密钥创建不带前缀的 1 MiB 分段流。
     * @param key 16 或 32 字节密钥
     * @return 官方流式认证加密实例
     * @throws GeneralSecurityException 初始化失败
     */
    public static StreamingAead primitive(byte[] key) throws GeneralSecurityException {
        StreamingAeadConfig.register();
        var parameters = key.length == 16
                ? PredefinedStreamingAeadParameters.AES128_GCM_HKDF_1MB
                : PredefinedStreamingAeadParameters.AES256_GCM_HKDF_1MB;
        var imported = AesGcmHkdfStreamingKey.create(parameters,
                SecretBytes.copyFrom(key, InsecureSecretKeyAccess.get()));
        return KeysetHandle.newBuilder()
                .addEntry(KeysetHandle.importKey(imported).withFixedId(1).makePrimary())
                .build().getPrimitive(RegistryConfiguration.get(), StreamingAead.class);
    }

    /**
     * 验证完整流、RAW 内部头、AAD 和尾随字节检查，任一失败均抛出异常。
     * @throws Exception 测试失败
     */
    public static void smoke() throws Exception {
        byte[] plain = new byte[(1 << 20) + 17];
        new java.util.Random(38).nextBytes(plain);
        for (int keySize : new int[]{16, 32}) {
            StreamingAead aead = primitive(new byte[keySize]);
            byte[] aad = {1, 2, 3};
            var bytes = new ByteArrayOutputStream();
            try (OutputStream out = aead.newEncryptingStream(bytes, aad)) { out.write(plain); }
            byte[] encrypted = bytes.toByteArray();
            if ((encrypted[0] & 255) != keySize + 8) throw new AssertionError("RAW 内部头长度错误");
            try (InputStream in = aead.newDecryptingStream(new ByteArrayInputStream(encrypted), aad)) {
                if (!Arrays.equals(plain, in.readAllBytes())) throw new AssertionError("完整流往返失败");
            }
            for (byte[] invalid : new byte[][]{Arrays.copyOf(encrypted, encrypted.length - 1),
                    Arrays.copyOf(encrypted, encrypted.length + 1)}) {
                boolean rejected = false;
                try (InputStream in = aead.newDecryptingStream(new ByteArrayInputStream(invalid), aad)) {
                    in.transferTo(OutputStream.nullOutputStream());
                } catch (java.io.IOException e) { rejected = true; }
                if (!rejected) throw new AssertionError("未拒绝截断或尾随数据");
            }
            boolean rejected = false;
            try (InputStream in = aead.newDecryptingStream(new ByteArrayInputStream(encrypted), new byte[]{4})) {
                in.transferTo(OutputStream.nullOutputStream());
            } catch (java.io.IOException e) { rejected = true; }
            if (!rejected) throw new AssertionError("未认证 AAD");
        }
    }
}
