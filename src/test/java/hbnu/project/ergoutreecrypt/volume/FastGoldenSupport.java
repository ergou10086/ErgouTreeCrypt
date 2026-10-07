package hbnu.project.ergoutreecrypt.volume;

import hbnu.project.ergoutreecrypt.crypto.Argon2Kdf;
import hbnu.project.ergoutreecrypt.crypto.SecureZero;
import hbnu.project.ergoutreecrypt.crypto.fast.FastKdfPolicy;
import hbnu.project.ergoutreecrypt.header.FastHeaderReaderWriter;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Properties;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;

/** 用独立 Python 黄金向量交叉验证两端官方库及冻结字节格式。 */
public final class FastGoldenSupport {
    private FastGoldenSupport() { }

    /**
     * 从同一向量验证密码编码、Argon2、HKDF、HMAC、头和完整 Tink 流。
     * @param input 黄金属性文件输入流
     * @throws Exception 任一中间值或明文不一致
     */
    public static void verify(InputStream input) throws Exception {
        Properties values = new Properties(); values.load(new InputStreamReader(input, StandardCharsets.UTF_8));
        byte[] password = FastKdfPolicy.encodePassword(new String(hex(values,"password.raw.utf8"),StandardCharsets.UTF_8));
        equal(hex(values,"password.nfc.utf8"), password);
        byte[] master = Argon2Kdf.deriveKey(password, hex(values,"argon.salt"), false,65536,3,4);
        byte[] headerKey = null, streamKey = null;
        try {
            equal(hex(values,"master"),master);
            headerKey = hkdf(master,hex(values,"hkdf.salt"),FastHeaderReaderWriter.HEADER_KEY_INFO);
            streamKey = hkdf(master,hex(values,"hkdf.salt"),FastHeaderReaderWriter.STREAM_KEY_INFO);
            equal(hex(values,"header.key"),headerKey); equal(hex(values,"stream.key"),streamKey);
            byte[] unsigned = FastHeaderReaderWriter.unsignedHeader(hex(values,"plaintext").length,
                    hex(values,"argon.salt"),hex(values,"hkdf.salt"));
            equal(hex(values,"unsigned"),unsigned);
            var mac = javax.crypto.Mac.getInstance("HmacSHA256");
            mac.init(new javax.crypto.spec.SecretKeySpec(headerKey,"HmacSHA256"));
            mac.update(FastHeaderReaderWriter.HEADER_DOMAIN.getBytes(StandardCharsets.US_ASCII));
            byte[] tag = mac.doFinal(unsigned); equal(hex(values,"header.mac"),tag);
            var header = FastHeaderReaderWriter.withMac(unsigned,tag); equal(hex(values,"header"),header.bytes());
            byte[] container = hex(values,"container");
            if (container.length != FastHeaderReaderWriter.containerLength(header.plaintextLength())) {
                throw new AssertionError("黄金向量长度公式不同");
            }
            var stream = new ByteArrayInputStream(container); FastHeaderReaderWriter.read(stream);
            try (var plaintext = FastPrototypeSupport.primitive(streamKey).newDecryptingStream(stream,hex(values,"aad"))) {
                equal(hex(values,"plaintext"),plaintext.readAllBytes());
            }
        } finally { SecureZero.zeroAll(password,master,headerKey,streamKey); }
    }

    /**
     * 对照官方 HKDF 实现，生产封装另由 P2 测试覆盖。
     * @param key 主密钥
     * @param salt 盐值
     * @param info 域标签
     * @return 32 字节输出
     */
    private static byte[] hkdf(byte[] key, byte[] salt, String info) {
        var generator = new HKDFBytesGenerator(new SHA256Digest());
        generator.init(new HKDFParameters(key,salt,info.getBytes(StandardCharsets.US_ASCII)));
        byte[] out = new byte[32]; generator.generateBytes(out,0,out.length); return out;
    }

    /**
     * 读取十六进制字段。
     * @param values 属性
     * @param key 字段名
     * @return 解码字节
     */
    private static byte[] hex(Properties values, String key) { return HexFormat.of().parseHex(values.getProperty(key)); }

    /**
     * 比较测试值。
     * @param expected 独立生成的期望值
     * @param actual Java 库结果
     */
    private static void equal(byte[] expected, byte[] actual) {
        if (!Arrays.equals(expected,actual)) throw new AssertionError("黄金向量不一致");
    }
}
