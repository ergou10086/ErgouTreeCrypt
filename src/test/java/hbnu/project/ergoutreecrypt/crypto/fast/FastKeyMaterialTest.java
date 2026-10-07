package hbnu.project.ergoutreecrypt.crypto.fast;

import static org.junit.jupiter.api.Assertions.*;

import hbnu.project.ergoutreecrypt.header.FastHeaderReaderWriter;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.util.HexFormat;
import java.util.Properties;

/** 验证生产密钥封装与独立向量一致，关闭后不能继续使用。 */
final class FastKeyMaterialTest {
    /** @throws Exception 派生或认证失败 */
    @Test
    void productionScheduleMatchesIndependentVector() throws Exception {
        var p = new Properties();
        try (var in = getClass().getResourceAsStream("/fast/v1/golden.properties")) {
            p.load(in);
        }
        var hex = HexFormat.of();
        var header = FastHeaderReaderWriter.parse(hex.parseHex(p.getProperty("header")));
        var keys = FastKeyMaterial.derive("é-极速🔐", header.argonSalt(), header.hkdfSalt(), null);
        try {
            assertArrayEquals(
                    hex.parseHex(p.getProperty("header.mac")),
                    keys.headerMac(header.authenticatedBytes()));
            assertTrue(keys.authenticate(header));
            assertArrayEquals(
                    hex.parseHex(p.getProperty("aad")),
                    FastStreamingAeadFactory.associatedData(header));
            byte[] container = hex.parseHex(p.getProperty("container"));
            try (var plain =
                    keys.streamingAead()
                            .newDecryptingStream(
                                    new ByteArrayInputStream(
                                            container, 160, container.length - 160),
                                    FastStreamingAeadFactory.associatedData(header))) {
                assertArrayEquals(hex.parseHex(p.getProperty("plaintext")), plain.readAllBytes());
            }
        } finally {
            keys.close();
        }
        assertThrows(IllegalStateException.class, keys::streamingAead);
        keys.close();
    }
}
