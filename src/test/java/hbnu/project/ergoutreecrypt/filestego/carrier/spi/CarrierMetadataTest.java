package hbnu.project.ergoutreecrypt.filestego.carrier.spi;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import hbnu.project.ergoutreecrypt.filestego.api.CarrierException;

import org.junit.jupiter.api.Test;

/**
 * CarrierMetadata 编解码测试。
 *
 * @author ErgouTree
 */
class CarrierMetadataTest {

    // ---- 往返测试 ----

    @Test
    void roundtripBasic() throws Exception {
        byte[] salt = fillBytes(16, 1);
        byte[] hkdfSalt = fillBytes(32, 50);
        byte[] nonce = fillBytes(24, 100);

        byte flags = CarrierMetadata.buildFlags(false, true, false);

        CarrierMetadata meta = new CarrierMetadata(1024L, flags,
                salt, hkdfSalt, nonce, null, null);

        byte[] serialized = meta.toBytes();
        CarrierMetadata restored = CarrierMetadata.fromBytes(serialized);

        assertEquals(1024L, restored.payloadSize());
        assertFalse(restored.isParanoid());
        assertTrue(restored.hasIntegrity());
        assertFalse(restored.isStealth());
        assertArrayEquals(salt, restored.salt());
        assertArrayEquals(hkdfSalt, restored.hkdfSalt());
        assertArrayEquals(nonce, restored.nonce());
    }

    @Test
    void roundtripParanoid() throws Exception {
        byte[] salt = fillBytes(16, 10);
        byte[] hkdfSalt = fillBytes(32, 60);
        byte[] nonce = fillBytes(24, 110);
        byte[] serpentIv = fillBytes(16, 200);

        byte flags = CarrierMetadata.buildFlags(true, true, false);

        CarrierMetadata meta = new CarrierMetadata(99999L, flags,
                salt, hkdfSalt, nonce, serpentIv, null);

        byte[] serialized = meta.toBytes();
        CarrierMetadata restored = CarrierMetadata.fromBytes(serialized);

        assertEquals(99999L, restored.payloadSize());
        assertTrue(restored.isParanoid());
        assertTrue(restored.hasIntegrity());
        assertArrayEquals(serpentIv, restored.serpentIv());
    }

    @Test
    void roundtripStealth() throws Exception {
        byte[] salt = fillBytes(16, 20);
        byte[] hkdfSalt = fillBytes(32, 70);
        byte[] nonce = fillBytes(24, 120);
        byte[] stealthSalt = fillBytes(16, 250);

        byte flags = CarrierMetadata.buildFlags(false, true, true);

        CarrierMetadata meta = new CarrierMetadata(5000L, flags,
                salt, hkdfSalt, nonce, null, stealthSalt);

        byte[] serialized = meta.toBytes();
        CarrierMetadata restored = CarrierMetadata.fromBytes(serialized);

        assertEquals(5000L, restored.payloadSize());
        assertTrue(restored.isStealth());
        assertArrayEquals(stealthSalt, restored.stealthSalt());
        assertTrue(restored.serpentIv() == null);
    }

    @Test
    void roundtripParanoidAndStealth() throws Exception {
        byte[] salt = fillBytes(16, 30);
        byte[] hkdfSalt = fillBytes(32, 80);
        byte[] nonce = fillBytes(24, 130);
        byte[] serpentIv = fillBytes(16, 210);
        byte[] stealthSalt = fillBytes(16, 255);

        byte flags = CarrierMetadata.buildFlags(true, true, true);

        CarrierMetadata meta = new CarrierMetadata(Long.MAX_VALUE, flags,
                salt, hkdfSalt, nonce, serpentIv, stealthSalt);

        byte[] serialized = meta.toBytes();
        CarrierMetadata restored = CarrierMetadata.fromBytes(serialized);

        assertEquals(Long.MAX_VALUE, restored.payloadSize());
        assertTrue(restored.isParanoid());
        assertTrue(restored.hasIntegrity());
        assertTrue(restored.isStealth());
        assertArrayEquals(serpentIv, restored.serpentIv());
        assertArrayEquals(stealthSalt, restored.stealthSalt());
    }

    // ---- 魔数检测 ----

    @Test
    void startsWithMagic() {
        byte[] meta = new CarrierMetadata(100L,
                CarrierMetadata.buildFlags(false, false, false),
                fillBytes(16, 0), fillBytes(32, 0), fillBytes(24, 0),
                null, null).toBytes();

        assertTrue(CarrierMetadata.startsWithMagic(meta));
    }

    @Test
    void startsWithMagicNotMatch() {
        byte[] garbage = "Not a valid metadata block".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        assertFalse(CarrierMetadata.startsWithMagic(garbage));
    }

    @Test
    void startsWithMagicTooShort() {
        byte[] shortData = new byte[]{0x45, 0x47}; // Only "EG"
        assertFalse(CarrierMetadata.startsWithMagic(shortData));
    }

    // ---- 异常测试 ----

    @Test
    void badMagicDetected() {
        byte[] garbage = new byte[200];
        // 随机数据不应包含 EGFS 魔数
        assertThrows(CarrierException.class, () -> CarrierMetadata.fromBytes(garbage));
    }

    @Test
    void tooShort() {
        byte[] shortData = new byte[10];
        assertThrows(CarrierException.class, () -> CarrierMetadata.fromBytes(shortData));
    }

    @Test
    void wrongVersion() throws Exception {
        // 构造一个有效魔数但版本号不对的数据
        byte[] valid = new CarrierMetadata(100L,
                CarrierMetadata.buildFlags(false, false, false),
                fillBytes(16, 0), fillBytes(32, 0), fillBytes(24, 0),
                null, null).toBytes();
        // 修改版本号（偏移 4 处）
        valid[4] = (byte) 99;

        byte[] finalValid = valid;
        assertThrows(CarrierException.class, () -> CarrierMetadata.fromBytes(finalValid));
    }

    // ---- Flag 构建 ----

    @Test
    void buildFlagsAllFalse() {
        byte flags = CarrierMetadata.buildFlags(false, false, false);
        assertEquals(0, flags);
    }

    @Test
    void buildFlagsParanoid() {
        byte flags = CarrierMetadata.buildFlags(true, false, false);
        assertEquals(0x01, flags);
    }

    @Test
    void buildFlagsAllTrue() {
        byte flags = CarrierMetadata.buildFlags(true, true, true);
        assertEquals(0x07, flags); // 0x01 | 0x02 | 0x04
    }

    // ---- 大小计算 ----

    @Test
    void totalSizeBasic() {
        int size = CarrierMetadata.totalSize(false, false);
        // 4+1+8+1+16+32+24+8 = 94
        assertEquals(94, size);
    }

    @Test
    void totalSizeParanoid() {
        int size = CarrierMetadata.totalSize(true, false);
        assertEquals(94 + 16, size);
    }

    @Test
    void totalSizeStealth() {
        int size = CarrierMetadata.totalSize(false, true);
        assertEquals(94 + 16, size);
    }

    @Test
    void totalSizeBoth() {
        int size = CarrierMetadata.totalSize(true, true);
        assertEquals(94 + 16 + 16, size);
    }

    // ---- 辅助方法 ----

    private static byte[] fillBytes(final int length, final int startValue) {
        byte[] b = new byte[length];
        for (int i = 0; i < length; i++) {
            b[i] = (byte) (startValue + i);
        }
        return b;
    }
}
