package hbnu.project.ergoutreecrypt.filestego.carrier.spi;

import hbnu.project.ergoutreecrypt.filestego.api.Argon2Params;
import hbnu.project.ergoutreecrypt.filestego.api.CarrierException;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * CarrierMetadata Argon2 参数覆写（RESERVED 字段）测试。
 *
 * <p>验证：参数往返（含 paranoid/stealth 可选字段组合下的偏移）、
 * 全零字段向后兼容（默认参数）、非法组合拒绝、旧格式字节布局不变。
 *
 * @author ErgouTree
 * @since 2026/8/14
 */
class CarrierMetadataArgon2ParamsTest {

    private static final Argon2Params BALANCED = new Argon2Params(256 * 1024, 3, 4);
    private static final Argon2Params LIGHT = new Argon2Params(64 * 1024, 2, 2);

    /**
     * 填充字节。
     */
    private static byte[] fill(final int len, final int seed) {
        byte[] b = new byte[len];
        for (int i = 0; i < len; i++) {
            b[i] = (byte) (seed + i);
        }
        return b;
    }

    /**
     * 普通模式参数往返。
     */
    @Test
    void roundtripNormal() throws Exception {
        CarrierMetadata meta = new CarrierMetadata(1000, (byte) 0,
                fill(16, 1), fill(32, 2), fill(24, 3), null, null, BALANCED);
        CarrierMetadata parsed = CarrierMetadata.fromBytes(meta.toBytes());

        assertEquals(1000, parsed.payloadSize());
        assertEquals(BALANCED, parsed.argon2Params());
    }

    /**
     * paranoid + stealth + 参数组合往返（RESERVED 位于可选字段之后，验证偏移正确）。
     */
    @Test
    void roundtripParanoidStealthWithParams() throws Exception {
        CarrierMetadata meta = new CarrierMetadata(2000,
                CarrierMetadata.buildFlags(true, true, true),
                fill(16, 1), fill(32, 2), fill(24, 3), fill(16, 4), fill(16, 5), LIGHT);
        CarrierMetadata parsed = CarrierMetadata.fromBytes(meta.toBytes());

        assertEquals(2000, parsed.payloadSize());
        assertEquals(LIGHT, parsed.argon2Params());
        assertEquals(CarrierMetadata.totalSize(true, true), meta.toBytes().length);
    }

    /**
     * 无覆写（null）时序列化为全零字段，与旧格式字节一致；解析结果为 null（默认参数）。
     */
    @Test
    void legacyZeroFieldCompatible() throws Exception {
        CarrierMetadata meta = new CarrierMetadata(3000, (byte) 0,
                fill(16, 1), fill(32, 2), fill(24, 3), null, null);
        byte[] raw = meta.toBytes();

        // 旧格式固定 94 字节，尾部 8 字节全零
        assertEquals(CarrierMetadata.totalSize(false, false), raw.length);
        for (int i = raw.length - 8; i < raw.length; i++) {
            assertEquals(0, raw[i], "无覆写时 RESERVED 字段应为全零");
        }

        CarrierMetadata parsed = CarrierMetadata.fromBytes(raw);
        assertNull(parsed.argon2Params(), "全零字段应解析为 null（使用默认参数）");
    }

    /**
     * 非法组合：memoryKiB 非零但 passes 为 0 → 拒绝。
     */
    @Test
    void invalidParamsRejected() {
        CarrierMetadata meta = new CarrierMetadata(1000, (byte) 0,
                fill(16, 1), fill(32, 2), fill(24, 3), null, null,
                new Argon2Params(64, 0, 2));
        assertThrows(CarrierException.class,
                () -> CarrierMetadata.fromBytes(meta.toBytes()));
    }

    /**
     * 非法组合：memoryKiB 过小（< 8）→ 拒绝。
     */
    @Test
    void invalidMemoryRejected() {
        CarrierMetadata meta = new CarrierMetadata(1000, (byte) 0,
                fill(16, 1), fill(32, 2), fill(24, 3), null, null,
                new Argon2Params(4, 2, 2));
        assertThrows(CarrierException.class,
                () -> CarrierMetadata.fromBytes(meta.toBytes()));
    }

    /**
     * 参数往返不改变非 RESERVED 区域的字节（与无覆写版本前缀一致）。
     */
    @Test
    void prefixUnchangedWithParams() throws Exception {
        CarrierMetadata without = new CarrierMetadata(500, (byte) 0,
                fill(16, 1), fill(32, 2), fill(24, 3), null, null);
        CarrierMetadata with = new CarrierMetadata(500, (byte) 0,
                fill(16, 1), fill(32, 2), fill(24, 3), null, null, BALANCED);

        byte[] rawWithout = without.toBytes();
        byte[] rawWith = with.toBytes();
        assertArrayEquals(java.util.Arrays.copyOf(rawWithout, rawWithout.length - 8),
                java.util.Arrays.copyOf(rawWith, rawWith.length - 8),
                "参数覆写只应改变 RESERVED 字段区域");
    }
}
