package hbnu.project.ergoutreecrypt.stego;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/**
 * 元数据头编解码测试。
 *
 * @author ErgouTree
 */
class StegoMetadataTest {

    @Test
    void roundtripWithoutMac() throws Exception {
        byte[] salt = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        byte[] hkdfSalt = new byte[32];
        for (int i = 0; i < 32; i++) hkdfSalt[i] = (byte) i;
        byte[] nonce = new byte[24];
        for (int i = 0; i < 24; i++) nonce[i] = (byte) (i + 100);

        StegoMetadata meta = StegoMetadata.builder()
                .lsbDepth(2)
                .hasMac(false)
                .paranoid(false)
                .channels(3)
                .payloadSize(12345L)
                .fileName("test.txt")
                .salt(salt)
                .hkdfSalt(hkdfSalt)
                .nonce(nonce)
                .build();

        byte[] serialized = meta.toBytes();
        StegoMetadata restored = StegoMetadata.fromBytes(serialized);

        assertEquals(2, restored.lsbDepth());
        assertEquals(false, restored.hasMac());
        assertEquals(false, restored.isParanoid());
        assertEquals(3, restored.channels());
        assertEquals(12345L, restored.payloadSize());
        assertEquals("test.txt", restored.fileName());
        assertArrayEquals(salt, restored.salt());
        assertArrayEquals(hkdfSalt, restored.hkdfSalt());
        assertArrayEquals(nonce, restored.nonce());
    }

    @Test
    void roundtripWithMac() throws Exception {
        byte[] mac = new byte[64];
        for (int i = 0; i < 64; i++) mac[i] = (byte) (i * 3);

        StegoMetadata meta = StegoMetadata.builder()
                .lsbDepth(1)
                .hasMac(true)
                .paranoid(true)
                .channels(3)
                .payloadSize(99999L)
                .fileName("secret.bin")
                .payloadMac(mac)
                .build();

        byte[] serialized = meta.toBytes();
        StegoMetadata restored = StegoMetadata.fromBytes(serialized);

        assertEquals(1, restored.lsbDepth());
        assertTrue(restored.hasMac());
        assertTrue(restored.isParanoid());
        assertEquals(99999L, restored.payloadSize());
        assertEquals("secret.bin", restored.fileName());
        assertArrayEquals(mac, restored.payloadMac());
    }

    @Test
    void badMagicDetected() {
        byte[] garbage = new byte[200];
        assertThrows(ImageStegoException.class, () -> StegoMetadata.fromBytes(garbage));
    }

    @Test
    void tooShort() {
        byte[] shortData = new byte[10];
        assertThrows(ImageStegoException.class, () -> StegoMetadata.fromBytes(shortData));
    }

    @Test
    void unicodeFileName() throws Exception {
        StegoMetadata meta = StegoMetadata.builder()
                .lsbDepth(1)
                .hasMac(false)
                .payloadSize(100)
                .fileName("中文文件名.txt")
                .build();
        byte[] serialized = meta.toBytes();
        StegoMetadata restored = StegoMetadata.fromBytes(serialized);
        assertEquals("中文文件名.txt", restored.fileName());
    }

    @Test
    void headerSizeCalculation() {
        int sizeNoMac = StegoMetadata.headerSize("a.txt", false);
        int sizeWithMac = StegoMetadata.headerSize("a.txt", true);
        assertEquals(64, sizeWithMac - sizeNoMac);
        assertTrue(sizeNoMac > 80);
    }
}
