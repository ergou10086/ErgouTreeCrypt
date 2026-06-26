package hbnu.project.ergoutreecrypt.mediacrypt;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/**
 * {@link MediaMetadata} 序列化/反序列化与边界校验（无需 KDF，纯快速测试）。
 *
 * @author ErgouTree
 */
class MediaMetadataTest {

    private static byte[] seq(int len, int start) {
        byte[] b = new byte[len];
        for (int i = 0; i < len; i++) {
            b[i] = (byte) (start + i);
        }
        return b;
    }

    @Test
    void roundTripWithMac() throws Exception {
        byte[] salt = seq(MediaMetadata.SALT_LEN, 1);
        byte[] hkdf = seq(MediaMetadata.HKDF_SALT_LEN, 50);
        byte[] nonce = seq(MediaMetadata.NONCE_LEN, 100);
        byte[] mac = seq(MediaMetadata.MAC_LEN, 7);

        MediaMetadata m = new MediaMetadata(MediaFormat.WAV, MediaCryptProfile.W_FULL,
                true, salt, hkdf, nonce, mac);
        byte[] bytes = m.toBytes();
        assertEquals(MediaMetadata.BASE_LEN + MediaMetadata.MAC_LEN, bytes.length);

        MediaMetadata parsed = MediaMetadata.fromBytes(bytes);
        assertEquals(MediaFormat.WAV, parsed.format());
        assertEquals(MediaCryptProfile.W_FULL, parsed.profile());
        assertTrue(parsed.paranoid());
        assertTrue(parsed.hasIntegrity());
        assertArrayEquals(salt, parsed.salt());
        assertArrayEquals(hkdf, parsed.hkdfSalt());
        assertArrayEquals(nonce, parsed.nonce());
        assertArrayEquals(mac, parsed.plainMac());
    }

    @Test
    void roundTripWithoutMac() throws Exception {
        MediaMetadata m = new MediaMetadata(MediaFormat.MP3, MediaCryptProfile.M_BODY,
                false, seq(16, 0), seq(32, 0), seq(24, 0), null);
        byte[] bytes = m.toBytes();
        assertEquals(MediaMetadata.BASE_LEN, bytes.length);

        MediaMetadata parsed = MediaMetadata.fromBytes(bytes);
        assertEquals(MediaFormat.MP3, parsed.format());
        assertEquals(MediaCryptProfile.M_BODY, parsed.profile());
        assertFalse(parsed.paranoid());
        assertFalse(parsed.hasIntegrity());
        assertNull(parsed.plainMac());
    }

    @Test
    void rejectsBadMagic() {
        byte[] bytes = new byte[MediaMetadata.BASE_LEN];
        assertFalse(MediaMetadata.hasMagic(bytes));
        assertThrows(MediaCryptException.class, () -> MediaMetadata.fromBytes(bytes));
    }

    @Test
    void rejectsTooShort() {
        byte[] bytes = new byte[10];
        assertThrows(MediaCryptException.class, () -> MediaMetadata.fromBytes(bytes));
    }

    @Test
    void rejectsProfileFormatMismatch() {
        // MP3 档位配 WAV 格式应被拒绝。
        assertThrows(IllegalArgumentException.class, () ->
                new MediaMetadata(MediaFormat.WAV, MediaCryptProfile.M_BODY, false,
                        seq(16, 0), seq(32, 0), seq(24, 0), null));
    }

    @Test
    void formatAndProfileEnumStability() {
        // formatId / profile code 不得变动（向后兼容关键）。
        assertEquals(1, MediaFormat.WAV.formatId());
        assertEquals(2, MediaFormat.MP3.formatId());
        assertEquals(3, MediaFormat.MP4.formatId());
        assertEquals(10, MediaCryptProfile.W_FULL.code());
        assertEquals(20, MediaCryptProfile.M_BODY.code());
        assertEquals(30, MediaCryptProfile.V_MDAT.code());
    }
}
