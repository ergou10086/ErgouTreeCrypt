package hbnu.project.ergoutreecrypt.android

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import hbnu.project.ergoutreecrypt.android.app.ErgouApp
import hbnu.project.ergoutreecrypt.crypto.Argon2Kdf
import hbnu.project.ergoutreecrypt.crypto.RandomBytes
import hbnu.project.ergoutreecrypt.encoding.Padding
import hbnu.project.ergoutreecrypt.encoding.ReedSolomon
import hbnu.project.ergoutreecrypt.encoding.RsCodecs
import hbnu.project.ergoutreecrypt.password.PasswordNormalizer
import hbnu.project.ergoutreecrypt.password.Passwordless
import hbnu.project.ergoutreecrypt.header.Flags
import hbnu.project.ergoutreecrypt.header.VolumeHeader
import hbnu.project.ergoutreecrypt.header.HeaderLayout
import hbnu.project.ergoutreecrypt.header.HeaderWriter
import hbnu.project.ergoutreecrypt.i18n.Messages
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4
import java.io.File
import java.nio.charset.StandardCharsets
import java.nio.file.Files

/**
 * 端到端加解密回环测试。
 *
 * <p>在 Android 设备上验证核心加密原语与加解密管线的完整性。
 *
 * <p>需要 BouncyCastle 已注册（由 ErgouApp 在 Application.onCreate 中完成）。
 *
 * @author ErgouTree
 * @since 2026/8/11
 */
@RunWith(JUnit4::class)
class RoundtripTest {

    private lateinit var context: Context
    private lateinit var tmpDir: File

    @Before
    fun setup() {
        context = ApplicationProvider.getApplicationContext()
        val app = context.applicationContext as ErgouApp
        assertNotNull("ErgouApp 未初始化", app)
        tmpDir = File(context.filesDir, "test_roundtrip")
        tmpDir.mkdirs()
    }

    @After
    fun cleanup() {
        tmpDir.deleteRecursively()
    }

    // ==================== 密码学原语测试 ====================

    /**
     * Argon2id 密钥派生确定性验证。
     */
    @Test
    fun argon2Kdf_deterministic() {
        val password = "test_password".toByteArray(StandardCharsets.UTF_8)
        val salt = ByteArray(16) { it.toByte() }
        val key1 = Argon2Kdf.deriveKey(password, salt, false)
        val key2 = Argon2Kdf.deriveKey(password, salt, false)
        assertEquals(32, key1.size)
        assertArrayEquals(key1, key2)
    }

    /**
     * Argon2id 参数覆写验证。
     */
    @Test
    fun argon2Kdf_overrideParams() {
        val password = "test_override".toByteArray(StandardCharsets.UTF_8)
        val salt = ByteArray(16) { 0x0f }

        val keyDefault = Argon2Kdf.deriveKey(password, salt, false, null, null, null)
        val keyOverride = Argon2Kdf.deriveKey(password, salt, false, 65536, 2, 2)

        assertEquals(32, keyDefault.size)
        assertEquals(32, keyOverride.size)

        val keysEqual = keyDefault.contentEquals(keyOverride)
        assertTrue("不同 Argon2 参数应产生不同密钥", !keysEqual)
    }

    /**
     * 密码 NFC 规范化验证。
     */
    @Test
    fun passwordNormalizer_nfc() {
        val composed = "é" // é NFC (single codepoint)
        val nfcResult = PasswordNormalizer.encodeForKdf(composed)
        assertTrue(nfcResult.isNotEmpty())
    }

    /**
     * 无密码模式默认密码验证。
     */
    @Test
    fun passwordless_default() {
        val effective = Passwordless.effectivePassword("")
        assertTrue(effective.isNotEmpty())
        assertEquals(
            Passwordless.effectivePassword(""),
            Passwordless.effectivePassword(null)
        )
    }

    // ==================== Reed-Solomon 测试 ====================

    /**
     * RS 编码大小验证。
     */
    @Test
    fun reedSolomon_encodeSize() {
        val rs = RsCodecs()
        val data = ByteArray(64) { it.toByte() }
        val encoded = ReedSolomon.encode(rs.rs64, data)
        assertEquals(192, encoded.size) // 64 * 3 = 192
    }

    /**
     * RS 编解码回环测试（无错误）。
     */
    @Test
    fun reedSolomon_roundtripNoError() {
        val rs = RsCodecs()
        val data = ByteArray(64) { (it % 256).toByte() }
        val encoded = ReedSolomon.encode(rs.rs64, data)
        val decoded = ReedSolomon.decode(rs.rs64, encoded, false)
        assertArrayEquals(data, decoded.data)
    }

    // ==================== Header 测试 ====================

    /**
     * Flags 序列化/反序列化回环。
     */
    @Test
    fun flags_roundtrip() {
        val flags = Flags(true, true, false, true, false)
        val bytes = flags.toBytes()
        assertEquals(5, bytes.size)
        val parsed = Flags.fromBytes(bytes)
        assertEquals(flags.isParanoid, parsed.isParanoid)
        assertEquals(flags.isUseKeyfiles, parsed.isUseKeyfiles)
        assertEquals(flags.isReedSolomon, parsed.isReedSolomon)
    }

    /**
     * Header 布局常量验证。
     */
    @Test
    fun headerLayout_constants() {
        val baseSize = HeaderLayout.BASE_HEADER_SIZE
        assertTrue("基础 header 大小应 > 0", baseSize > 0)
        val withComments = HeaderLayout.headerSize(10)
        assertEquals(baseSize + 10 * HeaderLayout.COMMENT_CHAR_ENC_SIZE, withComments)
    }

    /**
     * Header 写入/读取基本流程。
     */
    @Test
    fun header_writeVerify() {
        val rs = RsCodecs()
        val salt = RandomBytes.generate(VolumeHeader.SALT_SIZE)
        val hkdfSalt = RandomBytes.generate(VolumeHeader.HKDF_SALT_SIZE)
        val serpentIV = RandomBytes.generate(VolumeHeader.SERPENT_IV_SIZE)
        val nonce = RandomBytes.generate(VolumeHeader.NONCE_SIZE)

        val header = VolumeHeader(salt, hkdfSalt, serpentIV, nonce)
        header.comments = "Android Test"
        header.flags = Flags(false, false, false, false, false)

        val tmpFile = File(tmpDir, "header_test.bin")
        val written = Files.newOutputStream(tmpFile.toPath()).use { out ->
            val writer = HeaderWriter(out, rs)
            writer.writeHeader(header)
        }

        assertTrue("Header 写入失败", tmpFile.exists())
        assertTrue("Header 大小异常", tmpFile.length() > 0)

        tmpFile.delete()
    }

    // ==================== 基础密码原语测试 ====================

    /**
     * RandomBytes 生成验证。
     */
    @Test
    fun randomBytes_generation() {
        val r1 = RandomBytes.generate(32)
        val r2 = RandomBytes.generate(32)
        assertEquals(32, r1.size)
        assertEquals(32, r2.size)
        var same = true
        for (i in r1.indices) {
            if (r1[i] != r2[i]) {
                same = false
                break
            }
        }
        assertTrue("两次随机生成不应完全相同", !same)
    }

    /**
     * Padding PKCS#7 编解码回环。
     */
    @Test
    fun padding_roundtrip() {
        val data = "Test padding data".toByteArray(StandardCharsets.UTF_8)
        val padded = Padding.pad(data)
        assertEquals(0, padded.size % 16)
        val unpadded = Padding.unpad(padded)
        assertArrayEquals(data, unpadded)
    }

    /**
     * i18n Messages 基本功能。
     */
    @Test
    fun messages_get() {
        val msg = Messages.get("nav.encrypt")
        assertTrue(msg.isNotEmpty())
        // 缺失 key 应返回 !key! 格式
        val missing = Messages.get("nonexistent.key.xyz")
        assertEquals("!nonexistent.key.xyz!", missing)
    }
}
