package hbnu.project.ergoutreecrypt.android

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import hbnu.project.ergoutreecrypt.encoding.RsCodecs
import hbnu.project.ergoutreecrypt.exception.CryptoException
import hbnu.project.ergoutreecrypt.exception.ErrorKind
import hbnu.project.ergoutreecrypt.volume.*
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.io.IOException

/** 在实际 ART 验证重复密钥与不支持的高级选项都不会被静默接受。 */
@RunWith(AndroidJUnit4::class)
class KeyfileSafetyDeviceTest {
    /** 实际 ART 的 RS 恢复、损坏认证拒绝、强制解密及缺卷策略。 */
    @Test fun corruptionAndForcePolicies() {
        val root = root().toPath()
        hbnu.project.ergoutreecrypt.fileops.SplitInteropSupport.corruptionRegression(root.resolve("corruption"))
        hbnu.project.ergoutreecrypt.fileops.SplitInteropSupport.advancedOptionsRegression(root.resolve("force"))
        hbnu.project.ergoutreecrypt.fileops.SplitInteropSupport.readOnlySourceRegression(root.resolve("readonly"))
    }

    /** 不同路径的相同内容也必须被视为重复密钥。 */
    @Test fun rejectsPartialCancellation() {
        val root = root()
        val request = request(root)
        request.keyfiles = listOf("key-a", "改名-a", "key-b").map { File(root, "corpus/$it").path }
        try {
            Encryptor.encrypt(request)
            fail("无序重复密钥被接受")
        } catch (expected: IOException) {
            assertTrue(expected.message!!.contains("重复"))
        }
        assertFalse(File(request.outputFile).exists())
        assertFalse(File(request.outputFile + ".incomplete").exists())
    }

    /** EGTD 与 FAST 当前协议不支持密钥文件，各入口必须显式拒绝。 */
    @Test fun rejectsUnsupportedFormats() {
        val root = root()
        for (dual in listOf(true, false)) {
            val request = request(root)
            request.keyfiles = listOf(File(root, "corpus/key-a").path)
            if (dual) {
                request.isDualDeniability = true
                request.decoyFilePath = request.inputFile
                request.fakePassword = "decoy"
            } else request.mode = EncryptionMode.FAST
            rejected { Encryptor.encrypt(request) }
            assertFalse(File(request.outputFile).exists())
            val read = DecryptRequest()
            read.keyfiles = request.keyfiles
            if (dual) {
                rejected { DualDeniability.verify(read) }
                rejected { DualDeniability.decrypt(read) }
            } else {
                rejected { FastCapabilities.validateDecryption(read) }
                val verify = VerifyRequest()
                verify.keyfiles = read.keyfiles
                rejected { FastCapabilities.validateVerification(verify) }
            }
        }
    }

    /** @return 脚本授权的独占测试根目录。 */
    private fun root(): File {
        val name = InstrumentationRegistry.getArguments().getString("keyfileRoot")!!
        require(name.matches(Regex("keyfile-interop-[a-f0-9]{32}")))
        return File(InstrumentationRegistry.getInstrumentation().targetContext.filesDir, name)
    }

    /** @param root 独占测试目录 @return 小内存加密请求。 */
    private fun request(root: File): EncryptRequest = EncryptRequest().apply {
        inputFile = File(root, "corpus/sample.bin").path
        outputFile = File(root, "forbidden.ergou").path
        password = "keyfile-audit"
        rsCodecs = RsCodecs()
        argon2MemoryKib = 4096
        argon2Passes = 1
        argon2Threads = 1
    }

    /** @param action 必须报出选项不兼容的操作。 */
    private fun rejected(action: () -> Unit) {
        try { action(); fail("不支持的密钥文件选项被忽略") }
        catch (expected: CryptoException) { assertEquals(ErrorKind.UNSUPPORTED_FORMAT, expected.kind()) }
    }
}
