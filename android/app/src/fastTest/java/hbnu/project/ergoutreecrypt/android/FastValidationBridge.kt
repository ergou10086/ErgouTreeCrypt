package hbnu.project.ergoutreecrypt.android

import android.content.Context
import android.net.Uri
import hbnu.project.ergoutreecrypt.android.platform.FastSafOutput
import hbnu.project.ergoutreecrypt.android.platform.KdfPreflight
import hbnu.project.ergoutreecrypt.android.platform.Argon2MobileMode
import hbnu.project.ergoutreecrypt.volume.*
import java.io.File
import java.nio.file.Files

/** 验收包内部执行生产调用，使助手与密码核心一同接受 R8 优化。 */
object FastValidationBridge {
    /** @param root 脚本创建的本次独占语料目录 */
    @JvmStatic fun interop(root: File) {
        val path = root.toPath()
        val scratch = Files.createDirectory(path.resolve("scratch"))
        FastInteropSupport.verify(path.resolve("desktop"), path.resolve("desktop/ciphers"), scratch)
        FastInteropSupport.produce(path.resolve("desktop"), path.resolve("android"))
        FastInteropSupport.verify(path.resolve("desktop"), path.resolve("android"), scratch)
    }

    /** 完整任务性能入口，标准 KDF 参数来自当前设备 AUTO 档位。 */
    @JvmStatic fun benchmark(input: File, results: File) {
        val tier = Argon2MobileMode.AUTO.resolve()
        FastTaskBenchmark.run(input.toPath(), results.toPath(), tier.memoryKiB, tier.passes, tier.threads)
    }

    /** @param source 真实输入文件 @param results 本次新目录 */
    @JvmStatic fun large(source: File, results: File) = FastLargeFileSupport.run(source.toPath(), results.toPath())

    /** 使用默认生产入口写入 FAST 密文。 */
    @JvmStatic fun encrypt(input: File, cipher: File, password: String) {
        Encryptor.encrypt(EncryptRequest().apply {
            mode = EncryptionMode.FAST; inputFile = input.path; outputFile = cipher.path; this.password = password
        })
    }

    /** 完整独立认证后另行调用默认解密；两项均不能绕过认证。 */
    @JvmStatic fun authenticateAndDecrypt(cipher: File, plain: File, password: String) {
        check(Verifier.verify(VerifyRequest().apply { inputFile = cipher.path; this.password = password }))
        Decryptor.decrypt(DecryptRequest().apply {
            inputFile = cipher.path; outputFile = plain.path; this.password = password
        })
    }

    /** @param cipher 待预检密文 @return 实际内存 KiB */
    @JvmStatic fun memory(cipher: File): Int? = KdfPreflight.peekArgon2MemoryKib(cipher.toPath())

    /** @param cipher 待预检密文 @return 是否内部压缩 */
    @JvmStatic fun compressed(cipher: File): Boolean? = KdfPreflight.peekCompressed(cipher.toPath())

    /** 通过真实 ContentResolver 执行事务，取消参数仅供故障测试。 */
    @JvmStatic fun commit(context: Context, tree: Uri, source: File, cancelled: Boolean): Boolean =
        FastSafOutput(context).commit(tree, source) { cancelled }
}
