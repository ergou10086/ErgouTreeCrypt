package hbnu.project.ergoutreecrypt.android

import android.os.Build
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import hbnu.project.ergoutreecrypt.crypto.Argon2OffHeap
import hbnu.project.ergoutreecrypt.crypto.NativeArgon2
import hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptCodec
import hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptMetadata
import hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptMode
import hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptOptions
import hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptPassword
import hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptProgress
import hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptProtocol
import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.security.MessageDigest
import java.util.Properties

/**
 * EGTC-IMG v1 的真实双端互操作硬闸门（设备侧）。
 *
 * ## 为什么这个测试不能由宿主 JVM 测试替代
 *
 * 本测试运行在真实 Android 运行时（ART）上，走的是 APK 内的依赖、Android 文件系统与
 * 设备 CPU。`android/shared-test` 与 `KdfFourWayInteropTest` 跑在同一台 PC 的 JVM 上，
 * 既不会加载 APK 的 Bouncy Castle，也不会经过 ART 的 desugar 结果，因此**不能**用来证明
 * 跨端可用性。两者的区别不是"更快 vs 更慢"，而是"证明了不同的事情"。
 *
 * ## 两个方向
 *
 * | 方向 | 用例 | 做法 |
 * |---|---|---|
 * | Desktop → Android | [desktopArtifactsRestoreByteForByteOnDevice] | 读取随 APK 打包的桌面产物，在设备上还原并比对 SHA-256 |
 * | Android → Desktop | [androidArtifactsAreExportedForDesktopVerification] | 在设备上生成产物并写入可导出目录，交由桌面 JVM 校验 |
 *
 * 语料由 Gradle 从 `src/test/resources/imagecrypt/interop` 同步到 androidTest assets，
 * 因此两端看到的是**同一批字节**，不存在"两边各生成一份再互相比对"的伪互操作。
 *
 * ## 设备上必须成立的三件事
 *
 * 1. 桌面产物能被 ART 上的 reader 完整还原（协议解析、反滤波、KDF、MAC 全部正确）；
 * 2. v1 固定的 Argon2id 参数在设备上可执行——64 MiB / 3 passes / 4 lanes 不能被静默降档；
 * 3. 组合字符口令经 NFC 后导出的字节与桌面端完全一致。
 *
 * @author ErgouTree
 * @since 2026/9/16
 */
@RunWith(AndroidJUnit4::class)
class ImageCryptInteropTest {

    /**
     * 随 APK 打包的语料在 assets 中的前缀。
     */
    private val corpusAssetRoot = "imagecrypt/interop/v1"

    /**
     * 导出目录名（位于应用外部私有目录，可被 adb pull 取出）。
     */
    private val exportDirectoryName = "imagecrypt-interop-out"

    /**
     * 测试 APK 的上下文。语料 assets 打包在测试 APK 里，只能从这里读。
     */
    private val testContext get() = InstrumentationRegistry.getInstrumentation().context

    /**
     * 被测应用的上下文。
     *
     * 所有**文件**操作都走这里而不是测试 APK 的上下文：真实流程中图片加解密读写的是应用自己的
     * 私有目录，测试只有用同一个目录才验证了真实行为；而且测试运行器进程的 cacheDir / filesDir
     * 在部分设备上并不会被预先创建，用它反而会引入与产品无关的环境故障。
     */
    private val appContext get() = InstrumentationRegistry.getInstrumentation().targetContext

    /**
     * Desktop → Android：每条语料都必须在设备上逐字节还原。
     *
     * 这条用例是互操作承诺"任意端生成、任意端恢复"的设备侧证明。
     */
    @Test
    fun desktopArtifactsRestoreByteForByteOnDevice() {
        val corpus = loadCorpus()
        val count = corpus.getProperty("entry.count").toInt()
        assertTrue("语料条目数异常: $count", count >= 6)

        val codec = ImageCryptCodec()
        for (index in 0 until count) {
            val prefix = "entry.$index."
            val id = corpus.getProperty(prefix + "id")
            val artifact = materialize(corpus.getProperty(prefix + "file"))
            val password = passwordOf(corpus, prefix)

            assertTrue("$id 应被识别为 EGTC-IMG 产物", codec.isEncrypted(artifact.toPath()))

            val metadata: ImageCryptMetadata = codec.peekMetadata(artifact.toPath())
            assertMetadataMatchesCorpus(corpus, prefix, id, metadata)

            // 先只读校验，确认认证标签在设备上同样能通过
            codec.verify(artifact.toPath(), password, ImageCryptProgress.NONE)

            val restoreDirectory = ensureDirectory(File(appContext.cacheDir, "restored-$index"))
            val restored = codec.decrypt(
                artifact.toPath(),
                restoreDirectory.toPath(),
                password,
                ImageCryptProgress.NONE
            )

            assertEquals("$id 恢复文件名不符", corpus.getProperty(prefix + "restoredName"),
                restored.fileName.toString())
            assertEquals("$id 恢复长度不符", corpus.getProperty(prefix + "restoredLength"),
                restored.toFile().length().toString())
            assertEquals("$id 恢复内容 SHA-256 不符", corpus.getProperty(prefix + "restoredSha256"),
                sha256(restored.toFile().readBytes()))
        }
    }

    /**
     * 组合字符口令的 NFC 与 NFD 两种形态必须导出相同的 UTF-8 字节。
     *
     * 若设备端漏掉 NFC 归一化，用户会看到"同一个密码在电脑上能打开、在手机上打不开"这类
     * 极难排查的故障，因此这条断言独立于任何加解密流程单独成立。
     */
    @Test
    fun composedPasswordNormalizesIdenticallyOnDevice() {
        val corpus = loadCorpus()
        val nfc = corpus.getProperty("password.unicode")
        val nfd = corpus.getProperty("password.unicode.nfd")
        assertNotEquals("两种形态的码点序列本就应当不同", nfc, nfd)

        val nfcHex = hex(ImageCryptPassword.encodeForV1(nfc))
        val nfdHex = hex(ImageCryptPassword.encodeForV1(nfd))
        assertEquals("NFC 口令的规范化字节与桌面语料不符",
            corpus.getProperty("password.unicode.utf8Hex"), nfcHex)
        assertEquals("NFD 输入必须被归一化为与 NFC 相同的字节", nfcHex, nfdHex)
        assertEquals("ASCII 口令的规范化字节与桌面语料不符",
            corpus.getProperty("password.ascii.utf8Hex"),
            hex(ImageCryptPassword.encodeForV1(corpus.getProperty("password.ascii"))))
    }

    /**
     * v1 规范参数下，设备上的三条 KDF 执行路径必须给出完全相同的 32 字节密钥。
     *
     * 共享核心只有一份源码，但 Argon2 在运行时会按可用堆内存与 ABI 落到 BouncyCastle 堆内、
     * Java 离堆或 native libargon2 三条完全不同的实现上。只要有一条在某个参数组合上偏移一位，
     * 密码模式的产物就会变成"只有本机能打开"——而这在任一单端的测试里都不会有任何异常表现。
     *
     * 本用例**断言** native 库可用而不是跳过：APK 的 abiFilters 覆盖 arm64-v8a / armeabi-v7a /
     * x86_64，任何受支持的测试设备都应命中其中之一。若这里变成跳过，"native 路径已验证"就
     * 成了一句没有依据的话。
     */
    @Test
    fun everyKdfExecutionPathAgreesOnV1ParametersOnDevice() {
        val corpus = loadCorpus()
        val password = ImageCryptPassword.encodeForV1(corpus.getProperty("password.ascii"))
        val salt = ByteArray(16) { index -> index.toByte() }

        val expected = deriveWithBouncyCastle(password, salt)
        val offHeap = Argon2OffHeap.deriveKey(password, salt,
            ImageCryptProtocol.ARGON2_MEMORY_KIB,
            ImageCryptProtocol.ARGON2_PASSES,
            ImageCryptProtocol.ARGON2_LANES,
            ImageCryptProtocol.ARGON2_OUTPUT_LENGTH)
        assertArrayEquals("离堆实现与 BouncyCastle 在 v1 参数下不一致", expected, offHeap)

        assertTrue("设备 ABI(" + (Build.SUPPORTED_ABIS.firstOrNull() ?: "unknown")
                + ") 未打包 native libargon2，v1 的 native 执行路径未被验证",
            NativeArgon2.isAvailable())
        val nativeKey = NativeArgon2.deriveKey(password, salt,
            ImageCryptProtocol.ARGON2_MEMORY_KIB,
            ImageCryptProtocol.ARGON2_PASSES,
            ImageCryptProtocol.ARGON2_LANES,
            ImageCryptProtocol.ARGON2_OUTPUT_LENGTH)
        assertArrayEquals("native libargon2 与 BouncyCastle 在 v1 参数下不一致", expected, nativeKey)
        assertArrayEquals("native libargon2 与离堆实现在 v1 参数下不一致", offHeap, nativeKey)
    }

    /**
     * 直接用 BouncyCastle 的 Argon2id 派生 v1 密钥，作为另外两条路径的对照基准。
     *
     * @param password 口令字节
     * @param salt     salt
     * @return 32 字节派生密钥
     */
    private fun deriveWithBouncyCastle(password: ByteArray, salt: ByteArray): ByteArray {
        val parameters = Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
            .withVersion(Argon2Parameters.ARGON2_VERSION_13)
            .withMemoryAsKB(ImageCryptProtocol.ARGON2_MEMORY_KIB)
            .withIterations(ImageCryptProtocol.ARGON2_PASSES)
            .withParallelism(ImageCryptProtocol.ARGON2_LANES)
            .withSalt(salt)
            .build()
        val generator = Argon2BytesGenerator()
        generator.init(parameters)
        val output = ByteArray(ImageCryptProtocol.ARGON2_OUTPUT_LENGTH)
        generator.generateBytes(password, output)
        return output
    }

    /**
     * Android → Desktop：在设备上生成产物并写入可导出目录，交由桌面 JVM 校验。
     *
     * 产物命名与桌面语料保持一致（`android-<输入>-<组合>-v1.egimg.png`），因此桌面侧可以用
     * 同一份 `corpus.properties` 里的期望值来验证，而不必相信设备自己写下的"预期结果"——
     * 否则设备写错了期望值也能让校验通过，互操作就变成了自证。
     */
    @Test
    fun androidArtifactsAreExportedForDesktopVerification() {
        val corpus = loadCorpus()
        val exportDirectory = ensureDirectory(exportDirectory())

        val codec = ImageCryptCodec()
        val inputCount = corpus.getProperty("input.count").toInt()
        var entryIndex = 0

        for (inputIndex in 0 until inputCount) {
            val inputName = corpus.getProperty("input.$inputIndex.file")
            val input = materialize(inputName)
            val stem = inputName.replace('.', '-')

            for (combination in combinations()) {
                val password = combination.passwordKey
                    ?.let { ImageCryptPassword.encodeForV1(corpus.getProperty("password.$it")) }
                val artifactName = "android-$stem-${combination.tag}-v1.egimg.png"
                val artifact = File(exportDirectory, artifactName)

                codec.encrypt(
                    input.toPath(),
                    artifact.toPath(),
                    password,
                    ImageCryptOptions.of(combination.mode),
                    ImageCryptProgress.NONE
                )

                // 生成后立刻在设备上自还原一次，确保导出的确实是一份可用产物
                val roundTripDirectory =
                    ensureDirectory(File(appContext.cacheDir, "roundtrip-$entryIndex"))
                val restored = codec.decrypt(
                    artifact.toPath(),
                    roundTripDirectory.toPath(),
                    password,
                    ImageCryptProgress.NONE
                )
                assertEquals("设备自还原与原始输入不一致: $artifactName",
                    sha256(input.readBytes()), sha256(restored.toFile().readBytes()))

                writeEntry(exportDirectory, entryIndex, corpus, inputIndex, inputName,
                    combination, artifactName, artifact)
                entryIndex++
            }
        }

        writeExportProperties(exportDirectory, entryIndex)
        assertTrue("导出目录为空", entryIndex > 0)
    }

    // ==================== 语料读取 ====================

    /**
     * 读取设备上的语料属性表。
     *
     * 必须显式指定 UTF-8：`Properties.load(InputStream)` 默认按 ISO-8859-1 解码，会把
     * 组合字符口令读成乱码，进而派生出不同的密钥并报出误导性的"文件已损坏"。
     *
     * @return 语料属性表
     */
    private fun loadCorpus(): Properties {
        val properties = Properties()
        val assetPath = "$corpusAssetRoot/corpus.properties"
        testContext.assets.open(assetPath).reader(Charsets.UTF_8).use { reader ->
            properties.load(reader)
        }
        return properties
    }

    /**
     * 把语料文件从 assets 解出到应用缓存，模拟"用户拿到一个文件"。
     *
     * 真实流程里输入总是普通文件路径；核心的预检、临时文件与原子提交都建立在文件系统语义上，
     * 因此这里不做内存流特例。
     *
     * @param name 语料文件名
     * @return 缓存中的文件
     */
    private fun materialize(name: String): File {
        val target = File(appContext.cacheDir, name)
        if (target.exists() && target.length() > 0) {
            return target
        }
        ensureParentDirectory(target)
        testContext.assets.open("$corpusAssetRoot/$name").use { input ->
            target.outputStream().use { output -> input.copyTo(output) }
        }
        return target
    }

    /**
     * 取出条目对应的口令字节。
     *
     * @param corpus 语料属性表
     * @param prefix 条目前缀
     * @return 口令字节；公开恢复模式返回 null
     */
    private fun passwordOf(corpus: Properties, prefix: String): ByteArray? {
        val key = corpus.getProperty(prefix + "passwordKey")
        if (key.isNullOrEmpty()) {
            return null
        }
        return ImageCryptPassword.encodeForV1(corpus.getProperty("password.$key"))
    }

    /**
     * 断言设备读出的元数据与语料记录一致。
     *
     * @param corpus   语料属性表
     * @param prefix   条目前缀
     * @param id       条目标识（用于失败信息）
     * @param metadata 设备解析出的元数据
     */
    private fun assertMetadataMatchesCorpus(corpus: Properties, prefix: String, id: String,
                                            metadata: ImageCryptMetadata) {
        assertEquals("$id 画布宽度不符", corpus.getProperty(prefix + "canvasWidth"),
            metadata.canvasWidth().toString())
        assertEquals("$id 画布高度不符", corpus.getProperty(prefix + "canvasHeight"),
            metadata.canvasHeight().toString())
        assertEquals("$id 封装区长度不符", corpus.getProperty(prefix + "innerPlainLength"),
            metadata.payloadLength().toString())
        assertEquals("$id 保护模式不符", corpus.getProperty(prefix + "mode"),
            metadata.mode.name)
        if (metadata.mode() == ImageCryptMode.PASSWORD) {
            assertEquals("$id 设备未采用 v1 固定 Argon2 内存参数",
                ImageCryptProtocol.ARGON2_MEMORY_KIB, metadata.argon2MemoryKiB())
            assertEquals("$id 设备未采用 v1 固定 Argon2 迭代次数",
                ImageCryptProtocol.ARGON2_PASSES, metadata.argon2Passes())
            assertEquals("$id 设备未采用 v1 固定 Argon2 并行度",
                ImageCryptProtocol.ARGON2_LANES, metadata.argon2Lanes())
        } else {
            assertEquals("$id 公开恢复模式不得声明 Argon2 内存", 0, metadata.argon2MemoryKiB())
        }
    }

    /**
     * 记录一条导出条目，供桌面侧核对来源。
     *
     * 期望的恢复结果直接取自冻结语料中该输入自身的 SHA-256，而不是设备重新计算的值——
     * 后者只能证明"设备自己和自己一致"，证明不了"设备与桌面一致"。
     *
     * @param exportDirectory 导出目录
     * @param index           条目序号
     * @param corpus          语料属性表
     * @param inputIndex      输入在语料中的序号
     * @param inputName       输入文件名
     * @param combination     组合方式
     * @param artifactName    产物文件名
     * @param artifact        产物文件
     */
    private fun writeEntry(exportDirectory: File, index: Int, corpus: Properties, inputIndex: Int,
                           inputName: String, combination: Combination, artifactName: String,
                           artifact: File) {
        // 每个条目独占一个属性文件，因此键名不再带序号前缀；桌面侧按裸键读取
        val properties = Properties().apply {
            setProperty("id", "$inputName-${combination.tag}")
            setProperty("file", artifactName)
            setProperty("input", inputName)
            setProperty("mode", combination.mode.name)
            setProperty("passwordKey", combination.passwordKey ?: "")
            setProperty("artifactLength", artifact.length().toString())
            setProperty("artifactSha256", sha256(artifact.readBytes()))
            setProperty("restoredSha256", corpus.getProperty("input.$inputIndex.sha256"))
        }
        val file = File(exportDirectory, "export-$index.properties")
        file.outputStream().use { output -> properties.store(output, "android-interop-entry-$index") }
    }

    /**
     * 写出导出清单，记录生成设备与运行环境。
     *
     * 桌面侧只用它核对来源，**不用**它作为断言依据——期望值一律取自冻结的桌面语料，
     * 否则设备写错了期望值也能让校验通过。
     *
     * @param exportDirectory 导出目录
     * @param entryCount      导出条目数
     */
    private fun writeExportProperties(exportDirectory: File, entryCount: Int) {
        val properties = Properties().apply {
            setProperty("export.generator", "android-art")
            setProperty("export.deviceModel", Build.MODEL)
            setProperty("export.deviceManufacturer", Build.MANUFACTURER)
            setProperty("export.apiLevel", Build.VERSION.SDK_INT.toString())
            setProperty("export.abi", Build.SUPPORTED_ABIS.firstOrNull() ?: "unknown")
            setProperty("export.appVersion", BuildConfig.VERSION_NAME)
            setProperty("export.entryCount", entryCount.toString())
        }
        File(exportDirectory, "export.properties").outputStream().use { output ->
            properties.store(output, "EGTC-IMG v1 Android 导出清单")
        }
    }

    /**
     * 返回可导出的目录，优先使用外部私有目录以便 adb pull 取出。
     *
     * 外部私有目录在个别设备/存储状态下可能不可用（返回 null），此时退回应用内部目录；
     * 内部目录需要 `adb exec-out run-as <包名>` 才能取出，取法与命令见语料 README。
     *
     * @return 导出目录
     */
    private fun exportDirectory(): File =
        File(appContext.getExternalFilesDir(null) ?: appContext.filesDir, exportDirectoryName)

    /**
     * 清空并重建一个临时目录。
     *
     * @param directory 目标目录
     * @return 同一个目录对象，便于链式使用
     */
    private fun ensureDirectory(directory: File): File {
        directory.deleteRecursively()
        ensureParentDirectory(directory)
        if (!directory.mkdirs() && !directory.isDirectory) {
            throw AssertionError("无法创建目录: " + directory.absolutePath)
        }
        return directory
    }

    /**
     * 确保文件的上级目录存在。
     *
     * 首次运行的测试进程中，应用的 cacheDir / filesDir 可能尚未被创建，此时直接
     * `outputStream()` 会抛出 ENOENT。这里只创建不删除：上级目录往往是应用自己的工作目录，
     * 清空它会连带删掉同一测试里已经解出的其它语料。
     *
     * @param file 目标文件
     */
    private fun ensureParentDirectory(file: File) {
        val parent = file.parentFile ?: return
        if (!parent.isDirectory && !parent.mkdirs()) {
            throw AssertionError("无法创建目录: " + parent.absolutePath)
        }
    }

    /**
     * 本测试覆盖的保护组合。
     *
     * @return 组合列表
     */
    private fun combinations(): List<Combination> = listOf(
        Combination("public", ImageCryptMode.PUBLIC_RECOVERY, null),
        Combination("password-ascii", ImageCryptMode.PASSWORD, "ascii"),
        Combination("password-unicode", ImageCryptMode.PASSWORD, "unicode")
    )

    /**
     * 一种保护组合。
     *
     * @param tag         命名与检索用的标签
     * @param mode        保护模式
     * @param passwordKey 口令在语料属性表中的键名；公开恢复为 null
     */
    private data class Combination(
        val tag: String,
        val mode: ImageCryptMode,
        val passwordKey: String?
    )

    /**
     * 计算 SHA-256。
     *
     * @param data 字节数组
     * @return 小写十六进制摘要
     */
    private fun sha256(data: ByteArray): String =
        hex(MessageDigest.getInstance("SHA-256").digest(data))

    /**
     * 渲染为小写十六进制。
     *
     * @param data 字节数组
     * @return 十六进制文本
     */
    private fun hex(data: ByteArray): String =
        data.joinToString("") { "%02x".format(it) }

}
