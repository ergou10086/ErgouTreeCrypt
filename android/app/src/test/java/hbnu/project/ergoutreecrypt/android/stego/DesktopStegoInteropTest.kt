package hbnu.project.ergoutreecrypt.android.stego

import hbnu.project.ergoutreecrypt.filestego.FileStegoCodec
import hbnu.project.ergoutreecrypt.filestego.api.FileStegoOptions
import hbnu.project.ergoutreecrypt.filestego.carrier.spi.AbstractCarrierAdapter
import hbnu.project.ergoutreecrypt.filestego.carrier.spi.CarrierRegistry
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assume.assumeTrue
import org.junit.BeforeClass
import org.junit.Test
import java.nio.file.Files
import java.nio.file.Path
import java.security.Security
import kotlin.io.path.exists
import kotlin.io.path.fileSize
import kotlin.io.path.isDirectory
import kotlin.io.path.isRegularFile
import kotlin.io.path.name

/**
 * 移动端侧的桌面隐写产物提取互通测试（Phase S1 验收）。
 *
 * 用 Android 模块**自身编译的共享核心副本**（`syncCoreLibs` 同步的 `filestego` 包）
 * 提取桌面端 `FileStegoKdfInteropTest` 产出的真实隐写文件，并按移动端
 * `StegoViewModel.extract` 的选项组装（低内存模式 + 大文件护栏），验证：
 *
 * 1. 桌面端六种载体容器的隐写产物在移动端侧均可逐字节还原；
 * 2. 桌面端 S1 档位透传后，载体元数据里记录的是 256 MiB 档而非默认 1 GiB。
 *
 * 桌面测试产物缺失时整类跳过（`Assume`），不阻塞常规 CI。
 *
 * @author ErgouTree
 * @since 2026/8/31
 */
class DesktopStegoInteropTest {

    private val codec = FileStegoCodec()

    /**
     * 逐个提取桌面端产物并与源文件逐字节比对。
     */
    @Test
    fun desktopArtifacts_extractableWithMobileOptions() {
        val dir = artifactDir()
        assumeTrue("缺少桌面端隐写产物目录（先跑 mvn -Dtest=FileStegoKdfInteropTest）", dir != null)
        val artifacts = desktopArtifacts(dir!!)
        assumeTrue("桌面端产物目录为空", artifacts.isNotEmpty())

        val outRoot = Files.createDirectories(dir.resolve("_android_extract"))
        for (stego in artifacts) {
            val outDir = Files.createDirectories(outRoot.resolve(stego.name.substringBeforeLast('.')))
            val extracted = codec.extract(stego, outDir, PASSWORD, mobileExtractOptions(), null)
            val expected = dir.resolve(SECRETS_DIR).resolve(extracted.name)
            assumeTrue("缺少源文件用于比对: ${extracted.name}", expected.isRegularFile())
            assertEquals(
                "${stego.name} 在移动端侧提取后应与源逐字节一致",
                firstDiffOffset(expected, extracted), -1L
            )
        }
    }

    /**
     * 逐块比较两个文件，返回首个不同字节的偏移。
     *
     * 不用 `Files.mismatch`：该方法在 Android API 面上不可用（编译期即无法解析）。
     *
     * @param a 期望内容的文件
     * @param b 实际内容的文件
     * @return 首个差异字节的偏移；完全一致返回 -1
     */
    private fun firstDiffOffset(a: Path, b: Path): Long {
        if (a.fileSize() != b.fileSize()) {
            return minOf(a.fileSize(), b.fileSize())
        }
        Files.newInputStream(a).use { ina ->
            Files.newInputStream(b).use { inb ->
                val bufA = ByteArray(1 shl 20)
                val bufB = ByteArray(1 shl 20)
                var offset = 0L
                while (true) {
                    val n = ina.readNBytes(bufA, 0, bufA.size)
                    inb.readNBytes(bufB, 0, n)
                    if (n <= 0) {
                        return -1L
                    }
                    for (i in 0 until n) {
                        if (bufA[i] != bufB[i]) {
                            return offset + i
                        }
                    }
                    offset += n
                }
            }
        }
    }

    /**
     * 桌面端均衡档产物在移动端侧读到的 Argon2 参数应为 256 MiB / 3 / 4（S1 生效证据）。
     */
    @Test
    fun desktopBalancedArtifacts_recordMobileFriendlyTier() {
        val dir = artifactDir()
        assumeTrue("缺少桌面端隐写产物目录", dir != null)
        val artifacts = desktopArtifacts(dir!!).filter { it.name.startsWith(BALANCED_PREFIX) }
        assumeTrue("缺少桌面端均衡档产物", artifacts.isNotEmpty())

        for (stego in artifacts) {
            val adapter = CarrierRegistry.detectAdapter(stego).orElse(null)
            assertNotNull("${stego.name} 应能被载体适配器识别", adapter)
            val probe = Files.createTempFile("ergou-android-meta-probe-", ".tmp")
            try {
                val meta = (adapter as AbstractCarrierAdapter)
                    .extractFullToFile(stego, PASSWORD, probe)
                val params = meta.argon2Params()
                assertNotNull("${stego.name} 应记录 Argon2 档位（S1 透传）", params)
                assertEquals("${stego.name} 内存档位", 256 shl 10, params.memoryKiB())
                assertEquals("${stego.name} 轮数", 3, params.passes())
                assertEquals("${stego.name} 线程数", 4, params.threads())
            } finally {
                Files.deleteIfExists(probe)
            }
        }
    }

    /**
     * 构建移动端提取选项，与 `StegoViewModel.extract` 的组装保持一致。
     *
     * @return 移动端提取选项
     */
    private fun mobileExtractOptions(): FileStegoOptions = FileStegoOptions.builder()
        .lowMemoryMode(true)
        .lowMemoryThresholdBytes(MOBILE_THRESHOLD_BYTES)
        .build()

    /**
     * 列出待验证的桌面端产物（跳过提取输出目录与体量过大的用例）。
     *
     * @param dir 产物根目录
     * @return 桌面端产出的隐写文件列表
     */
    private fun desktopArtifacts(dir: Path): List<Path> =
        Files.list(dir).use { s ->
            s.filter { it.isRegularFile() }
                .filter { it.name.startsWith(BALANCED_PREFIX) || it.name.startsWith(ADV_PREFIX) }
                .filter { it.fileSize() <= MAX_ARTIFACT_BYTES }
                .sorted()
                .toList()
        }

    companion object {

        /** 桌面端互通测试使用的密码，须与 `FileStegoKdfInteropTest` 一致。 */
        private val PASSWORD = "ergou-stego-interop".toByteArray(Charsets.UTF_8)

        /** 移动端大文件护栏阈值（典型 256 MiB 堆设备的 availableHeap/4 取值）。 */
        private const val MOBILE_THRESHOLD_BYTES = 64L shl 20

        /** 单个产物的验证上限：超过则跳过，避免单元测试写入数百 MiB 临时文件。 */
        private const val MAX_ARTIFACT_BYTES = 128L shl 20

        /** 桌面端默认（均衡）档产物的命名前缀。 */
        private const val BALANCED_PREFIX = "desktop_balanced_to_mobile_"

        /** 桌面端高级选项产物的命名前缀。 */
        private const val ADV_PREFIX = "adv_desktop_"

        /** 源文件缓存子目录名。 */
        private const val SECRETS_DIR = "_secrets"

        /** 桌面端产物目录的候选相对路径（单元测试工作目录为 `android/app`）。 */
        private val CANDIDATES = listOf(
            "../../temp/test/test_output/stego",
            "temp/test/test_output/stego"
        )

        @JvmStatic
        @BeforeClass
        fun registerProvider() {
            if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
                Security.insertProviderAt(BouncyCastleProvider(), 1)
            }
        }

        /**
         * 解析桌面端产物目录。
         *
         * @return 产物目录；不存在返回 null
         */
        @JvmStatic
        private fun artifactDir(): Path? = CANDIDATES
            .map { Path.of(it) }
            .firstOrNull { it.exists() && it.isDirectory() }
    }
}
