package hbnu.project.ergoutreecrypt.android

import android.app.Application
import android.content.ContentUris
import android.graphics.BitmapFactory
import android.net.Uri
import android.provider.MediaStore
import androidx.core.content.FileProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import hbnu.project.ergoutreecrypt.android.viewmodel.ImageCryptDirection
import hbnu.project.ergoutreecrypt.android.viewmodel.ImageCryptUiState
import hbnu.project.ergoutreecrypt.android.viewmodel.ImageCryptViewModel
import hbnu.project.ergoutreecrypt.android.viewmodel.ProgressState
import hbnu.project.ergoutreecrypt.android.platform.OutputDirResolver
import hbnu.project.ergoutreecrypt.imagecrypt.ImageCryptMode
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.util.UUID

/**
 * 在真实 Android 运行时验证图片页面 ViewModel 的 URI、暂存、MediaStore 与协议工作流。
 *
 * <p>与直接调用共享 codec 的互操作测试不同，本测试覆盖 Phase 7 新增的平台适配层：
 * FileProvider URI → 私有 Path、Activity 作用域状态、OperationCoordinator、认证后公共提交，
 * 以及公开/密码两种模式的页面调用参数。
 */
@RunWith(AndroidJUnit4::class)
class ImageCryptViewModelDeviceTest {

    /** 测试 APK 上下文，用于读取同步的互操作 assets。 */
    private val testContext get() = InstrumentationRegistry.getInstrumentation().context

    /** 被测应用上下文。 */
    private val appContext get() = InstrumentationRegistry.getInstrumentation().targetContext

    /**
     * 公开与密码模式都应经 ViewModel 加密、提交到相册，再经同一页面还原为原始字节。
     */
    @Test
    fun publicAndPasswordWorkflow_roundTripThroughMediaStore() = runBlocking {
        val sourceBytes = testContext.assets
            .open("imagecrypt/interop/v1/corpus-input.png")
            .use { it.readBytes() }
        for (mode in listOf(ImageCryptMode.PUBLIC_RECOVERY, ImageCryptMode.PASSWORD)) {
            val unique = "phase7-${mode.name.lowercase()}-${UUID.randomUUID()}"
            val source = File(appContext.cacheDir, "$unique.png")
            source.writeBytes(sourceBytes)
            val sourceUri = FileProvider.getUriForFile(
                appContext,
                "${appContext.packageName}.fileprovider",
                source
            )
            val viewModel = ImageCryptViewModel(appContext.applicationContext as Application)
            try {
                viewModel.setMode(mode)
                viewModel.selectInput(sourceUri)
                val inputSelected = awaitState(viewModel) {
                    !it.selecting && it.inputName == source.name
                }
                assertPreviewDecodes(inputSelected.inputPreviewPath)
                if (mode == ImageCryptMode.PASSWORD) {
                    viewModel.setPassword(TEST_PASSWORD)
                    viewModel.setConfirmPassword(TEST_PASSWORD)
                }
                viewModel.start()
                val encrypted = awaitTerminal(viewModel)
                assertEquals(ProgressState.State.DONE, encrypted.progress.state)
                assertPreviewDecodes(encrypted.resultPreviewPath)
                val encryptedName = requireNotNull(encrypted.result).outputName
                val encryptedUri = requireNotNull(findOutput(encryptedName))

                viewModel.dismissResult()
                viewModel.setDirection(ImageCryptDirection.RESTORE)
                viewModel.selectInput(encryptedUri)
                val selected = awaitState(viewModel) { !it.selecting && it.metadata != null }
                if (selected.metadata?.requiresPassword() == true) {
                    viewModel.setPassword(TEST_PASSWORD)
                }
                viewModel.start()
                val restored = awaitTerminal(viewModel)
                assertEquals(ProgressState.State.DONE, restored.progress.state)
                assertPreviewDecodes(restored.resultPreviewPath)
                val restoredName = requireNotNull(restored.result).outputName
                val restoredUri = requireNotNull(findOutput(restoredName))
                val restoredBytes = readUri(restoredUri)
                assertArrayEquals(sourceBytes, restoredBytes)

                viewModel.dismissResult()
                val dismissed = awaitState(viewModel) { it.result == null }
                assertPreviewDecodes(dismissed.resultPreviewPath)
                viewModel.clearInput()
                val cleared = awaitState(viewModel) {
                    it.inputName == null && it.resultPreviewPath == null
                }
                assertNull(cleared.inputPreviewPath)

                deleteOutput(encryptedUri)
                deleteOutput(restoredUri)
            } finally {
                source.delete()
            }
        }
    }

    /**
     * 错误密码必须在认证失败后终止，且不得新增或替换公共还原文件。
     */
    @Test
    fun wrongPassword_doesNotPublishOutput() = runBlocking {
        val assetName = "imagecrypt/interop/v1/desktop-corpus-input-png-password-ascii-v1.egimg.png"
        val source = File(appContext.cacheDir, "phase7-wrong-${UUID.randomUUID()}.egimg.png")
        testContext.assets.open(assetName).use { input ->
            source.outputStream().use(input::copyTo)
        }
        val outputName = "corpus-input.restored.png"
        val before = outputFingerprints(outputName)
        val sourceUri = FileProvider.getUriForFile(
            appContext,
            "${appContext.packageName}.fileprovider",
            source
        )
        val viewModel = ImageCryptViewModel(appContext.applicationContext as Application)
        try {
            viewModel.setDirection(ImageCryptDirection.RESTORE)
            viewModel.selectInput(sourceUri)
            awaitState(viewModel) { !it.selecting && it.metadata != null }
            viewModel.setPassword("definitely-wrong-password")
            viewModel.start()

            val terminal = awaitTerminal(viewModel)
            assertEquals(ProgressState.State.ERROR, terminal.progress.state)
            assertEquals(before, outputFingerprints(outputName))
        } finally {
            source.delete()
        }
    }

    /**
     * 密码加密在任务启动后立即取消时必须进入取消态，且不得留下公共输出。
     */
    @Test
    fun immediateCancellation_doesNotPublishOutput() = runBlocking {
        val sourceBytes = testContext.assets
            .open("imagecrypt/interop/v1/corpus-input.png")
            .use { it.readBytes() }
        val unique = "phase7-cancel-${UUID.randomUUID()}"
        val source = File(appContext.cacheDir, "$unique.png")
        source.writeBytes(sourceBytes)
        val sourceUri = FileProvider.getUriForFile(
            appContext,
            "${appContext.packageName}.fileprovider",
            source
        )
        val outputName = "$unique.egimg.png"
        val viewModel = ImageCryptViewModel(appContext.applicationContext as Application)
        try {
            viewModel.setMode(ImageCryptMode.PASSWORD)
            viewModel.selectInput(sourceUri)
            awaitState(viewModel) { !it.selecting && it.inputName == source.name }
            viewModel.setPassword(TEST_PASSWORD)
            viewModel.setConfirmPassword(TEST_PASSWORD)
            viewModel.start()
            viewModel.cancel()

            val terminal = awaitTerminal(viewModel)
            assertEquals(ProgressState.State.CANCELLED, terminal.progress.state)
            assertNull(findOutput(outputName))
        } finally {
            findOutput(outputName)?.let(::deleteOutput)
            source.delete()
        }
    }

    /**
     * 等待满足谓词的 ViewModel 状态。
     *
     * @param viewModel 被测 ViewModel
     * @param predicate 完成谓词
     * @return 首个满足谓词的状态
     */
    private suspend fun awaitState(
        viewModel: ImageCryptViewModel,
        predicate: (ImageCryptUiState) -> Boolean
    ): ImageCryptUiState = withTimeout(120_000L) {
        viewModel.uiState.first(predicate)
    }

    /**
     * 等待任务进入成功、错误或取消终态。
     *
     * @param viewModel 被测 ViewModel
     * @return 终态页面状态
     */
    private suspend fun awaitTerminal(viewModel: ImageCryptViewModel): ImageCryptUiState =
        awaitState(viewModel) {
            it.progress.state == ProgressState.State.DONE ||
                it.progress.state == ProgressState.State.ERROR ||
                it.progress.state == ProgressState.State.CANCELLED
        }

    /**
     * 按显示名查找应用提交到公共相册的最新条目。
     *
     * @param displayName 文件显示名
     * @return MediaStore URI；未找到返回 {@code null}
     */
    private fun findGalleryImage(displayName: String): Uri? {
        val collection = MediaStore.Images.Media.EXTERNAL_CONTENT_URI
        val projection = arrayOf(MediaStore.MediaColumns._ID)
        val selection = "${MediaStore.MediaColumns.DISPLAY_NAME} = ? AND " +
            "${MediaStore.MediaColumns.RELATIVE_PATH} = ?"
        val args = arrayOf(
            displayName,
            "${OutputDirResolver.IMAGE_MEDIA_RELATIVE_PATH}/"
        )
        return appContext.contentResolver.query(
            collection,
            projection,
            selection,
            args,
            "${MediaStore.MediaColumns.DATE_ADDED} DESC"
        )?.use { cursor ->
            if (!cursor.moveToFirst()) {
                null
            } else {
                ContentUris.withAppendedId(collection, cursor.getLong(0))
            }
        }
    }

    /**
     * 查找相册 MediaStore 或旧系统直接写入的 Pictures 输出。
     *
     * @param displayName 文件显示名
     * @return 输出 URI；未找到返回 {@code null}
     */
    private fun findOutput(displayName: String): Uri? {
        val mediaUri = findGalleryImage(displayName)
        if (mediaUri != null) {
            return mediaUri
        }
        val direct = File(OutputDirResolver.publicPicturesPath(), displayName)
        return if (direct.isFile) Uri.fromFile(direct) else null
    }

    /**
     * 记录同名公共输出的稳定指纹，用于确认失败任务没有新增或替换文件。
     *
     * @param displayName 文件显示名
     * @return 已存在条目的稳定指纹集合
     */
    private fun outputFingerprints(displayName: String): Set<String> {
        val fingerprints = linkedSetOf<String>()
        val collection = MediaStore.Images.Media.EXTERNAL_CONTENT_URI
        val projection = arrayOf(
            MediaStore.MediaColumns._ID,
            MediaStore.MediaColumns.SIZE,
            MediaStore.MediaColumns.DATE_MODIFIED
        )
        val selection = "${MediaStore.MediaColumns.DISPLAY_NAME} = ? AND " +
            "${MediaStore.MediaColumns.RELATIVE_PATH} = ?"
        appContext.contentResolver.query(
            collection,
            projection,
            selection,
            arrayOf(displayName, "${OutputDirResolver.IMAGE_MEDIA_RELATIVE_PATH}/"),
            null
        )?.use { cursor ->
            while (cursor.moveToNext()) {
                fingerprints += "media:${cursor.getLong(0)}:${cursor.getLong(1)}:${cursor.getLong(2)}"
            }
        }
        val direct = File(OutputDirResolver.publicPicturesPath(), displayName)
        if (direct.isFile) {
            fingerprints += "file:${direct.length()}:${direct.lastModified()}"
        }
        return fingerprints
    }

    /**
     * 断言预览路径存在且 Android 平台能够解码其有界首帧。
     *
     * @param path 私有输入或结果预览路径
     */
    private fun assertPreviewDecodes(path: String?) {
        val file = File(requireNotNull(path))
        assertEquals(true, file.isFile)
        val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        BitmapFactory.decodeFile(file.absolutePath, bounds)
        assertNotNull(bounds.outMimeType)
    }

    /**
     * 读取内容或文件 URI 的完整字节。
     *
     * @param uri 输出 URI
     * @return 文件字节
     */
    private fun readUri(uri: Uri): ByteArray? {
        if (uri.scheme == "file") {
            return uri.path?.let { File(it).readBytes() }
        }
        return appContext.contentResolver.openInputStream(uri)?.use { it.readBytes() }
    }

    /**
     * 清理测试创建的公共输出。
     *
     * @param uri 输出 URI
     */
    private fun deleteOutput(uri: Uri) {
        if (uri.scheme == "file") {
            uri.path?.let { File(it).delete() }
        } else {
            appContext.contentResolver.delete(uri, null, null)
        }
    }

    companion object {
        /** 跨端测试口令。 */
        private const val TEST_PASSWORD = "phase7-café-中文"
    }
}
