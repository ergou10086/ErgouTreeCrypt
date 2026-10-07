package hbnu.project.ergoutreecrypt.android

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import hbnu.project.ergoutreecrypt.android.viewmodel.MediaCryptViewModel
import hbnu.project.ergoutreecrypt.android.viewmodel.ProgressState
import hbnu.project.ergoutreecrypt.fileops.ArchiveExtractor
import hbnu.project.ergoutreecrypt.fileops.ZipxArchive
import hbnu.project.ergoutreecrypt.mediacrypt.MediaCryptCodec
import hbnu.project.ergoutreecrypt.settings.SettingsManager
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.flow.first
import org.junit.Test
import org.junit.Assert.*
import org.junit.runner.RunWith
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder

/** 检查真实移动端媒体 ViewModel 的 ZIPX 格式与原生密码传递。 */
@RunWith(AndroidJUnit4::class)
class ZipxMediaArchiveTest {
    /** 普通及带密码的 ZIPX 媒体输出均逐字节还原原始 WAV。 */
    @Test fun mediaViewModelUsesNativeZipx() {
        val instrument = InstrumentationRegistry.getInstrumentation()
        val root = File(instrument.targetContext.cacheDir, "zipx-media").apply { mkdirs() }
        val saved = SettingsManager.isArchiveCustomEncryption()
        val fallback = SettingsManager.isArchivePasswordFallback()
        try {
            SettingsManager.setArchiveCustomEncryption(false)
            SettingsManager.setArchivePasswordFallback(false)
            val pcm = ByteArray(16384) { (it % 113).toByte() }
            val wav = ByteBuffer.allocate(44 + pcm.size).order(ByteOrder.LITTLE_ENDIAN)
            wav.put("RIFF".toByteArray()).putInt(36 + pcm.size).put("WAVEfmt ".toByteArray()).putInt(16)
            wav.putShort(1).putShort(1).putInt(8000).putInt(16000).putShort(2).putShort(16)
            wav.put("data".toByteArray()).putInt(pcm.size).put(pcm)
            val source = File(root, "source.wav").apply { writeBytes(wav.array()) }
            for (password in listOf(null, "archive-密码")) {
                val output = File(root, "media-${password != null}.enc.wav")
                val vm = MediaCryptViewModel()
                instrument.runOnMainSync {
                    vm.startEncrypt(source.absolutePath, output.absolutePath, "volume", argon2MemoryKib = 32,
                        argon2Passes = 1, argon2Threads = 1, archiveFormat = "ZIPX", archivePassword = password)
                }
                val state = runBlocking { withTimeout(30000) {
                    vm.progress.first { it.state != ProgressState.State.IDLE && it.state != ProgressState.State.RUNNING }
                } }
                assertEquals(state.error, ProgressState.State.DONE, state.state)
                val archive = File(output.absolutePath + ".zipx")
                assertTrue(archive.isFile); assertFalse(output.exists())
                assertEquals(password != null, ArchiveExtractor.hasEncryptedEntries(archive.toPath()))
                ZipxArchive.verify(archive.toPath(), password)
                val files = ArchiveExtractor.extract(archive.toPath(), File(root, "out-${password != null}").toPath(), password)
                val restored = File(root, "restored-${password != null}.wav")
                MediaCryptCodec().decrypt(files.single(), restored.toPath(), "volume".toByteArray())
                assertArrayEquals(source.readBytes(), restored.readBytes())
            }
        } finally {
            SettingsManager.setArchiveCustomEncryption(saved)
            SettingsManager.setArchivePasswordFallback(fallback)
        }
    }
}
