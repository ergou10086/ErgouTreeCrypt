package hbnu.project.ergoutreecrypt.android

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import hbnu.project.ergoutreecrypt.fileops.ZipxInteropSupport
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/** Revalidates raw codec cases after an interoperability fix without repeating unchanged volume workflows. */
@RunWith(AndroidJUnit4::class)
class ZipxRawInteropTest {
    /** Reads refreshed desktop artifacts, then regenerates and self-verifies the Android raw artifacts. */
    @Test fun desktopToAndroidAndAndroidToAndroidThenExport() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val root = File(context.filesDir, "zipx-interop")
        ZipxInteropSupport.verifyRawArchives(File(root, "desktop").toPath(), File(root, "desktop-raw-on-android").toPath())
        ZipxInteropSupport.refreshXzArchives(File(root, "android").toPath(), true)
    }
}
