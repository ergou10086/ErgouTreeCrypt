package hbnu.project.ergoutreecrypt.android

import android.app.Activity
import android.content.ClipData
import android.content.Intent
import android.provider.DocumentsContract
import androidx.activity.compose.LocalActivityResultRegistryOwner
import androidx.activity.result.ActivityResultRegistry
import androidx.activity.result.ActivityResultRegistryOwner
import androidx.activity.result.contract.ActivityResultContract
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.core.app.ActivityOptionsCompat
import androidx.test.ext.junit.runners.AndroidJUnit4
import hbnu.project.ergoutreecrypt.android.ui.screen.DecryptScreen
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/** 通过实际文件选择回调和 Compose 显示验证缺卷信息。 */
@RunWith(AndroidJUnit4::class)
class SplitDecryptUiTest {
    /** 新格式只选择一卷也能显示准确总数和末卷缺失，无需清单 URI。 */
    @Test fun embeddedSafSelectionShowsTotalWithoutManifest() {
        val first=DocumentsContract.buildDocumentUri("hbnu.project.ergoutreecrypt.split.tests","root/Embedded/same.bin.ergou.0")
        val registry=object:ActivityResultRegistry() {
            override fun <I,O> onLaunch(requestCode:Int,contract:ActivityResultContract<I,O>,input:I,options:ActivityOptionsCompat?) {
                dispatchResult(requestCode,Activity.RESULT_OK,Intent().apply{clipData=ClipData.newRawUri("split",first)})
            }
        }
        val owner=object:ActivityResultRegistryOwner{override val activityResultRegistry=registry}
        compose.setContent{CompositionLocalProvider(LocalActivityResultRegistryOwner provides owner){MaterialTheme{DecryptScreen()}}}
        compose.onNodeWithText("或选择多个待解密文件").performScrollTo().performClick()
        compose.waitUntil(15000){compose.onAllNodesWithText(".1",substring=true).fetchSemanticsNodes().isNotEmpty()}
        compose.onNodeWithText(".1",substring=true).assertExists().assertTextContains("2",substring=true)
    }

    @get:Rule val compose=createComposeRule()
    @Test fun multipleSafSelectionShowsKnownTotalAndMissingVolume() {
        val authority="hbnu.project.ergoutreecrypt.split.tests"
        val first=DocumentsContract.buildDocumentUri(authority,"root/A/same.bin.ergou.0")
        val manifest=DocumentsContract.buildDocumentUri(authority,"root/A/same.bin.ergou.volumes")
        val registry=object:ActivityResultRegistry() {
            override fun <I,O> onLaunch(requestCode:Int,contract:ActivityResultContract<I,O>,input:I,options:ActivityOptionsCompat?) {
                val clip=ClipData.newRawUri("split",first).apply{addItem(ClipData.Item(manifest))}
                dispatchResult(requestCode,Activity.RESULT_OK,Intent().apply{clipData=clip})
            }
        }
        val owner=object:ActivityResultRegistryOwner{override val activityResultRegistry=registry}
        compose.setContent{CompositionLocalProvider(LocalActivityResultRegistryOwner provides owner){MaterialTheme{DecryptScreen()}}}
        compose.onNodeWithText("或选择多个待解密文件").performScrollTo().performClick()
        compose.waitUntil(15000){compose.onAllNodesWithText(".1",substring=true).fetchSemanticsNodes().isNotEmpty()}
        compose.onNodeWithText(".1",substring=true).assertExists()
        compose.onNodeWithText(".1",substring=true).assertTextContains("2",substring=true)
    }
}