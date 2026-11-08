package hbnu.project.ergoutreecrypt.android

import android.provider.DocumentsContract
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.ext.junit.rules.ActivityScenarioRule
import androidx.test.platform.app.InstrumentationRegistry
import hbnu.project.ergoutreecrypt.android.platform.AndroidFileOps
import hbnu.project.ergoutreecrypt.fileops.Splitter
import org.junit.Assert.*
import org.junit.Test
import org.junit.Rule
import org.junit.Before
import org.junit.runner.RunWith
import java.io.File

/** 实际 ContentResolver/SAF 回退，覆盖多选、同名不同目录和整目录授权。 */
@RunWith(AndroidJUnit4::class)
class SplitSafTest {
    /** 保持测试应用在前台，避免真机系统冻结后台 instrumentation。 */
    @get:Rule val foreground = ActivityScenarioRule(MainActivity::class.java)

    private val authority="hbnu.project.ergoutreecrypt.split.tests"
    /** 先确认测试提供者可见，避免把设备权限问题误报成分卷算法故障。 */
    @Before fun providerIsReadable() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val uri = DocumentsContract.buildDocumentUri(authority, "root/A/same.bin.ergou.0")
        context.contentResolver.query(uri, null, null, null, null).use { cursor ->
            assertNotNull("Split test provider is not visible to the target app", cursor)
        }
        context.contentResolver.openInputStream(uri).use { stream ->
            assertNotNull("Split test document is not readable", stream)
            assertEquals(0, stream!!.read())
        }
    }

    @Test fun multipleChunksKeepNamesAndParentsWithoutDataColumn() {
        val ops=AndroidFileOps(InstrumentationRegistry.getInstrumentation().targetContext)
        val bases=mutableListOf<File>()
        for(parent in listOf("A","B")) {
            for(suffix in listOf("0","1","volumes")) {
                val uri=DocumentsContract.buildDocumentUri(authority,"root/$parent/same.bin.ergou.$suffix")
                val path=ops.resolveToPath(uri);assertNotNull(path)
                assertEquals("same.bin.ergou.$suffix",File(path!!).name)
                if(suffix=="0")bases.add(File(File(path).parentFile,"same.bin.ergou"))
            }
            Splitter.inspect(bases.last().toPath()).requireComplete()
        }
        assertNotEquals(bases[0].parent,bases[1].parent)
        val out=File(bases[0].parentFile,"merged");Splitter.recombine(out.toPath(),bases[0].path)
        assertArrayEquals(ByteArray(10){it.toByte()},out.readBytes())
    }
    /** 取消选择后旧碎片不再补齐缺卷，其他页面的副本保持独立。 */
    @Test fun removedSelectionDoesNotReuseStaleChunks() {
        val context=InstrumentationRegistry.getInstrumentation().targetContext
        val ops=AndroidFileOps(context)
        val uris=listOf("0","1","volumes").map{DocumentsContract.buildDocumentUri(authority,"root/A/same.bin.ergou.$it")}
        val paths=uris.map{ops.resolveToPath(it)!!}
        val base=File(File(paths[0]).parentFile,"same.bin.ergou").toPath()
        Splitter.inspect(base).requireComplete()
        ops.retainSplitInputs(listOf(uris[0],uris[2]))
        assertFalse(File(paths[1]).exists())
        assertEquals(listOf(1),Splitter.inspect(base).missing())
        val second=AndroidFileOps(context)
        val secondPaths=listOf(uris[0],uris[2]).map{second.resolveToPath(it)!!}
        assertNotEquals(File(paths[0]).parent,File(secondPaths[0]).parent)
        assertEquals(listOf(1),Splitter.inspect(File(File(secondPaths[0]).parentFile,"same.bin.ergou").toPath()).missing())
        ops.resolveToPath(uris[1]);Splitter.inspect(base).requireComplete()
        ops.retainSplitInputs(emptyList())
        assertFalse(File(paths[0]).exists())
        assertTrue(File(secondPaths[0]).exists())
    }
    /** 完全改名的 SAF 文档依靠内嵌批次识别；取消选择不会复用已移除的卷。 */
    @Test fun renamedDocumentsUseContentAndRetainOnlyCurrentSelection() {
        val ops = AndroidFileOps(InstrumentationRegistry.getInstrumentation().targetContext)
        val first = DocumentsContract.buildDocumentUri(authority, "root/Renamed/QQ-photo.jpg")
        val last = DocumentsContract.buildDocumentUri(authority, "root/Renamed/attachment.bin")
        val firstPath = ops.resolveToPath(first, preserveName = true)!!
        val base = Splitter.inputBase(File(firstPath).toPath())!!
        assertEquals(listOf(1), Splitter.inspect(base).missing())
        val lastPath = ops.resolveToPath(last, preserveName = true)!!
        assertEquals(File(firstPath).parent, File(lastPath).parent)
        Splitter.inspect(base).requireComplete()
        val output = File(File(firstPath).parentFile, "merged")
        Splitter.recombine(output.toPath(), base.toString())
        assertArrayEquals(ByteArray(10) { it.toByte() }, output.readBytes())
        ops.retainSplitInputs(listOf(last))
        assertFalse(File(firstPath).exists())
        assertEquals(listOf(0), Splitter.inspect(base).missing())
    }

    /** 下载附加后缀、重名标记及长 Unicode 名称不会丢失分卷关系。 */
    @Test fun downloadSuffixAndLongNamesSurviveSafMaterialization() {
        for ((parent, names) in listOf(
            "Suffix" to listOf("same.bin.ergou.0 (1).下载", "same.bin.ergou (2).1"),
            "Long" to listOf("长".repeat(100) + ".ergou.0", "长".repeat(100) + ".ergou.1")
        )) {
            val ops = AndroidFileOps(InstrumentationRegistry.getInstrumentation().targetContext)
            val paths = names.map { name ->
                ops.resolveToPath(DocumentsContract.buildDocumentUri(authority, "root/$parent/$name"), preserveName = true)!!
            }
            val base = Splitter.inputBase(File(paths.first()).toPath())!!
            Splitter.inspect(base).requireComplete()
            assertEquals(1, Splitter.inputBases(paths.map { File(it).toPath() }).size)
        }
    }

    @Test fun wholeTreeRetainsNestedSameNameGroupsAndManifest() {
        val ops=AndroidFileOps(InstrumentationRegistry.getInstrumentation().targetContext)
        val tree=DocumentsContract.buildTreeDocumentUri(authority,"root")
        val path=ops.resolveDecryptTreeToPath(tree);assertNotNull(path)
        for(parent in listOf("A","B")) {
            val base=File(path,"$parent/same.bin.ergou").toPath()
            val info=Splitter.inspect(base);assertTrue(info.totalKnown());assertEquals(2,info.expectedCount());info.requireComplete()
        }
    }
}
