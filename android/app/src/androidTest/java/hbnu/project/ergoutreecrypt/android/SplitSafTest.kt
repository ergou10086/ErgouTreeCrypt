package hbnu.project.ergoutreecrypt.android

import android.provider.DocumentsContract
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import hbnu.project.ergoutreecrypt.android.platform.AndroidFileOps
import hbnu.project.ergoutreecrypt.fileops.Splitter
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/** 实际 ContentResolver/SAF 回退，覆盖多选、同名不同目录和整目录授权。 */
@RunWith(AndroidJUnit4::class)
class SplitSafTest {
    private val authority="hbnu.project.ergoutreecrypt.split.tests"
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
