package hbnu.project.ergoutreecrypt.android

import android.graphics.BitmapFactory
import android.graphics.ImageDecoder
import androidx.test.filters.SdkSuppress
import androidx.test.ext.junit.runners.AndroidJUnit4
import hbnu.project.ergoutreecrypt.imagecrypt.png.PixelPngWriter
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Test
import org.junit.runner.RunWith
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer

/**
 * Android 平台图片解码器对 EGTC-IMG RGB8 PNG 容器的兼容测试。
 *
 * <p>测试只验证 Phase 2 外层容器能被平台正常打开；协议帧与跨端恢复属于后续互操作阶段。
 *
 * @author ErgouTree
 * @since 2026/9/16
 */
@RunWith(AndroidJUnit4::class)
class ImageCryptPngCompatibilityTest {

    /**
     * BitmapFactory 必须能在全部受支持 Android API 上打开 writer 产物。
     */
    @Test
    fun bitmapFactoryOpensGeneratedContainer() {
        val png = generatedPng()
        val bitmap = BitmapFactory.decodeByteArray(png, 0, png.size)

        assertNotNull(bitmap)
        assertEquals(CANVAS_WIDTH, bitmap.width)
        assertEquals(CANVAS_HEIGHT, bitmap.height)
        bitmap.recycle()
    }

    /**
     * API 28 起的 ImageDecoder 必须能打开同一 writer 产物。
     */
    @Test
    @SdkSuppress(minSdkVersion = 28)
    fun imageDecoderOpensGeneratedContainer() {
        val png = generatedPng()
        val bitmap = ImageDecoder.decodeBitmap(ImageDecoder.createSource(ByteBuffer.wrap(png)))

        assertEquals(CANVAS_WIDTH, bitmap.width)
        assertEquals(CANVAS_HEIGHT, bitmap.height)
        bitmap.recycle()
    }

    /**
     * 生成包含确定性逻辑载荷的测试 PNG。
     *
     * @return PNG 文件字节
     */
    private fun generatedPng(): ByteArray {
        val payload = ByteArray(300) { index -> (index * 17 + 5).toByte() }
        val output = ByteArrayOutputStream()
        PixelPngWriter().write(
            output,
            CANVAS_WIDTH,
            CANVAS_HEIGHT,
            ByteArrayInputStream(payload),
            payload.size.toLong()
        )
        return output.toByteArray()
    }

    /**
     * 测试画布与稳定标识。
     */
    private companion object {

        /**
         * 测试画布宽度。
         */
        const val CANVAS_WIDTH = 16

        /**
         * 测试画布高度。
         */
        const val CANVAS_HEIGHT = 10
    }
}
