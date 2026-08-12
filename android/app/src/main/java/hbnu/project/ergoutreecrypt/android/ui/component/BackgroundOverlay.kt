package hbnu.project.ergoutreecrypt.android.ui.component

import android.content.Context
import android.graphics.BitmapFactory
import android.net.Uri
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.painter.BitmapPainter
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import hbnu.project.ergoutreecrypt.android.platform.AndroidSettings
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * 全屏背景图片叠加层。
 *
 * <p>根据 DataStore 中存储的图片 URI 和透明度设置加载并显示背景图片。
 * 图片以 {@link ContentScale#Crop} 模式填满整个屏幕，透明度由设置控制。
 *
 * <p>用法：在内容区域的最外层 Box 中，将此组件置于最底层。
 *
 * @author ErgouTree
 * @since 2026/8/12
 */
@Composable
fun BackgroundOverlay(modifier: Modifier = Modifier) {
    val ctx = LocalContext.current
    val settings = remember { AndroidSettings(ctx) }

    val bgUri by settings.backgroundImageUri.collectAsState(initial = null)
    val opacity by settings.backgroundOpacity.collectAsState(initial = 30)

    if (bgUri.isNullOrBlank()) return

    var bitmap by remember(bgUri) { mutableStateOf<android.graphics.Bitmap?>(null) }

    // 在 IO 线程中加载图片
    LaunchedEffect(bgUri) {
        // 回收旧 Bitmap，防止 native 内存泄漏
        bitmap?.recycle()
        bitmap = withContext(Dispatchers.IO) {
            loadBitmapFromUri(ctx, bgUri!!)
        }
    }

    // 离开组合时回收 Bitmap
    DisposableEffect(Unit) {
        onDispose {
            bitmap?.recycle()
        }
    }

    bitmap?.let { bmp ->
        Image(
            painter = BitmapPainter(bmp.asImageBitmap()),
            contentDescription = "背景图片",
            modifier = modifier.fillMaxSize(),
            contentScale = ContentScale.Crop,
            alpha = opacity / 100f
        )
    }
}

/**
 * 从 Content URI 安全加载 Bitmap。
 *
 * <p>使用采样缩小大图片以避免 OOM：目标宽高不超过 2048px。
 *
 * @param ctx 上下文
 * @param uriString content:// 格式的 URI 字符串
 * @return 加载成功返回 Bitmap，失败返回 null
 */
private fun loadBitmapFromUri(ctx: Context, uriString: String): android.graphics.Bitmap? {
    return try {
        val uri = Uri.parse(uriString)
        // 先仅解码尺寸以计算采样率
        val options = BitmapFactory.Options().apply {
            inJustDecodeBounds = true
        }
        ctx.contentResolver.openInputStream(uri)?.use { stream ->
            BitmapFactory.decodeStream(stream, null, options)
        }

        // 计算采样率：目标最大 2048px
        val maxDim = 2048
        val scale = maxOf(
            1,
            maxOf(options.outWidth, options.outHeight) / maxDim
        )
        val sampleSize = Integer.highestOneBit(scale)

        val decodeOptions = BitmapFactory.Options().apply {
            inSampleSize = sampleSize
        }
        ctx.contentResolver.openInputStream(uri)?.use { stream ->
            BitmapFactory.decodeStream(stream, null, decodeOptions)
        }
    } catch (e: Exception) {
        null
    }
}
