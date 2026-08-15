package hbnu.project.ergoutreecrypt.android.ui.component

/**
 * 隐写载体格式常量与判定工具。
 *
 * <p>统一维护隐藏/提取页面支持的载体文件格式，供文件选择器过滤与格式校验共用，
 * 避免多处重复定义导致不一致。
 *
 * @author ErgouTree
 * @since 2026/8/13
 */

/** 支持的所有载体文件扩展名（含 "." 前缀，小写） */
val SUPPORTED_CARRIER_EXTENSIONS = setOf(
    ".png", ".zip", ".pdf", ".wav", ".flac", ".mp4", ".m4a", ".m4v"
)

/** 支持的所有载体文件 MIME 类型，供文件选择器按类型过滤显示 */
val SUPPORTED_CARRIER_MIME_TYPES = arrayOf(
    "image/png",
    "application/zip",
    "application/pdf",
    "audio/wav", "audio/x-wav",
    "audio/flac", "audio/x-flac",
    "video/mp4",
    "audio/mp4"
)

/** 可显示图像预览的载体扩展名 */
private val IMAGE_CARRIER_EXTENSIONS = setOf(".png")

/**
 * 检测文件扩展名是否为支持的载体类型。
 *
 * @param fileName 文件名
 * @return 若为支持的载体类型返回 true
 */
fun isSupportedCarrier(fileName: String): Boolean {
    val lower = fileName.lowercase()
    return SUPPORTED_CARRIER_EXTENSIONS.any { lower.endsWith(it) }
}

/**
 * 检测文件扩展名是否可显示图像预览。
 *
 * @param fileName 文件名
 * @return 若为图像类型返回 true
 */
fun isImageCarrier(fileName: String): Boolean {
    val lower = fileName.lowercase()
    return IMAGE_CARRIER_EXTENSIONS.any { lower.endsWith(it) }
}
