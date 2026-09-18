# Add project specific ProGuard rules here.
# You can control the set of applied configuration files using the
# proguardFiles setting in build.gradle.
#
# For more details, see
#   http://developer.android.com/guide/developing/tools/proguard.html

# If your project uses WebView with JS, uncomment the following
# and specify the fully qualified class name to the JavaScript interface
# class:
#-keepclassmembers class fqcn.of.javascript.interface.for.webview {
#   public *;
#}

# 保留行号信息，使 release 崩溃堆栈仍带行号；配合 mapping.txt 可还原完整调用栈。
# 类名/方法名依旧会被混淆，只是额外保留「源文件别名 + 行号」两个调试属性。
-keepattributes SourceFile,LineNumberTable

# 把源文件名统一改写为 SourceFile，避免混淆后泄露真实文件名（配合上一条一起用）
-renamesourcefileattribute SourceFile

# 保留 JNI 原生 Argon2 桥接的 native 方法名，否则 R8 混淆后 loadLibrary 找不到符号
-keepclasseswithmembernames,includedescriptorclasses class hbnu.project.ergoutreecrypt.crypto.NativeArgon2 {
    native <methods>;
}

# ============================================================

# 纠错载体的 Android 像素桥由共享核心通过固定类名和方法名反射调用。
-keep class hbnu.project.ergoutreecrypt.imagecrypt.robust.DesktopRobustImageDecoder {
    public static *** decode(...);
}
-keep class hbnu.project.ergoutreecrypt.imagecrypt.robust.DesktopRobustPayloadTranscoder {
    public static *** transcode(...);
}
# BouncyCastle 说明（无需 keep 规则，此处仅作记录）
#
# 本项目在 Android 侧只使用 BC 的低层 API（org.bouncycastle.crypto.*，
# 如 SHA3Digest / GCMBlockCipher / AESEngine），这些是直接引用，
# R8 会随调用链一并保留，因此 JCA Provider 实现层
# （org.bouncycastle.jcajce.provider.*）被整包裁剪是预期且安全的结果。
#
# 若将来在 Android 侧新增「按算法名」的查找（Cipher/Mac/MessageDigest
# 的 getInstance 且指定 BC），则必须补上下面两条，否则运行时会因
# Provider 表中记录的类名已被删除/改名而抛 NoSuchAlgorithmException：
#   -keep class org.bouncycastle.jcajce.provider.** { *; }
#   -keep class org.bouncycastle.jce.provider.** { *; }
# ============================================================
