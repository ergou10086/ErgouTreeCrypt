# AndroidJUnitRunner 依赖应用侧 tracing；只保留测试启动所需 API，核心继续执行完整 R8 优化。
-keep class androidx.tracing.** { *; }
# Runner 的预编译字节码不会随应用映射 Kotlin/生命周期 API；保留其外部调用面。
# 不保留项目业务、Tink 或 BC 类，密码核心仍按 release 规则裁剪、优化、混淆。
-keep,allowoptimization class hbnu.project.ergoutreecrypt.android.FastValidationBridge { public *; }
-keep,allowoptimization class kotlin.** { *; }
-keep,allowoptimization class androidx.lifecycle.** { *; }
-keep,allowoptimization class androidx.concurrent.** { *; }
