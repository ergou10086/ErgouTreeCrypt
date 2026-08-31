import java.util.Properties

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
}

// ============================================================
// 任务：从桌面端同步共享核心源码到 Android 构建目录
// 排除桌面特有层
// ============================================================
val syncCoreLibs by tasks.registering(Copy::class) {
    from("../../src/main/java") {
        exclude(
            // 桌面 JavaFX UI 层
            "hbnu/project/ergoutreecrypt/ui/**",
            // 桌面入口类
            "hbnu/project/ergoutreecrypt/Launcher.java",
            "hbnu/project/ergoutreecrypt/PicocryptApplication.java",
            // 桌面 java.util.prefs 设置
            "hbnu/project/ergoutreecrypt/settings/SettingsManager.java",
            // 图像隐写 — 依赖 java.awt.BufferedImage / javax.imageio（Android 不可用）
            "hbnu/project/ergoutreecrypt/stego/**",
            // JPMS 模块声明
            "module-info.java"
        )
    }
    into(layout.buildDirectory.dir("sync-core"))
}

val syncI18n by tasks.registering(Copy::class) {
    from("../../src/main/resources/hbnu/project/ergoutreecrypt/i18n")
    into("src/main/resources/hbnu/project/ergoutreecrypt/i18n")
}

// ============================================================
// 版本号：文件级变量，供 android 块和 APK 重命名任务共用
// ============================================================
val appVersionName = "2.5.0"
val appVersionCode = 20500

// ============================================================
// 签名配置：从 keystore.properties 读取（该文件已加入 .gitignore，不提交到仓库）
// 若文件不存在（如 CI 环境），release 将回退为未签名构建
// ============================================================
val keystorePropertiesFile = rootProject.file("keystore.properties")
val keystoreProperties = Properties().apply {
    if (keystorePropertiesFile.exists()) {
        keystorePropertiesFile.inputStream().use { load(it) }
    }
}

android {
    namespace = "hbnu.project.ergoutreecrypt.android"
    compileSdk = 36

    buildFeatures {
        buildConfig = true
    }

    defaultConfig {
        applicationId = "hbnu.project.ergoutreecrypt"
        minSdk = 26
        targetSdk = 35
        versionCode = appVersionCode
        versionName = appVersionName

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        // 将版本名注入 BuildConfig，供运行时显示
        buildConfigField("String", "APP_VERSION_NAME", "\"${appVersionName}\"")
        buildConfigField("int", "APP_VERSION_CODE", "${appVersionCode}")

        // 原生 Argon2（libargon2）目标 ABI；未打包 ABI 的设备回退纯 Java 离堆
        ndk {
            abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64")
        }
    }

    signingConfigs {
        if (keystorePropertiesFile.exists()) {
            create("release") {
                storeFile = file(keystoreProperties["storeFile"] as String)
                storePassword = keystoreProperties["storePassword"] as String
                keyAlias = keystoreProperties["keyAlias"] as String
                keyPassword = keystoreProperties["keyPassword"] as String
            }
        }
    }

    buildTypes {
        // 调试版本：不混淆，可调试，应用名含 Debug 后缀
        debug {
            isMinifyEnabled = false
            isDebuggable = true
            applicationIdSuffix = ".debug"
            versionNameSuffix = "-debug"
        }
        // 发布版本：开启混淆和资源缩减
        release {
            if (keystorePropertiesFile.exists()) {
                signingConfig = signingConfigs.getByName("release")
            }
            isMinifyEnabled = true
            isShrinkResources = true
            isDebuggable = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }

    compileOptions {
        isCoreLibraryDesugaringEnabled = true
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }

    kotlinOptions {
        jvmTarget = "21"
    }

    // ============================================================
    // sourceSets：Android 自有代码 + 同步后的共享核心代码
    // ============================================================
    sourceSets {
        named("main") {
            java.srcDirs(
                "src/main/java",
                layout.buildDirectory.dir("sync-core")  // 同步任务产物目录
            )
        }
    }

    // 原生 Argon2：CMake 编译 vendored libargon2 + JNI 桥
    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }
}

// 编译前自动同步共享核心代码与 i18n 文案（桌面端 properties 为源）
tasks.named("preBuild") { dependsOn(syncCoreLibs, syncI18n) }

// ============================================================
// 自定义 APK 输出文件名：ErgouTreeCrypt-v2.5.0-release.apk
// 原理：在所有 assemble 任务完成后，扫描 outputs/apk 目录并复制一份重命名后的 APK
// ============================================================
val renameApks by tasks.registering {
    doLast {
        layout.buildDirectory.get().asFile
            .resolve("outputs/apk")
            .walkTopDown()
            // 跳过上一次构建已重命名的 APK，避免把文件复制到自身（overwrite 会先删源文件导致 FileNotFoundException）
            .filter { it.extension == "apk" && !it.name.startsWith("ErgouTreeCrypt-v") }
            .forEach { apk ->
                val dirName = apk.parentFile.name
                val newName = "ErgouTreeCrypt-v${appVersionName}-${dirName}.apk"
                apk.copyTo(apk.parentFile.resolve(newName), overwrite = true)
            }
    }
}
tasks.matching { it.name.startsWith("assemble") }.configureEach {
    finalizedBy(renameApks)
}

dependencies {
    // ============================================================
    // 共享核心加密依赖（版本与桌面端 pom.xml 严格一致）
    // ============================================================
    implementation(libs.bouncycastle)
    implementation(libs.commons.compress)
    implementation(libs.zip4j)
    implementation(libs.tukaani.xz)
    implementation(libs.zstd.jni)

    // ============================================================
    // AndroidX 基础
    // ============================================================
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.appcompat)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.androidx.navigation.compose)
    implementation(libs.androidx.datastore.preferences)

    // ============================================================
    // Compose UI
    // ============================================================
    implementation(platform(libs.compose.bom))
    implementation(libs.compose.material3)
    implementation(libs.compose.ui)
    implementation(libs.compose.ui.graphics)
    implementation(libs.compose.ui.tooling.preview)
    implementation("androidx.compose.material:material-icons-extended")
    debugImplementation(libs.compose.ui.tooling)
    debugImplementation(libs.compose.ui.test.manifest)

    // ============================================================
    // Kotlin 协程
    // ============================================================
    implementation(libs.kotlinx.coroutines.android)

    // ============================================================
    // 安全 / 生物识别（可选功能，Phase 3 启用）
    // ============================================================
    implementation(libs.androidx.security.crypto)
    implementation(libs.androidx.biometric)

    // ============================================================
    // Java 21 desugar（提供 java.nio.file 等 API 兼容低版本 Android）
    // ============================================================
    coreLibraryDesugaring(libs.androidx.core.desugar)

    // ============================================================
    // 测试
    // ============================================================
    testImplementation(libs.junit)
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.9.0")
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
    androidTestImplementation(libs.androidx.ui.test.junit4)
}
