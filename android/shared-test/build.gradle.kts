plugins {
    id("java-library")
}

java {
    sourceCompatibility = JavaVersion.VERSION_21
    targetCompatibility = JavaVersion.VERSION_21
}

// ============================================================
// 同步共享源码（排除 module-info.java 和桌面专用代码）
// ============================================================
val syncCoreLibs by tasks.registering(Copy::class) {
    from("../../src/main/java") {
        exclude(
            "module-info.java",
            "hbnu/project/ergoutreecrypt/ui/**",
            "hbnu/project/ergoutreecrypt/stego/**",
            "hbnu/project/ergoutreecrypt/filestego/**",
            "hbnu/project/ergoutreecrypt/Launcher.java",
            "hbnu/project/ergoutreecrypt/PicocryptApplication.java"
        )
    }
    into(layout.buildDirectory.dir("sync-core"))
}

val syncTests by tasks.registering(Copy::class) {
    from("../../src/test/java") {
        exclude(
            "hbnu/project/ergoutreecrypt/stego/**",
            "hbnu/project/ergoutreecrypt/filestego/**",
            "hbnu/project/ergoutreecrypt/mediacrypt/**"
        )
    }
    into(layout.buildDirectory.dir("sync-test"))
}

// 同步 i18n 资源，供共享核心的 Messages 在测试类路径下加载
val syncTestResources by tasks.registering(Copy::class) {
    from("../../src/main/resources") {
        include("hbnu/project/ergoutreecrypt/i18n/messages*.properties")
    }
    into(layout.buildDirectory.dir("sync-test-resources"))
}

sourceSets {
    main {
        java.srcDirs(layout.buildDirectory.dir("sync-core"))
    }
    test {
        java.srcDirs(layout.buildDirectory.dir("sync-test"))
        resources.srcDirs(layout.buildDirectory.dir("sync-test-resources"))
    }
}

tasks.named("compileJava") { dependsOn(syncCoreLibs) }
tasks.named("compileTestJava") { dependsOn(syncTests) }
tasks.named("processTestResources") { dependsOn(syncTestResources) }

dependencies {
    // 共享核心依赖（与桌面端一致）
    implementation("org.bouncycastle:bcprov-jdk18on:1.78.1")
    implementation("org.apache.commons:commons-compress:1.27.1")
    implementation("net.lingala.zip4j:zip4j:2.11.5")
    implementation("org.tukaani:xz:1.10")

    // JUnit 5（使用 BOM 确保版本对齐）
    testImplementation(platform("org.junit:junit-bom:5.12.1"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.withType<Test> {
    useJUnitPlatform()
    // Argon2id 需要 ~1 GiB 堆外内存，CI 环境通常无法满足
    maxHeapSize = "1536m"
    // 排除需要完整测试资源或桌面环境的集成测试
    exclude("**/Argon2KdfTest.class")
    exclude("**/VolumeRoundtripTest.class")
    exclude("**/BinaryFileRoundtripTest.class")
    exclude("**/EncryptDepthTest.class")
    exclude("**/DualDeniabilityTest.class")
    exclude("**/FolderCryptRoundtripTest.class")
    exclude("**/EncryptCompressTest.class")
    exclude("**/ProgressPhaseI18nTest.class")
    exclude("**/ArchiveProgressPhaseTest.class")
    exclude("**/ParallelProgressAggregatorTest.class")
    exclude("**/HeaderTest.class")
    exclude("**/NativeArchivePasswordTest.class")
}
