import java.util.zip.ZipFile
plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
}

android {
    namespace = "com.detectany.app"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.detectany.app"
        minSdk = 24
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        ndk {
            abiFilters += listOf("arm64-v8a", "armeabi-v7a")
        }
    }

    buildTypes {
        release {
            // 混淆/加固策略在任务组 6（selfguard）落地，骨架期关闭保证可构建
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }
}

dependencies {
    // 全模块接线（design.md D1）
    implementation(project(":core:model"))
    implementation(project(":core:engine"))
    implementation(project(":core:rules"))
    implementation(project(":core:native-platform"))
    implementation(project(":collectors:fs-probe"))
    implementation(project(":collectors:properties"))
    implementation(project(":collectors:endpoints"))
    implementation(project(":collectors:app-fingerprint"))
    implementation(project(":collectors:memory-map"))
    implementation(project(":collectors:code-integrity"))
    implementation(project(":collectors:behavior-probe"))
    implementation(project(":feature:attestation"))
    implementation(project(":feature:report"))
    implementation(project(":data:signature"))
    implementation(project(":compat:platform"))
    implementation(project(":selfguard"))

    implementation(libs.androidx.activity.compose)

    androidTestImplementation(libs.androidx.test.ext.junit)
    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.uiautomator)
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.tooling.preview)
    implementation(libs.androidx.compose.icons.extended)
    implementation(libs.androidx.navigation.compose)
}

// ---------------------------------------------------------------------------
// 16KB 页对齐门禁（Android 15+ 16KB 设备强制；双重校验，产物越界即失败）
//  1) APK zip 层：zipalign -c -P 16
//  2) ELF 层：每个打包 so 的全部 PT_LOAD 段 p_align >= 16384
// 挂接 packageDebug / packageRelease / packageDebugAndroidTest；独立执行：
//   ./gradlew :app:verify16kAlignment
// ---------------------------------------------------------------------------
fun leShort(b: ByteArray, off: Int): Int = (b[off].toInt() and 0xFF) or ((b[off + 1].toInt() and 0xFF) shl 8)

fun leInt(b: ByteArray, off: Int): Long {
    var v = 0L
    for (i in 3 downTo 0) v = (v shl 8) or (b[off + i].toLong() and 0xFF)
    return v
}

fun leLong(b: ByteArray, off: Int): Long {
    var v = 0L
    for (i in 7 downTo 0) v = (v shl 8) or (b[off + i].toLong() and 0xFF)
    return v
}

/** 返回 (PT_LOAD 索引, p_align) 列表；解析失败返回空表。 */
fun ptLoadAligns(bytes: ByteArray): List<Pair<Int, Long>> {
    if (bytes.size < 64) return emptyList()
    val is64 = bytes[4] == 2.toByte()
    val phoff = (if (is64) leLong(bytes, 32) else leInt(bytes, 28)).toInt()
    val phentsize = if (is64) leShort(bytes, 54) else leShort(bytes, 42)
    val phnum = if (is64) leShort(bytes, 56) else leShort(bytes, 44)
    if (phentsize <= 0 || phnum <= 0 || phoff <= 0 || phoff + phnum * phentsize > bytes.size) return emptyList()
    val out = mutableListOf<Pair<Int, Long>>()
    for (i in 0 until phnum) {
        val off = phoff + i * phentsize
        if (leInt(bytes, off) == 1L) { // PT_LOAD
            out += i to (if (is64) leLong(bytes, off + 48) else leInt(bytes, off + 28))
        }
    }
    return out
}

val verify16kAlignment by tasks.registering {
    group = "verification"
    description = "16KB page-alignment gate: zipalign -P 16 on APKs + PT_LOAD p_align>=16384 for all packaged .so"
    doLast {
        val sdk = android.sdkDirectory
        val zipalign = sdk.resolve("build-tools").listFiles { f -> f.isDirectory }
            ?.maxByOrNull { it.name }?.resolve("zipalign")
            ?: throw GradleException("zipalign not found under ${sdk.resolve("build-tools")}")
        if (!zipalign.canExecute()) throw GradleException("zipalign not executable: $zipalign")

        val apkRoots = listOf(
            layout.buildDirectory.dir("outputs/apk/debug"),
            layout.buildDirectory.dir("outputs/apk/release"),
            layout.buildDirectory.dir("outputs/apk/androidTest/debug"),
        )
        val apks = apkRoots.flatMap { dir ->
            dir.get().asFile.walkTopDown().filter { it.isFile && it.extension == "apk" }.toList()
        }.sortedBy { it.absolutePath }
        if (apks.isEmpty()) {
            logger.lifecycle("[16KB-GATE] 无 APK 产物，跳过（先 assemble）")
            return@doLast
        }

        var failed = false
        for (apk in apks) {
            // 1) zip 层
            val proc = ProcessBuilder(zipalign.absolutePath, "-c", "-P", "16", "-v", "4", apk.absolutePath)
                .redirectErrorStream(true).start()
            val out = proc.inputStream.bufferedReader().readText()
            if (proc.waitFor() != 0) {
                failed = true
                logger.error("[16KB-GATE] zipalign 未通过: ${apk.name}")
                out.lineSequence().filter { !it.contains("OK") && it.isNotBlank() }.take(12).forEach { logger.error("    $it") }
            } else {
                logger.lifecycle("[16KB-GATE] zipalign OK: ${apk.name}")
            }

            // 2) ELF 层
            ZipFile(apk).use { zip ->
                for (e in zip.entries()) {
                    if (!e.name.endsWith(".so")) continue
                    val bytes = zip.getInputStream(e).readBytes()
                    val aligns = ptLoadAligns(bytes)
                    if (aligns.isEmpty()) {
                        logger.warn("[16KB-GATE] ${apk.name}!${e.name}: 未解析到 PT_LOAD（非 ELF 或损坏）")
                        continue
                    }
                    for ((idx, align) in aligns) {
                        if (align < 16384L) {
                            failed = true
                            logger.error("[16KB-GATE] ${apk.name}!${e.name} PT_LOAD[$idx] p_align=$align < 16384")
                        }
                    }
                }
            }
        }
        if (failed) throw GradleException("16KB 对齐门禁失败（见上方 [16KB-GATE] 输出）")
        logger.lifecycle("[16KB-GATE] 全部 ${apks.size} 个 APK 通过 16KB 对齐校验")
    }
}

tasks.matching { it.name in setOf("packageDebug", "packageRelease", "packageDebugAndroidTest") }
    .configureEach { finalizedBy(verify16kAlignment) }
tasks.named("check") { dependsOn(verify16kAlignment) }
