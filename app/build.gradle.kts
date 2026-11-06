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
    implementation(libs.conscrypt.android)

    androidTestImplementation(libs.androidx.test.ext.junit)
    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.uiautomator)
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.tooling.preview)
}
