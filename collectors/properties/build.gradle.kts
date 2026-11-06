plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
}

android {
    namespace = "com.detectany.collectors.props"
    compileSdk = 35
    defaultConfig { minSdk = 24 }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
}

dependencies {
    api(project(":core:model"))
    api(project(":core:native-platform"))
    implementation(project(":compat:platform"))
    testImplementation(kotlin("test"))
    testImplementation(project(":core:rules"))
}
