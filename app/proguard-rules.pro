# Detect-Any release rules (P3, 2026-11-11)

# kotlinx.serialization — signature DB / report models
-keepattributes *Annotation*, InnerClasses, Signature
-dontnote kotlinx.serialization.**
-keepclassmembers class com.detectany.data.signature.** { *** Companion; }
-keepclasseswithmembers class com.detectany.** { kotlinx.serialization.KSerializer serializer(...); }
-keep,includedescriptorclasses class com.detectany.**$$serializer { *; }

# JNI surface — native probes resolve by name
-keepclasseswithmembernames class com.detectany.core.nativeplatform.** { native <methods>; }
-keep class com.detectany.core.nativeplatform.** { *; }

# SelfGuard XOR constants + JNI
-keep class com.detectany.selfguard.** { *; }

# Attestation ASN.1/BouncyCastle
-keep class org.bouncycastle.** { *; }
-dontwarn org.bouncycastle.**

# Collector SPI — reflection-free but keep rules engine data classes' enum values
-keepclassmembers enum com.detectany.core.model.** { *; }

# R8 校准（2026-11-16 Redmi A15 实证）：R8 重写 app 内调用点后移除 kotlin.jvm.internal.*，
# 而 androidTest（androidx.test AppComponentFactoryRegistry）经 app classloader 解析
# kotlin/jvm/internal/Intrinsics → minified release 下 instrument 启动即 NoClassDefFoundError
-keep class kotlin.jvm.internal.** { *; }
# androidTest（androidx.test runner）经 app classloader 解析 androidx.tracing
#（compose 传递依赖；R8 视 app 未用而裁掉 → release 下 instrument 崩）
-keep class androidx.tracing.** { *; }
# androidTest 大量经 app classloader 用 kotlin-stdlib 公共面（Function0 等）——逐类补不完，
# 整面保留（生产 release 不加载 androidx.test，此 keep 仅 instrument 校准构建需要）
-keep class kotlin.** { *; }
-keep class kotlinx.** { *; }
# 自有类面 keep：androidTest 按原名解析 com.detectany.**（R8 混淆改名致 instrument 失败）。
# 本项目 Apache 2.0 开源，混淆无防护价值——整包保留（R8 收益：依赖裁剪+优化）
-keep class com.detectany.** { *; }
