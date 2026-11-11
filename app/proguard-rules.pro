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
