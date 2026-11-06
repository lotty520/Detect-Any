package com.detectany.app

import android.app.Application
import java.security.Security

/**
 * TLS Provider 接线（design.md D7 / 任务 1.4，2026-11-06 修订）：
 *
 * 原「内置 Conscrypt AAR」方案已移除——conscrypt-android 2.5.2 的 libconscrypt_jni.so
 * PT_LOAD p_align=4096，无 16KB 对齐版本可用，而 Play 对 targetSdk 35+ 已强制 16KB
 * （16KB 门禁 :app:verify16kAlignment 会拦截该依赖）。
 *
 * 现行分层：
 * - API ≥29：平台自带 TLS 1.3，无需处理；
 * - API 24-28：优先启用 GMS 下发的 Conscrypt Provider（"GmsCore_OpenSSL"，随 Play services
 *   更新分发、驻留 GMS APK 内，不进本包），同样提供 TLS 1.3；
 * - GMS 缺失/过旧的 Android 7 设备：回落平台 TLS 1.2 —— SecureChannel 的自有信任锚 +
 *   SPKI pinning 不依赖 TLS 版本，通道安全性不受影响（仅握手协议降级）。
 */
class DetectAnyApp : Application() {

    override fun onCreate() {
        super.onCreate()
        installGmsConscryptIfAvailable()
    }

    /** API <29 且设备装有 GMS Conscrypt 时将其提为首选 Provider（不引入本包 so）。 */
    private fun installGmsConscryptIfAvailable() {
        runCatching {
            if (android.os.Build.VERSION.SDK_INT < 29) {
                val gms = Security.getProvider("GmsCore_OpenSSL")
                if (gms != null && Security.getProviders().firstOrNull() !== gms) {
                    Security.removeProvider("GmsCore_OpenSSL")
                    Security.insertProviderAt(gms, 1)
                }
            }
        }
    }
}
