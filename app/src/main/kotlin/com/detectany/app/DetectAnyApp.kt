package com.detectany.app

import android.app.Application
import org.conscrypt.Conscrypt
import java.security.Security

/**
 * Conscrypt 接线（design.md D7 / 任务 1.4）：
 * Android 7 系统栈无 TLS 1.3 且 7.0/7.1.0 缺 ISRG 根 —— 内置 Conscrypt(支持 API 21+)
 * 作为首选 Provider，为 SecureChannel 的特征下发/CRL 通道提供统一 TLS 能力。
 */
class DetectAnyApp : Application() {

    override fun onCreate() {
        super.onCreate()
        installConscrypt()
    }

    private fun installConscrypt() {
        runCatching {
            if (Security.getProvider("Conscrypt") == null) {
                Security.insertProviderAt(Conscrypt.newProvider(), 1)
            }
        }
    }
}
