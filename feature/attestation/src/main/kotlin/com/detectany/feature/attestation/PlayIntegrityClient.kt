package com.detectany.feature.attestation

/**
 * Play Integrity 客户端（Phase 2 服务端通道脚手架）：
 * 客户端只发起 requestIntegrityToken，verdict 解码/验证在服务端完成
 * （specs/attestation-verify：不在被测设备上做最终信任判定）。
 *
 * 装配前提：Google Play Console 项目 + 服务账号密钥 + Play Integrity API 启用。
 */
class PlayIntegrityClient(
    /** Google Play services 的 ApplicationInfo（由装配层注入） */
    private val requestToken: (String) -> String?,
) {
    data class IntegrityResult(
        val token: String?,
        val error: String? = null,
    )

    /**
     * 发起 Play Integrity 请求（Standard，毫秒级）。
     * @param requestHash 服务端生成的防重放哈希（绑定会话）
     * @return token 或 null（GMS 不可用/离线）
     */
    fun requestIntegrity(requestHash: String): IntegrityResult {
        val token = requestToken(requestHash)
            ?: return IntegrityResult(null, "Google Play services unavailable or offline")
        return IntegrityResult(token)
    }
}

/**
 * Play Integrity 服务端解码器（部署在应用后端，不在设备上）。
 * 依赖：Google Play Integrity API 服务账号 + Google API 客户端库。
 *
 * 验证步骤：
 * 1. 用 Play Console 下发的 AES 密钥本地解密 JWE
 * 2. 用 EC 公钥验签 JWS
 * 3. 校验 requestHash 回显、包签名、时间戳
 * 4. 检查 deviceIntegrity 字段（MEETS_BASIC/DEVICE/STRONG_INTEGRITY）
 */
object PlayIntegrityServerDecoder {
    data class DecodedVerdict(
        val appIdRecognitionVerdict: String?,
        val deviceRecognitionVerdict: List<String>,
        val appLicensingVerdict: String?,
        val requestHashMatch: Boolean,
    )

    /**
     * 服务端解码（伪代码骨架——实际需 Google API 客户端库）：
     * decryptIntegrityToken(token, aesKey) → verifyJws(jws, ecPublicKey) → parseVerdict(json)
     */
    fun decodeSkeleton(): String = "服务端解码需部署 Google API 客户端；详见 developer.android.com/google/play/integrity"
}
