package com.detectany.data.signature

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.security.KeyFactory
import java.security.PublicKey
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

/** 签名更新信封（任务 4.2）。签名覆盖 payload 的规范 JSON 字节。 */
@Serializable
data class SignedUpdate(
    val version: Long,
    /** 增量模式的基线版本；null = 全量 */
    val baseVersion: Long? = null,
    val payload: SignatureDb,
    /** ed25519 对 payloadBytes 的签名（base64） */
    val signatureBase64: String,
)

object UpdateCodec {
    val json: Json get() = BundledSignatureDb.json

    /** payload 的规范字节（签名与验证的共同输入）。 */
    fun payloadBytes(payload: SignatureDb): ByteArray =
        BundledSignatureDb.json.encodeToString(SignatureDb.serializer(), payload).toByteArray(Charsets.UTF_8)
}

/** ed25519 验签器（内置公钥；测试与运营期可注入密钥对）。 */
class SignatureVerifier(publicKeyX509Base64: String) {

    private val publicKey: PublicKey = KeyFactory.getInstance("Ed25519")
        .generatePublic(X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyX509Base64)))

    fun verify(update: SignedUpdate): Boolean = runCatching {
        val sig = Signature.getInstance("Ed25519")
        sig.initVerify(publicKey)
        sig.update(UpdateCodec.payloadBytes(update.payload))
        sig.verify(Base64.getDecoder().decode(update.signatureBase64))
    }.getOrDefault(false)
}

/** 更新应用结果。 */
sealed interface ApplyResult {
    data class Applied(val db: SignatureDb) : ApplyResult
    data class Rejected(val reason: String, val kept: SignatureDb) : ApplyResult
}

/**
 * 特征库存储（任务 4.2）：验证 → 版本检查 → 增量合并 → 装载即生效。
 * 约束：单次增量 ≤200KB；任何拒绝路径 MUST 保留旧版本。
 */
class SignatureStore(
    initial: SignatureDb = BundledSignatureDb.db,
    /** null = 更新通道未装配（仅内置基线；发布密钥装配后注入） */
    private val verifier: SignatureVerifier? = null,
    private val maxDeltaBytes: Int = 200 * 1024,
) {
    @Volatile
    private var currentDb: SignatureDb = initial

    fun current(): SignatureDb = currentDb

    fun apply(update: SignedUpdate): ApplyResult {
        val bytes = UpdateCodec.payloadBytes(update.payload)
        if (bytes.size > maxDeltaBytes) {
            return ApplyResult.Rejected("payload ${bytes.size}B exceeds cap $maxDeltaBytes", currentDb)
        }
        if (verifier == null) {
            return ApplyResult.Rejected("update channel not configured (bundled only)", currentDb)
        }
        if (!verifier.verify(update)) {
            return ApplyResult.Rejected("bad ed25519 signature", currentDb)
        }
        if (update.version <= currentDb.version) {
            return ApplyResult.Rejected("version regression: ${update.version} <= ${currentDb.version}", currentDb)
        }
        val merged: SignatureDb = if (update.baseVersion == null) {
            update.payload.copy(version = update.version)
        } else {
            if (update.baseVersion != currentDb.version) {
                return ApplyResult.Rejected("delta base mismatch: expected ${currentDb.version}, got ${update.baseVersion}", currentDb)
            }
            merge(currentDb, update.payload, update.version)
        }
        currentDb = merged
        return ApplyResult.Applied(merged)
    }

    /** 增量合并：按 id 去重替换、追加新条目；黑名单/基线按 key 去重合并。 */
    internal fun merge(base: SignatureDb, delta: SignatureDb, newVersion: Long): SignatureDb = SignatureDb(
        version = newVersion,
        paths = mergeById(base.paths, delta.paths) { it.id },
        apps = mergeById(base.apps, delta.apps) { it.id },
        sockets = mergeById(base.sockets, delta.sockets) { it.id },
        properties = mergeById(base.properties, delta.properties) { it.id },
        supercalls = base.supercalls + delta.supercalls.filter { d -> base.supercalls.none { it.family == d.family } },
        keyboxBlacklist = base.keyboxBlacklist + delta.keyboxBlacklist.filterNot { d -> base.keyboxBlacklist.any { it.serialHex == d.serialHex } },
        deviceBaselines = base.deviceBaselines + delta.deviceBaselines.filterNot { d -> base.deviceBaselines.any { it.model == d.model } },
    )

    private fun <T> mergeById(base: List<T>, delta: List<T>, id: (T) -> String): List<T> {
        val byId = base.associateBy(id).toMutableMap()
        delta.forEach { byId[id(it)] = it }
        return byId.values.toList()
    }
}
