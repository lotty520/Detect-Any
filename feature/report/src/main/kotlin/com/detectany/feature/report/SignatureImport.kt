package com.detectany.feature.report

import com.detectany.data.signature.ApplyResult
import com.detectany.data.signature.BundledSignatureDb
import com.detectany.data.signature.SignatureStore
import com.detectany.data.signature.SignedUpdate
import kotlinx.serialization.json.Json

/**
 * 特征文件手动导入（任务 7.3）：通道无关——同一 SignatureStore.apply 验证/装载/生效路径，
 * 与在线更新完全等价。
 */
class SignatureImport(private val store: SignatureStore) {

    fun import(jsonText: String): Result = runCatching {
        val update = BundledSignatureDb.json.decodeFromString(SignedUpdate.serializer(), jsonText)
        when (val r = store.apply(update)) {
            is ApplyResult.Applied -> Result.Applied(update.version)
            is ApplyResult.Rejected -> Result.Rejected(r.reason)
        }
    }.getOrElse { Result.Rejected("malformed update file: ${it.message ?: it.javaClass.simpleName}") }

    sealed interface Result {
        data class Applied(val version: Long) : Result
        data class Rejected(val reason: String) : Result
    }
}
