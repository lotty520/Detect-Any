package com.detectany.core.model

/**
 * supercall 族规格（采集器消费的最小视图；完整数据在 data:signature 的 SignatureDb.supercalls）。
 * specs/signal-collection「supercall 行为探测」：魔数与命令号 MUST 来自特征数据。
 */
data class SupercallSpec(
    val family: String,
    val magic1: Long? = null,
    val magic2: Long? = null,
    val superkey: String? = null,
    val helloCmd: Long? = null,
)
