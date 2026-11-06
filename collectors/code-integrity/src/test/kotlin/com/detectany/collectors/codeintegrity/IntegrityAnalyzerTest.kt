package com.detectany.collectors.codeintegrity

import kotlin.test.Test
import kotlin.test.assertEquals

/** 任务 3.7 主机侧验证：字节序换算（GOT 槽位解析的前置）；prologue/GOT 比对在模拟器冒烟覆盖。 */
class IntegrityAnalyzerTest {

    @Test
    fun bytesToLongLittleEndian() {
        assertEquals(0x0102030405060708L, IntegrityAnalyzer.bytesToLong(byteArrayOf(8, 7, 6, 5, 4, 3, 2, 1)))
        assertEquals(1L, IntegrityAnalyzer.bytesToLong(byteArrayOf(1)))
        assertEquals(0L, IntegrityAnalyzer.bytesToLong(byteArrayOf()))
    }

    @Test
    fun bytesToLongZeroSlot() {
        assertEquals(0L, IntegrityAnalyzer.bytesToLong(ByteArray(8)))
    }
}
