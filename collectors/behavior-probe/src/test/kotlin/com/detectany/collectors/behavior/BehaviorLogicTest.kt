package com.detectany.collectors.behavior

import kotlin.test.Test
import kotlin.test.assertEquals

/** 任务 3.8 主机侧验证：/proc/self/stat 的 ppid 解析（ptrace 残留比对的前置逻辑）。 */
class BehaviorLogicTest {

    @Test
    fun parsesPpidWithSpacedComm() {
        // comm 可含空格与括号 —— 必须取最后一个 ')' 之后；字段序：state ppid pgrp...
        val stat = "4728 (Some Process) S 731 4728 710 0 -1 1077952832"
        val ppidField = stat.substringAfterLast(')').trim().split(Regex("\\s+"))[1]
        assertEquals("731", ppidField)
    }

    @Test
    fun apatchHelloCmdLayout() {
        // ver_and_cmd = (0x1158 << 16) | 0x1000 —— 与 KernelPatch scdefs 布局一致
        val cmd = BehaviorCollector.APATCH_HELLO_CMD
        assertEquals(0x1158L shl 16 or 0x1000L, cmd)
        assertEquals(0x11581000L, cmd)
    }

    @Test
    fun ksuMagics() {
        assertEquals(0xDEADBEEFL, BehaviorCollector.KSU_MAGIC1)
        assertEquals(0xCAFEBABEL, BehaviorCollector.KSU_MAGIC2)
    }
}
