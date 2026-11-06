package com.detectany.compat.platform

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class KernelVersionTest {

    @Test
    fun parsesAndroidReleaseStrings() {
        assertEquals(KernelVersion(3, 18, 35), KernelVersion.parse("3.18.35-perf+"))
        assertEquals(KernelVersion(4, 4, 302), KernelVersion.parse("4.4.302-g9d5a2b3f9c"))
        assertEquals(KernelVersion(5, 15, 104), KernelVersion.parse("5.15.104-android13-4k-o"))
        assertEquals(KernelVersion(6, 1, 0), KernelVersion.parse("6.1"))
        assertEquals(KernelVersion(6, 12, 0), KernelVersion.parse("6.12.0-android16-0"))
    }

    @Test
    fun rejectsMalformedInput() {
        assertNull(KernelVersion.parse(""))
        assertNull(KernelVersion.parse("android"))
        assertNull(KernelVersion.parse("x.y.z"))
    }

    @Test
    fun comparesCorrectly() {
        assertTrue(KernelVersion(3, 17, 0) > KernelVersion(3, 10, 101))
        assertTrue(KernelVersion(4, 14, 0) > KernelVersion(3, 18, 100))
        assertTrue(KernelVersion(3, 10, 9) < KernelVersion(3, 17, 0))
    }
}
