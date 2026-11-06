package com.detectany.core.nativeplatform

import androidx.test.ext.junit.runners.AndroidJUnit4
import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * 模拟器/真机上的 native 基座验证（任务 2.1/2.3/2.4 的设备侧验证）。
 */
@RunWith(AndroidJUnit4::class)
class NativeSmokeTest {

    private fun mappedLibc(): String? {
        // 现代 Android 的 app 可见 libc 在 /apex 下；从 maps 找真实映射路径。
        // maps 行格式：addr perms offset dev inode pathname —— pathname 是最后的 '/' 开头字段
        File("/proc/self/maps").useLines { lines ->
            for (line in lines) {
                val path = line.trim().split(Regex("\\s+")).lastOrNull { it.startsWith("/") } ?: continue
                if (path.endsWith("/libc.so")) return path
            }
        }
        return null
    }

    @Test
    fun nativeLibraryLoads() {
        assertTrue(NativePlatform.nativeVersion().startsWith("detectany-native/"))
    }

    @Test
    fun tripleExecutorSvcLibcConsistentOnMappedLibc() {
        val libc = mappedLibc() ?: "/system/lib64/libc.so"
        val diff = TriplePathExecutor(JniSyscallBackend).probe(libc)
        assertEquals("svc vs libc 不一致: ${diff.svcVsLibc}", null, diff.svcVsLibc)
    }

    @Test
    fun elfSelfParseMatchesDlsym() {
        val libc = mappedLibc() ?: error("maps 中未找到 libc.so")
        val expected = ElfInspector().expectedRuntimeAddress(libc, "fopen")
        val actual = ElfJni.dlsymAddress("fopen")
        assertTrue("expected=$expected (disk st_value+base)", expected != null && expected != 0L)
        assertTrue("dlsym 实测为 0", actual != 0L)
        assertEquals("磁盘自解析与 dlsym 不一致", expected!!, actual)
    }

    @Test
    fun syscallGuardRejectsForeignNr() {
        val arm64 = android.os.Build.SUPPORTED_ABIS.firstOrNull() == "arm64-v8a"
        val allowedNr = if (arm64) 79L else 300L  // newfstatat / fstatat64
        val statxNr = if (arm64) 291L else 397L
        assertTrue(SyscallJni.svcNrAllowed(allowedNr))
        assertTrue("statx 必须被 native 守卫拒绝", !SyscallJni.svcNrAllowed(statxNr))
    }

    @Test
    fun propsListAndGetWork() {
        val bridge = SystemPropertiesBridge()
        val props = bridge.list()
        assertTrue("属性枚举为空", props.isNotEmpty())
        assertTrue("缺少 ro.build.fingerprint", props.containsKey("ro.build.fingerprint"))
        assertNotNull("ro.build.type 读取失败", bridge.get("ro.build.type"))
    }
}
