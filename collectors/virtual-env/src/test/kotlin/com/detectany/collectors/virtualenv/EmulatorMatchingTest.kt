package com.detectany.collectors.virtualenv

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** fixture：真实 emulator 指纹 vs 三台真机（Pixel4/Redmi/华为模板形态——FP 边界）。 */
class EmulatorMatchingTest {

    @Test
    fun emulatorFingerprintsHit() {
        // API 35 google_apis AVD 典型指纹——多模式命中（保持旧循环多 B 共振语义）
        assertEquals(
            listOf("sdk_gphone", "ranchu"),
            EmulatorMatching.buildPatternHits(
                fingerprint = "google/sdk_gphone64_x86_64/emu64xa:15/APBX.250105.002/12838543:user/release-keys",
                model = "sdk_gphone64_x86_64",
                product = "emu64xa",
                hardware = "ranchu",
            ),
        )
        assertEquals(listOf("ranchu"), EmulatorMatching.buildPatternHits("a/b/c:d/e/1", "Pixel 8", "husky", "ranchu"))
    }

    @Test
    fun realDevicesDoNotHit() {
        // Pixel 4
        assertTrue(
            EmulatorMatching.buildPatternHits(
                fingerprint = "google/flame/flame:13/TQ3A.230901.001/10750268:user/release-keys",
                model = "Pixel 4", product = "flame", hardware = "flame",
            ).isEmpty(),
        )
        // Redmi（HyperOS）
        assertTrue(
            EmulatorMatching.buildPatternHits(
                fingerprint = "Redmi/23124RN87C_global/23124RN87C:15/HKCNVEXM/user/release-keys",
                model = "23124RN87C", product = "23124RN87C", hardware = "qcom",
            ).isEmpty(),
        )
        // 华为：bootimage 侧 generic_a15 模板属 PIF 域（C3 build_pair），不在 Build.FINGERPRINT 主指纹
        assertTrue(
            EmulatorMatching.buildPatternHits(
                fingerprint = "HUAWEI/TAS-AL00/HWTAS:12/HUAWEITAS-AL00/109:user/release-keys",
                model = "TAS-AL00", product = "TAS-AL00", hardware = "kirin990",
            ).isEmpty(),
        )
    }
}
