package com.detectany.data.signature

import com.detectany.core.model.Confidence
import com.detectany.core.model.Finding
import com.detectany.core.model.SignatureEntries
import kotlinx.serialization.json.Json

/**
 * 内置签名基线（任务 4.1/4.2：离线首扫可用）。
 * 内容与 2026-11 调研对齐（各采集器 default* 条目的数据化形态）；
 * 热更新后由 SignatureStore.current() 替代。
 */
object BundledSignatureDb {

    val json: Json = Json {
        ignoreUnknownKeys = true
        encodeDefaults = false
    }

    val db: SignatureDb by lazy { json.decodeFromString(SignatureDb.serializer(), JSON_TEXT) }

    /** 转采集器消费的条目视图（drops until 失效条目的兜底过滤：until 非空且已标记失效的场景由数据侧控制）。 */
    fun toEntries(db: SignatureDb = this.db): SignatureEntries = SignatureEntries(
        paths = db.paths.map { SignatureEntries.PathEntry(it.id, it.path, it.framework, confidence(it.confidence), category(it.category)) },
        sockets = db.sockets.map { SignatureEntries.SocketEntry(it.id, it.name, it.framework, confidence(it.confidence), category(it.category)) },
        properties = db.properties.map { SignatureEntries.PropertyEntry(it.id, it.keyPrefix, it.framework, confidence(it.confidence), category(it.category), it.valueContains) },
        apps = db.apps.map {
            SignatureEntries.AppEntry(it.id, it.packageNames, it.certPins, it.dexStrings, it.framework, confidence(it.confidence), category(it.category))
        },
        filesystems = db.filesystems.map { SignatureEntries.FilesystemEntry(it.id, it.fsName, it.framework, confidence(it.confidence), category(it.category)) },
    )

    /** supercall 规格 → 采集器视图（hex 字符串转 Long）。 */
    fun toSupercallSpecs(db: SignatureDb = this.db): List<com.detectany.core.model.SupercallSpec> =
        db.supercalls.map { e ->
            com.detectany.core.model.SupercallSpec(
                family = e.family,
                magic1 = e.magic1Hex?.let { java.lang.Long.parseUnsignedLong(it, 16) },
                magic2 = e.magic2Hex?.let { java.lang.Long.parseUnsignedLong(it, 16) },
                superkey = e.superkey,
                helloCmd = e.helloCmdHex?.let { java.lang.Long.parseUnsignedLong(it, 16) },
            )
        }

    internal fun confidence(tag: String): Confidence = when (tag.uppercase()) {
        "A" -> Confidence.A
        "B" -> Confidence.B
        "C" -> Confidence.C
        else -> throw IllegalArgumentException("unknown confidence tag: $tag")
    }

    internal fun category(tag: String): Finding.Category = Finding.Category.valueOf(tag)

    private val JSON_TEXT = """
    {
      "version": 14,
      "paths": [
        {"id": "path.debug_ramdisk.magisk", "path": "/debug_ramdisk/.magisk/socket", "framework": "magisk", "confidence": "C", "category": "ROOT_USERSPACE", "until": "v26.x"},
        {"id": "path.magisk.device_socket", "path": "/debug_ramdisk/.magisk/device/socket", "framework": "magisk", "confidence": "C", "category": "ROOT_USERSPACE", "since": "v27"},
        {"id": "path.magisk.device_preinit", "path": "/debug_ramdisk/.magisk/device/preinit", "framework": "magisk", "confidence": "C", "category": "ROOT_USERSPACE", "since": "v27"},
        {"id": "path.magisk.data_debug_ramdisk", "path": "/data/debug_ramdisk", "framework": "magisk", "confidence": "C", "category": "ROOT_USERSPACE", "since": "v27"},
        {"id": "path.magisk.databin", "path": "/data/adb/magisk", "framework": "magisk", "confidence": "C", "category": "ROOT_USERSPACE"},
        {"id": "path.zygisk.monitor", "path": "/debug_ramdisk/zygisk/monitor.sock", "framework": "zygisknext", "confidence": "C", "category": "ZYGISK"},
        {"id": "path.zygisk.zygisk", "path": "/debug_ramdisk/zygisk/zygisk.sock", "framework": "zygisknext", "confidence": "C", "category": "ZYGISK"},
        {"id": "path.zygisk.dev_cp64", "path": "/dev/zygisk/cp64.sock", "framework": "zygisknext", "confidence": "C", "category": "ZYGISK"},
        {"id": "path.zygisk.dev_cp32", "path": "/dev/zygisk/cp32.sock", "framework": "zygisknext", "confidence": "C", "category": "ZYGISK"},
        {"id": "path.zygisk.module_dir", "path": "/data/adb/modules/zygisksu", "framework": "zygisknext", "confidence": "C", "category": "ZYGISK"},
        {"id": "path.rezygisk.dir", "path": "/data/adb/rezygisk", "framework": "rezygisk", "confidence": "C", "category": "ZYGISK"},
        {"id": "path.rezygisk.module_dir", "path": "/data/adb/modules/rezygisk", "framework": "rezygisk", "confidence": "C", "category": "ZYGISK"},
        {"id": "path.lsposed.data", "path": "/data/adb/lspd", "framework": "lsposed", "confidence": "C", "category": "HOOK"},
        {"id": "path.lsposed.misc", "path": "/data/misc/lspd", "framework": "lsposed", "confidence": "C", "category": "HOOK"},
        {"id": "path.lsposed.module_dir", "path": "/data/adb/modules/zygisk_lsposed", "framework": "lsposed", "confidence": "C", "category": "HOOK"},
        {"id": "path.trickystore.dir", "path": "/data/adb/tricky_store", "framework": "trickystore", "confidence": "C", "category": "ATTESTATION_SPOOF"},
        {"id": "path.pif.module_dir", "path": "/data/adb/modules/playintegrityfix", "framework": "pif", "confidence": "C", "category": "ATTESTATION_SPOOF"},
        {"id": "path.pif.config", "path": "/data/adb/pif.json", "framework": "pif", "confidence": "C", "category": "ATTESTATION_SPOOF"},
        {"id": "path.shamiko.module_dir", "path": "/data/adb/modules/zygisk_shamiko", "framework": "shamiko", "confidence": "C", "category": "ANTI_DETECT_PRESENT"},
        {"id": "path.ksu.modules", "path": "/data/adb/ksu", "framework": "ksu", "confidence": "C", "category": "ROOT_KERNEL"},
        {"id": "path.ksu.ksud", "path": "/data/adb/ksud", "framework": "ksu", "confidence": "C", "category": "ROOT_KERNEL"},
        {"id": "path.apatch.ap", "path": "/data/adb/ap", "framework": "apatch", "confidence": "C", "category": "ROOT_KERNEL"},
        {"id": "path.apatch.apd", "path": "/data/adb/apd", "framework": "apatch", "confidence": "C", "category": "ROOT_KERNEL"},
        {"id": "path.apatch.kpm", "path": "/data/adb/ap/kpm", "framework": "apatch", "confidence": "C", "category": "ROOT_KERNEL"},
        {"id": "path.riru.dir", "path": "/data/adb/riru", "framework": null, "confidence": "C", "category": "HOOK", "until": null},
        {"id": "path.su.system", "path": "/system/bin/su", "framework": null, "confidence": "C", "category": "ROOT_USERSPACE"},
        {"id": "path.su.system_xbin", "path": "/system/xbin/su", "framework": null, "confidence": "C", "category": "ROOT_USERSPACE"},
        {"id": "path.su.sbin", "path": "/sbin/su", "framework": null, "confidence": "C", "category": "ROOT_USERSPACE"},
        {"id": "path.frida.server", "path": "/data/local/tmp/frida-server", "framework": "frida", "confidence": "B", "category": "INSTRUMENTATION"},
        {"id": "path.frida.hkuda", "path": "/data/local/tmp/hluda-server", "framework": "frida", "confidence": "B", "category": "INSTRUMENTATION"},
        {"id": "path.frida.florida", "path": "/data/local/tmp/florida-server", "framework": "frida", "confidence": "B", "category": "INSTRUMENTATION"},
        {"id": "path.frida.gadget", "path": "/data/local/tmp/frida-gadget.so", "framework": "frida", "confidence": "B", "category": "INSTRUMENTATION"}
      ],
      "apps": [
        {"id": "app.magisk", "packageNames": ["com.topjohnwu.magisk"], "dexStrings": ["libmagisk", "magiskinit", "magiskpolicy"], "framework": "magisk", "confidence": "B", "category": "ROOT_USERSPACE"},
        {"id": "app.magiskdelta", "packageNames": ["io.github.huskydg.magisk"], "dexStrings": ["huskydg", "Magisk"], "framework": "magisk", "confidence": "B", "category": "ROOT_USERSPACE"},
        {"id": "app.ksu", "packageNames": ["me.weishu.kernelsu", "me.weishu.kernelsu.pr"], "dexStrings": ["ksu_driver", "KernelSU"], "framework": "ksu", "confidence": "B", "category": "ROOT_KERNEL"},
        {"id": "app.ksunext", "packageNames": ["com.rifsxd.ksunext"], "dexStrings": ["rifsxd", "KernelSU"], "framework": "ksunext", "confidence": "B", "category": "ROOT_KERNEL"},
        {"id": "app.sukisu", "packageNames": ["com.sukisu.ultra", "io.sukisu.ultra", "com.sukisu.zako"], "dexStrings": ["sukisu", "KernelSU"], "framework": "sukisu", "confidence": "B", "category": "ROOT_KERNEL"},
        {"id": "app.apatch", "packageNames": ["me.bmax.apatch"], "dexStrings": ["superkey", "KernelPatch"], "framework": "apatch", "confidence": "B", "category": "ROOT_KERNEL"},
        {"id": "app.lspatch", "packageNames": ["org.lsposed.lspatch"], "dexStrings": ["LSPatch", "metaloader"], "framework": "lspatch", "confidence": "B", "category": "REPACKAGED"},
        {"id": "app.trustmealready", "packageNames": ["mfsx.xposed.trustmealready", "io.github.vvb2060.trustmealready"], "dexStrings": [], "framework": "trustmealready", "confidence": "C", "category": "HOOK"},
        {"id": "app.zygiskdetect", "packageNames": ["com.example.zygiskdetect"], "dexStrings": ["zygisk", "ZygiskDetect"], "framework": "zygiskdetect", "confidence": "B", "category": "ZYGISK"},
        {"id": "app.vector", "packageNames": ["org.lsposed.vector"], "dexStrings": ["Vector", "lsposed"], "framework": "vector", "confidence": "B", "category": "HOOK"},
        {"id": "app.neozygisk", "packageNames": ["moe.neozygisk"], "dexStrings": ["NeoZygisk", "zygiskd"], "framework": "neozygisk", "confidence": "B", "category": "ZYGISK"},
        {"id": "app.nyazygisk", "packageNames": ["nk.be.nyazygisk"], "dexStrings": ["NyaZygisk", "zygiskd"], "framework": "nyazygisk", "confidence": "B", "category": "ZYGISK"},
        {"id": "app.fakegps", "packageNames": ["com.lexa.fakegps", "com.theappninjas.fakegpsjoystick", "com.theappninjas.gpsjoystick"], "dexStrings": [], "framework": "fakegps", "confidence": "C", "category": "GPS_SPOOF"},
        {"id": "app.fakecamera", "packageNames": ["com.droidrooter.virtualcamera", "com.adriangl.pict2cam"], "dexStrings": [], "framework": "fakecamera", "confidence": "C", "category": "CAMERA_SPOOF"},
        {"id": "app.deviceidchanger", "packageNames": ["com.aksym.androiddeviceidchanger"], "dexStrings": [], "framework": "deviceidchanger", "confidence": "C", "category": "DEVICE_SPOOF"},
        {"id": "app.virtualnet", "packageNames": ["com.droidrooter.virtualnet"], "dexStrings": [], "framework": "virtualnet", "confidence": "C", "category": "DEVICE_SPOOF"},
        {"id": "app.appenv", "packageNames": ["com.sollyu.xposed.hook.model", "com.variable.apkhook"], "dexStrings": [], "framework": "appenv", "confidence": "C", "category": "DEVICE_SPOOF"},
        {"id": "app.screenrecorder", "packageNames": ["com.hecorat.screenrecorder.free", "com.hecorat.screenrecorder.premium", "com.du.screenrecorder", "videoeditor.videorecorder.screenrecorder", "videoeditor.videorecorder.screenrecorder.lite"], "dexStrings": [], "framework": "screenrecorder", "confidence": "C", "category": "SCREEN_SHARE"}
      ],
      "sockets": [
        {"id": "sock.ksud", "name": "ksud", "framework": "ksu", "confidence": "C", "category": "ROOT_KERNEL"},
        {"id": "sock.zygiskd", "name": "zygiskd", "framework": "zygisknext", "confidence": "C", "category": "ZYGISK"},
        {"id": "sock.zygiskd64", "name": "zygiskd64", "framework": "zygisknext", "confidence": "C", "category": "ZYGISK"},
        {"id": "sock.lsposed", "name": "lsposed", "framework": "lsposed", "confidence": "C", "category": "HOOK"},
        {"id": "sock.fs.zygisk_monitor", "name": "/debug_ramdisk/zygisk/monitor.sock", "framework": "zygisknext", "confidence": "C", "category": "ZYGISK"},
        {"id": "sock.fs.magisk_socket", "name": "/debug_ramdisk/.magisk/socket", "framework": "magisk", "confidence": "C", "category": "ROOT_USERSPACE"}
      ],
      "properties": [
        {"id": "prop.init_svc_magisk", "keyPrefix": "init.svc.magisk", "framework": "magisk", "confidence": "C", "category": "ROOT_USERSPACE"},
        {"id": "prop.riru_bridge", "keyPrefix": "ro.dalvik.vm.native.bridge", "framework": null, "confidence": "C", "category": "HOOK", "valueContains": "libriruloader"},
        {"id": "prop.zygisk_denylists", "keyPrefix": "ro.zygisk.denylists", "framework": "zygisknext", "confidence": "B", "category": "ROOT_USERSPACE"},
        {"id": "prop.magisk_version", "keyPrefix": "ro.magisk.version", "framework": "magisk", "confidence": "B", "category": "ROOT_USERSPACE"},
        {"id": "prop.kcmdline_loaded", "keyPrefix": "kcmdline.loaded", "framework": null, "confidence": "C", "category": "ROOT_KERNEL"}
      ],
      "supercalls": [
        {"family": "ksu_reboot", "magic1Hex": "deadbeef", "magic2Hex": "cafebabe", "framework": "ksu", "since": "v2.0.0"},
        {"family": "apatch_supercall", "superkey": "su", "helloCmdHex": "11581000", "helloMagicHex": "11581158", "framework": "apatch"},
        {"family": "ksu_prctl", "magic1Hex": "deadbeef", "framework": "ksu"}
      ],
      "filesystems": [
        {"id": "fs.susfs", "fsName": "susfs", "framework": "susfs", "confidence": "B", "category": "ROOT_KERNEL"}
      ],
       "keyboxBlacklist": [],
      "deviceBaselines": [
        {"model": "TAS-AL00", "mountCountMin": 120, "stDev": {"/dev": 16, "/proc": 18, "/sys": 19}},
        {"model": "Pixel 8", "mountCountMin": 260, "stDev": {}}
      ]
    }
    """.trimIndent()
}
