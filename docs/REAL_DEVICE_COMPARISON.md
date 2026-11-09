# Pixel 8 真机对比验证报告（修正版）

> 2026-11-09 · 设备：Pixel 8 / Android 16 / APatch root + susfs 深度隐藏
> **修正**：`com.lucky.luckyclient` 为瑞幸咖啡 App（非 Lucky Patcher），本设备唯一作弊工具为 APatch。

---

## 最终扫描结果

| 指标 | 模拟器（干净） | Pixel 8（APatch + susfs 深度隐藏） |
|---|---|---|
| **分数** | 70 / 检出 | **32 / 未达定性** |
| **假阳性** | 0 | **0**（瑞幸咖啡未被误报 ✓） |
| **真阳性** | 7 | 5（1 B 级 + 4 C 级） |
| **能力域** | 11/11 | 11/11 |

## 命中明细

| 威胁 | 级别 | 来源 | 判定 |
|---|---|---|---|
| **APatch** | **B** | C5 包枚举 + DEX 探针（superkey/KernelPatch） | ✅ 真阳性 |
| AUTOMATION ×3 | C | C11 无障碍枚举（未知服务） | ✅ 真阳性（非白名单） |
| REMOTE_CONTROL | C | C12 ADB 启用 | ✅ 真阳性 |

## 深度隐藏下的检测盲区

| 被隐藏的证据 | adb shell 可见 | app 可见 | 隐藏手段 |
|---|---|---|---|
| /system/bin/su | ✅ | ❌ | susfs 挂载命名空间 |
| overlay 挂载 | ✅ | ❌ | susfs try_umount |
| 属性痕迹 | ✅ | ❌ | resetprop + selinux hide |
| supercall 响应 | — | ❌ | APatch 需 superkey |
| SELinux 域标签 | — | ❌ | selinux hide |

## 32 分根因分析

APatch(B) 是唯一穿透隐藏层的 B 级信号。仅 1 条 B → 不足以定性（需跨域双 B）。

其余 4 条全为 C 级（AUTOMATION/REMOTE_CONTROL），不参与定性。

**根因**：susfs 完全遮蔽了 C1/C2/C3/C8 的静态信号面；C6/C7 因进程未被注入而正确地无异常。

## 结论

1. **零假阳性** ✓ — 瑞幸咖啡（com.lucky.luckyclient）未被误报
2. **零崩溃** ✓ — 11 域全部运行
3. **APatch 管理器正确检出 B 级** ✓ — C5 包指纹穿透隐藏层
4. **32 分为深度隐藏下的正确结果** — 单 B 不定性符合评分模型
5. **提升路径**：硬件证明（C9 attestation）是深度隐藏场景下的最终判定依据
