# 框架稳定接口清单（源码级盘点）

> 2026-11-10 建立。方法论：直接克隆各框架仓库，读内核/uapi 权威头文件提取
> 「框架为自身兼容必须保持」的接口常量——这类特征跨版本稳定，是最优版本锚定目标。
> 每条注明：来源文件 | 版本范围 | 非特权可探测性 | 库内状态。

---

## 1. KernelSU 家族（上游 tiann/KernelSU · KernelSU-Next · SukiSU-Ultra）

### 1.1 reboot supercall（✅ 已入库，全家族有效）

| 项 | 值 | 来源 |
|---|---|---|
| magic1 | `0xDEADBEEF`（KSU_INSTALL_MAGIC1） | `uapi/supercall.h:17` |
| magic2 | `0xCAFEBABE`（KSU_INSTALL_MAGIC2） | `uapi/supercall.h:18` |
| 三家一致性 | **完全一致**（上游/KSU-Next/SukiSU 的 uapi/supercall.h 逐字相同） | 2026-11-10 本地克隆 diff |
| 调用形态 | `reboot(magic1, magic2, cmd, arg)`，kprobe 拦截于 cmd 检查前 | `kernel/supercall/supercall.c:122` |
| 非特权探测 | 可行（无 CAP_SYS_BOOT → 无 handler 时 EPERM；有 handler 时被拦截） | C8 已实现 |
| 库内状态 | `ksu_reboot` since v2.0.0 ✓ | |

### 1.2 prctl supercall（⚠️ 库内 until 标注已修正）

| 项 | 值 | 来源 |
|---|---|---|
| magic | `0xDEADBEEF`（prctl 第一参数） | `manager/app/src/main/cpp/ksu.h:62` |
| 调用形态 | `prctl(0xDEADBEEF, cmd, &out, &flags, &result)`，cmd=2 为版本查询 | 同上 |
| 版本范围 | **至今在用**（next-gen manager 12882 仍调用）——旧条目标 `until v1.0.5` 是错的，v11 已移除 until | |
| 库内状态 | `ksu_prctl`（v11 从 legacy_ksu_prctl 改名） | |

### 1.3 KSU-Next susfs supercall（🆕 数据资产，非特权不可探测）

| 项 | 值 | 来源 |
|---|---|---|
| magic1 | `0xDEADBEEF`（KSU_INSTALL_MAGIC1，同 1.1） | `kernel/susfs/susfs_abi.h:15` |
| magic2 | `0xFAFAFAFA`（**SUSFS_MAGIC——susfs 专用第二魔数**） | `kernel/susfs/susfs_abi.h:16` |
| 命令族 | `CMD_SUSFS_ADD_SUS_PATH=0x55550` 起（0x55551/2 deprecated、0x55553、0x55560+ ...） | 同上 |
| 分发 | `kernel/susfs/susfs_supercall.c:287`——**uid!=0 直接 goto orig** | |
| 非特权探测 | 不可行（无差异响应）→ 仅作版本对照数据 | |
| 库内状态 | 不入 supercalls 执行段（避免无意义探测），记录于此 | |

### 1.4 SukiSU KPM 桥（🆕 数据资产，内核态内部 ABI）

| 项 | 值 | 来源 |
|---|---|---|
| MAGIC | `0x53554b504d000002`（"SKPM"+v2） | `kernel/extension/kpm/bridge.h:13` |
| MAGIC2 | `0x4b504d4252494447`（"KPMBRIDGE"） | bridge.h:14 |
| MAGIC3 | `0x53554b494e544552`（"SUKINTER"） | bridge.h:15 |
| ABI 版本 | 2（x8 寄存器） | bridge.h |
| 通道 | **内核内部**：ksud → KSU supercall → 内核合成 pt_regs → KP 的 `__arm64_sys_truncate` patch | `kpm.c:33-55` |
| 非特权探测 | 不可行（用户态无直接入口）→ 数据资产 | |

### 1.5 allowlist 文件魔数（数据资产）

- `FILE_MAGIC 0x7f4b5355`（"\x7fKSU"）——三家一致（`kernel/policy/allowlist.c:29`）；文件仅 root 可读。

---

## 2. APatch / KernelPatch（bmax121/KernelPatch）

### 2.1 supercall 通道（✅ 已入库，与源码逐项一致）

| 项 | 值 | 来源 |
|---|---|---|
| syscall 号 | `__NR_supercall = 45`（**45 即 arm64 truncate 号被 KP 占用**；曾有 `__NR3264_truncate` 别名注释） | `kernel/patch/include/uapi/scdefs.h:23` |
| HELLO 命令 | `SUPERCALL_HELLO = 0x1000` | scdefs.h |
| HELLO 魔数 | `SUPERCALL_HELLO_MAGIC = 0x11581158` | scdefs.h:135 |
| 打包格式 | `(version_code << 32) \| (0x1158 << 16) \| (cmd & 0xFFFF)` → HELLO 即 `0x11581000` | `user_deprecated/supercall.h:31` |
| 回显 | 内核 log `hello1158`（SUPERCALL_HELLO_ECHO） | `patch/common/supercall.c:302` |
| 认证 | superkey（安装时设定；KSU 兼容模式固定 "kernelsu"） | |
| 库内状态 | `apatch_supercall`：helloCmdHex=11581000 / helloMagicHex=11581158 ✓ **与源码完全一致** | |

### 2.2 架构关联事实

- SukiSU KPM 桥（1.4）最终落到 KP 的 truncate patch——**KSU 系用 reboot 号 + kprobe，KP 系直接占用 truncate 号**，这是两族 supercall 通道的根本差异。

---

## 3. Magisk（topjohnwu/Magisk，以 main=v31.x 为准）

### 3.1 目录/工件常量（`native/src/include/consts.rs` 权威）

| 常量 | 值 | 版本 | 库内状态 |
|---|---|---|---|
| INTERNAL_DIR | `.magisk` | — | 前缀命中 |
| DEVICEDIR | `.magisk/device` | v27+ 重构 | 🆕 v11 |
| MAIN_SOCKET | **`.magisk/device/socket`** | **v27+** | 🆕 v11（旧条目 `/debug_ramdisk/.magisk/socket` 标 until v26.x） |
| PREINITDEV | `.magisk/device/preinit` | v27+ | 🆕 v11 |
| LOG_PIPE | `.magisk/device/log` | v27+ | 未入库（文件型 pipe，存在性弱） |
| DATABIN | `/data/adb/magisk` | 长期 | 🆕 v11 |
| 根目录落点 | `/debug_ramdisk`（rootdir.cpp:263），挂载中转 **`/data/debug_ramdisk`**（xmount MOVE） | v27+ | 🆕 v11 |

**勘误**（2026-11-10）：v11 前库内 Magisk socket 路径为旧形态（`.magisk/socket`），
v27+ 设备上不存在——此为源码盘点发现的真实缺口。

### 3.2 SELinux 语义（C8 已用）

- 进程域 `magisk`、文件类型 `magisk_file`（consts.rs:42-45）。

---

## 4. 盘点结论与原则

1. **接口常量是版本锚定的最优目标**：三家 KSU fork 的 DEADBEEF/CAFEBABE 逐字一致（fork 为兼容 ksud 生态必须保持）；APatch HELLO 协议同样稳定。
2. **fork 专属扩展是分叉指纹**：FAFAFAFA（KSU-Next/susfs）、SKPM 桥魔数（SukiSU）——能区分"哪家 fork"，但非特权多不可探测，价值在版本对照与内存/日志取证。
3. **版本敏感的是路径形态**：Magisk socket 路径 v27 重构就是实例——路径条目必须带 since/until，并随框架 release 更新（热更新机制存在的意义）。
4. **维护流程**：框架新版本发布 → 克隆/拉 diff → 比对本清单 → 更新特征库 + 本文档。

## 附：本地克隆指纹（2026-11-10 快照）

| 仓库 | 分支/Tag |
|---|---|
| tiann/KernelSU | main（next-gen） |
| KernelSU-Next/KernelSU-Next | 默认分支 |
| SukiSU-Ultra/SukiSU-Ultra | main |
| topjohnwu/Magisk | main |
| bmax121/KernelPatch | main |
