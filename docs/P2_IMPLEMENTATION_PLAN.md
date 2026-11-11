# P2 实现方案设计

> 2026-11-11 · 覆盖四项：attestation 接线 L3（P2-1）、too_clean/st_dev 接线（P2-2）、
> 热更新在线通道 Phase 2（P2-3）、G6 输入事件行为分析（P2-4）。
> 每项含：目标 / 现状 / 设计 / 改动面 / 验证 / 风险与决策点。

---

## P2-1 attestation 接线 L3（最大断链，建议首个实施）

### 目标
把已建成未接线的硬件证明域（双根校验/CRL/交叉检查/分级降级）接入扫描管道，
使 L3 档成为"L2 + 硬件信任锚"——深度隐藏场景的最终判定路径（specs 契约）。

### 现状（断链细节）
- `AttestationService.run(): Outcome` 同步 API 完整，异常边界已修（第十一轮）
- findings 挂在 `CollectorId.C1_PATH` 占位（"C9 无独立编号"注释——历史 hack）
- `ScanOrchestrator` 零引用；`DetectionEngine` L3 = L2 同款 collectors
- UI 只有 L1/L2 按钮；spec「L3 异步档附加硬件证明发起」处于断链记录状态

### 设计

**1. 新采集器 C13_ATTESTATION**（遵循"每检测项实现 Collector"铁律）

```
core/model: enum CollectorId { ... C12_SCREEN_SHARE, C13_ATTESTATION }
feature/attestation: AttestationCollector(context, challenge: () -> ByteArray)
  - collect(): CountDownLatch 等待 Keymaster 异步 attest，预算 3000ms
    超时 → CollectorResult(DEGRADED, meta={timeout})，产出
    attest.degraded.timeout C 级 info（不采信不误报）
  - 到达 → AttestationService.run() 同步链（验签/CRL/交叉）→ findings
    （collector 字段从 C1_PATH 占位改为 C13_ATTESTATION）
  - KeyDescription 无 keymaster（2% 无 TEE 设备/模拟器软件链）→
    现有 software_backed B / Degraded 路径不变
```

**2. challenge 生命周期**（防重放：证明必须绑定本次扫描）
```
ScanOrchestrator.scan(L3): nonce = SecureRandom(32)
  → ScanInput 新字段 attestationChallenge: ByteArray?
  → AttestationCollector 从 input 取 challenge 传入 attest
  → Verifier challenge 回 echo 校验（已有 expectedChallenge 参数）
单次使用：nonce 在 scan 调用内生成即弃，不落盘不复用
```

**3. 引擎档位**
```
DetectionEngine: L3 -> collectors + attestationCollector（构造注入，
  L3 专用集合）；fastCollectorIds 不变（L1 快扫绝不碰 Keymaster）
```

**4. UI**：第三按钮「L3 深度」（副样式，subtitle="含硬件证明 · 数秒"）；
  扫描进行态文案区分（证明阶段占大头，进度条不细分——诚实呈现总时延）。

**5. 规则**：`rule.attestation`（category ATTESTATION_SPOOF，前缀 attest.，
  weight 16）；Trusted 结果 → meta 记录（零 finding = 通过，证据页显示
  "硬件证明通过（Trusted 级）"信息条——正向证据也该可见）。

### 改动面
core/model（ScanInput+CollectorId）、feature/attestation（Collector 包装）、
core/engine（L3 集合）、app（按钮+orchestrator 装配）、rules、UI 证据页信息条。
预计 ~300 行。

### 验证
- 模拟器：keymaster 软件链 → software_backed B 路径（TP 首次实证！）
- 华为（有 Keymaster，无 GMS 不影响——用平台 Keymaster 非 Play）：
  **首次真机 Trusted 级通过路径**；同时 first_api_level=29 → 分级降级路径
- P8 对抗组：TrickyStore 在装 → keybox/CRL 或 cross 异常路径（若可触发）
- 干净侧：超时治理（Keymaster 慢设备不得拖垮扫描——3000ms 硬预算）

### 风险与决策点
- **超时值**：3000ms 初值，真机数据校准（Keymaster 冷启动 100-800ms 常态）
- **L3 时延**：spec L3 预算待定（建议 ≤ L2+3s）
- 华为 Kirin Keymaster 的 attestation 扩展 schema 兼容性——
  KeyDescription 解析器已防御化（第十一轮 catch-all 兜底）

---

## P2-2 too_clean / st_dev 接线（消费侧小改 + 数据长线）

### 目标
激活两个建成未接线的挂载基线信号（B 级 too_clean / st_dev 偏离），
消除 MountAnalyzer 的死代码状态。

### 现状
- `MountAnalyzer(baselineMountCount=null, expectedStDev=emptyMap)` 生产默认 →
  两信号从未执行（第十一轮审计发现）
- DB v14 已有 2 数据点（TAS-AL00 mountCountMin=120 + stDev 三点 / Pixel 8 mountCountMin=260）
- `SignatureEntries` **未暴露** deviceBaselines 段（toEntries 不映射）

### 设计
```
1. SignatureEntries 增 DeviceBaselineEntry(model, mountCountMin, stDev: Map<String,Long>)
   toEntries() 映射 deviceBaselines 段
2. MountCollector 构造注入 baselineLookup: (String) -> DeviceBaselineEntry?
   collect(): lookup(Build.MODEL) 命中 → analyzer(baselineMountCount=…,
   expectedStDev=…)（未命中 → 现状不判，透明）
3. MountAnalyzer 语义对齐 DB 字段：
   - too_clean：threshold 直接用 mountCountMin（DB 存的就是下限观测，
     不再 ×0.6——原 ×0.6 是拍脑袋基线的缓冲，真数据不需要）
   - st_dev 偏离：降 C 级（跨重启稳定性未验证——tmpfs 设备号按挂载顺序
     分配，同机型多启动采样后才可升 B；太_clean 维持 B）
4. ScanOrchestrator: entries.deviceBaselines 接线
```

### 验证
- 华为：156 挂载 vs mountCountMin=120 → 不触发 ✓；
  人为 rm 大量挂载不可行——host 单测桩覆盖 `<120` 路径
- st_dev：P8 三点数据补进 DB（REGRESSION 有：/dev=18,/proc=20,/sys=21）
- 假阳性防线：无基线机型（大多数）零行为变化

### 风险与决策点
- **数据长线**：每台过手设备记录 model/mountCount/stDev 入库
  （REGRESSION 协议追加一行）；目标 10 机型后 too_clean 逐步全机型生效
- st_dev 跨重启稳定性验证方法：同机型重启 ≥3 次采样对比，稳定才升 B

---

## P2-3 热更新在线通道 Phase 2

### 目标
特征库热更新从"手动导入"升级为"在线拉取 + 缓存 + 节流"（spec 条款 17 完整兑现）。

### 现状
- 手动导入链路完整（SignatureImport → SignatureStore.apply：ed25519 验签/
  版本单调/200KB 上限/增量合并（丢段 bug 已修））
- CrlStore 已实现 fetcher + @Volatile 缓存 + cache-control 节流 + 离线兜底
  ——模式可直接复用
- 在线端点不存在（无服务端）——本项交付客户端半边 + 可配置 URL

### 设计
```
data/signature: RemoteSignatureSource(
  url: String,                      // 构建配置注入，默认官方占位
  fetcher: (String) -> Pair<String, Long?>,   // HttpsURLConnection，遵循 max-age
  clock/lastFetch @Volatile 节流（复用 CrlStore 模式：minInterval 4h +
  cache-control 优先）
)
  fun pollAndApply(store: SignatureStore): ApplyResult?
    - 节流内 → null（静默）
    - 拉取 SignedUpdate JSON → store.apply（全部安全语义复用）
    - 任何失败 → 静默降级（扫描永不因更新失败阻塞——specs）

接线：ScanOrchestrator init 后台单线程触发一次 + Settings「检查更新」
手动触发（立即 poll）；仅 HTTPS；不新增权限（INTERNET 已有）。

发布侧（配套但独立）：运营密钥签名工具（ed25519 私钥保管在发布流水线，
文档给签名/分发格式说明——RUNBOOK 已有骨架）
```

### 验证
- host 单测：mock fetcher 三态（新版本应用/同版本跳过/坏签名拒绝）
- 设备：本地 https 伪端点（python -m http.server + 自签更新包）走全链路
- 节流：二次 poll 静默

### 风险与决策点
- **端点 URL 与服务端**：先交付客户端 + 测试端点方案；正式端点是运营事项
- 隐私：poll 不携带设备标识（GET 裸 URL，无 telemetry——与产品定位一致）

---

## P2-4 G6 输入事件行为分析（MotionEvent 层）

### 目标
补齐姿态维最后一块：无障碍注入/合成输入的**运行时行为**检测
（静态枚举之外的动态证据）。

### 现状
- spec 子项降范围注记在案（需要触摸事件流）
- C12 有静态 InputDevice.isVirtual 枚举；MotionEvent 标志位族从未实现
- 前置模式已有：ScreenRecordingMonitor（Activity 生命周期挂接 +
  状态单例 + 扫描时读取）——完全同构可复制

### 设计
```
collectors/screen-share: InputEventMonitor（状态单例，对齐 RecordingMonitor）
  - MainActivity.dispatchTouchEvent 转发（比 onTouchEvent 全——
    拦在 dispatch 层可见所有事件含子视图消费前的）
  - 滚动窗口（最近 N=200 事件或 60s）统计：
    a) FLAG_IS_ACCESSIBILITY_EVENT 比例（API 34+ flag；低版本 0 恒）
    b) 设备 isVirtual 比例 / deviceId==0（合成）比例
    c) 节律熵：ACTION_DOWN 间隔的变异系数 CV（机器人低抖动）
  - find()：比例阈值 + CV 阈值 → C12 扫描时读快照产出
    input.accessibility_ratio C 级 / input.synthetic_input B 级（a+b 双高）
    / input.bot_rhythm C 级（初版全 C——节律校准不足，样本积累后升）
  - 白名单联动：C11 白名单内的无障碍（TalkBack 等）注入比例高 →
    降为 info 不产出（残障用户合法场景，准确性优先）
```

### 改动面
MainActivity dispatch 转发、Monitor 类、C12 采集、规则、（可选）UI。
预计 ~200 行。

### 验证
- 模拟器：TalkBack 开启 + 手动操作 → 白名单路径零产出
- 云端式：adb shell sendevent/input tap 脚本注入 → synthetic 路径 TP
  （`input tap` 走 Instrumentation → deviceId 特征可验）
- Auto clicker app（华为有装过样本）→ accessibility flag TP

### 风险与决策点
- **初版全 C 定级**：节律分析与注入比例的 FP 面（残障用户/辅助触控）
  需要真实样本积累，严格遵循「不确定降 C」
- 60s 窗口意味着扫描前需有交互——冷启动即扫无输入数据 →
  finding 缺席可接受（meta 标注 input=insufficient）

---

## 实施顺序建议

| 序 | 项 | 理由 |
|---|---|---|
| 1 | **P2-2 too_clean 接线** | ✅ 完成（2026-11-11，20cfd4f） |
| 2 | **P2-1 attestation L3** | ✅ 完成（2026-11-11，f6b84d8+b1a3d68 加固） |
| 3 | **P2-4 G6 输入分析** | 依赖 P2-1 建立的 Activity 挂接模式经验 |
| 4 | **P2-3 在线通道** | 独立性最强，运营端点就绪前价值有限 |

每项独立 openspec change（proposal → 实施 → 归档），遵循现有工作流。
