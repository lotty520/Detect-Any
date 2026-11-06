# Detect-Any 使用与运维手册

## 构建

```bash
./gradlew assembleDebug      # 调试构建（16 模块 + 双 ABI native）
./gradlew assembleRelease    # 发布构建（见「发布装配清单」）
```

要求：JDK 17+、Android SDK（platforms 35、NDK 25.2.9519653、CMake 3.22.1）、Gradle 8.9（wrapper 自带）。

## 测试（本手册内命令均已验证可运行）

```bash
./gradlew test                              # 全部主机单测（compat/采集器分析器/引擎/证明/自保护/报告）
./gradlew :app:connectedDebugAndroidTest    # 设备/模拟器冒烟 + UI 走查 + 时延探针
```

注意：`connectedAndroidTest` **不支持** `--tests` 过滤器，请全量执行。

## 产物核验（16KB 对齐 / 无系统 crypto 依赖）

```bash
SO=$(find core/native-platform/build -name "libdetectany_native.so" -path "*stripped*arm64*" | head -1)
RE=$(ls ~/Library/Android/sdk/ndk/*/toolchains/llvm/prebuilt/*/bin/llvm-readelf | head -1)
$RE -lW "$SO" | grep LOAD     # Align 必须为 0x4000
$RE -dW "$SO" | grep NEEDED   # 仅允许 liblog/libm/libdl/libc
```

## 特征热更新运营

- 数据格式：`data/signature/src/main/kotlin/.../SignatureDb.kt`（JSON schema）。
- 更新信封：`SignedUpdate`（ed25519 签名，payload ≤200KB）。
- 发布流程：改动条目 → 语义化递增 `version` → 运营密钥签名 → 下发（Phase 2 通道）或手动导入。
- **手动导入**：更新文件 JSON 走 `SignatureImport.import(text)`——与在线更新同一验证/装载路径。
- 失效条目：置 `until`（框架版本区间），不需要代码变更。

## 发布装配清单（每次发版必做）

1. **自保护 XOR 常量替换**：`core/native-platform/src/main/cpp/guard.cpp` 中
   `SIG_A/SIG_B`（APK 签名摘要）与 `CRC_A/CRC_B`（classes.dex CRC32）按发布产物替换
   （debug 构建默认以当前构建实测值为预期，release 必须替换否则自保护失效）。
2. **Google attestation 双根 PEM**：装配 `AttestationVerifier(roots)`（旧 RSA 根 + 2026-02 起
   ECDSA P-384 新根）；未装配时 C9 走 Degraded（不误报）。
3. 更新密钥（ed25519 公钥）注入 `SignatureStore(verifier=...)`。
4. keybox 黑名单/机型基线随特征数据下发。

## 排障速查

| 症状 | 根因 → 处置 |
|---|---|
| 模拟器 props 测试进程崩溃 | 旧 `__system_property_read` 遇超长属性名 → 已双路径（26+ callback） |
| `reboot` 探针进程 SIGSYS | seccomp 白名单外 → 已 fork 隔离（父进程收割） |
| C7 找不到自身库 | `extractNativeLibs=false` → 已 solist 基址 + zip 抽取 |
| GOT 校验误报 memcpy | IFUNC 运行时变体 → 样本已排除 IFUNC 族 |
| 属性条目命中默认值 | 条目缺 `valueContains` → 加值条件 |
