# Spec Delta

## Purpose

提供 C1-C8 框架无关的纯取证采集器：路径/挂载/属性/网络端点/应用指纹/内存映射/指令完整性/接口行为，为检测引擎与规则提供统一观测来源。

## ADDED Requirements

### Requirement: 采集器框架无关
采集器 SHALL 只输出取证观测（原始事实），MUST NOT 内嵌任何具体框架的判定逻辑或特征常量；新增框架目标 MUST NOT 导致新增采集器。

#### Scenario: 新框架仅改数据
- **WHEN** 特征数据更新引入一个此前未覆盖的框架
- **THEN** 仅规则与特征数据变化，采集器代码保持不变

### Requirement: 三路执行观测
文件与系统调用类观测 MUST 可经三层路径（Java API、libc 包装、裸 svc）分别执行，并输出各层原始结果供规则比对。

#### Scenario: 层间不一致被记录
- **WHEN** 某一层的系统调用被 hook 并返回伪造结果
- **THEN** 三层结果不一致作为独立观测被记录

### Requirement: supercall 行为探测
接口行为采集 SHALL 提供 KernelSU 系的 reboot 双魔数探测（fd 表新增 anon_inode 设备 fd 与后续 ioctl，未授权命令返回 -EPERM 可区分）与 APatch 的独立 supercall 布局探测；全部魔数与命令号 MUST 来自特征数据，MUST NOT 编译期写死。

#### Scenario: KSU 系内核探测
- **WHEN** 设备内核为 KernelSU 主线/Next/SukiSU 任一当前版本
- **THEN** 探测取得可区分的 fd 表变化或权限错误码观测

#### Scenario: 原厂内核不误报
- **WHEN** 设备为未修改的原厂内核
- **THEN** 探测退化为普通调用失败且不产生命中

### Requirement: 结构性内存观测
内存映射采集 SHALL 覆盖 maps/fd readlink/smaps 脏页/soinfo 链表/class loader 计数与可执行自探针，输出结构类观测而非仅字符串匹配。

#### Scenario: 注入后结构计数异常
- **WHEN** 本进程被注入额外 class loader
- **THEN** class loader 计数观测高于该应用基线并被记录

#### Scenario: maps 读取被篡改
- **WHEN** maps 读取被 hook 抹除痕迹
- **THEN** 可执行自探针（自建可执行映射的可见性校验）产出异常观测

### Requirement: 自身指令完整性
指令完整性采集 SHALL 将自身敏感函数 prologue 与磁盘 ELF 比对、校验 GOT/PLT 完整性，校验清单 MUST 覆盖全部采集器自身入口。

#### Scenario: 采集入口被 hook
- **WHEN** 采集器函数入口被 inline hook 改写
- **THEN** 内存与磁盘字节比对产出不一致观测

### Requirement: 兼容门控强制
全部采集器 MUST 经统一能力查询接口（版本 × 内核 × targetSdk → 允许/降级/阻塞）决定执行路径，MUST NOT 使用「先试探再回退」的裸 syscall 模式。

#### Scenario: 危险 syscall 被禁止
- **WHEN** 运行环境为 Android 9-11 且目标 syscall 不在 seccomp 白名单
- **THEN** 该 syscall 不被发起，采集走门控指定的替代路径

### Requirement: 采集隐私最小化
采集输出 MUST 仅包含检测所需观测；任何出端（导出/遥测）数据 MUST 经过哈希脱敏且仅含特征数据声明允许的字段。

#### Scenario: 属性快照脱敏
- **WHEN** 属性观测进入导出或遥测通道
- **THEN** 仅特征数据声明键的哈希化结果出现，无全量明文
