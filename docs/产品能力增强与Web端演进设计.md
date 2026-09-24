# ErgouTreeCrypt 产品能力增强与 Web 端演进设计

> 文档状态：建议稿 1.0  
> 评估基线：仓库 `2.9.0`，代码快照 `c2779bf`（2026-09-20）  
> 编制日期：2026-09-21  
> “双端”定义：本文默认指 JavaFX 桌面端与 Android 端；Web 端作为新增的第三运行端单独说明。

## 1. 结论摘要

ErgouTreeCrypt 已经不是一个只提供单文件加解密的工具。当前仓库已经具备通用卷、文件夹与多文件、
格式保持媒体、图片加密、文件隐写、可否认加密、归档与分卷、跨端 KDF、缓存管理、历史记录和
真实 Desktop JVM ↔ Android ART 互操作测试。下一阶段不适合继续无边界增加“新算法按钮”，而应把
产品能力收敛到以下四条主线：

1. **先完成可发布与可演进底座**：图片 Phase 8、共享核心模块化、统一格式探测、跨端压缩兼容、
   协议语料与畸形输入测试。
2. **从“知道密码即可解密”升级到“能安全分享并确认发件人”**：Ed25519 签名、X25519 多接收者
   密钥信封、可导出恢复的身份密钥包。
3. **为大文件、迁移与浏览器打基础**：新增分块认证容器，而不是破坏现有 `.ergou` 格式；提供旧文件
   批量检查与事务式重加密工具。
4. **Web 端可以做，而且不需要重写整个项目**，但应区分两种产品：
   - 短期可做“可信 Java 网关 + 网页 UI”，高度复用现有 Java 核心，但文件会经过网关主机；
   - 长期推荐“浏览器本地 PWA + WASM”，文件和密码不出浏览器，但浏览器适配层需要重新实现协议
     I/O 和现有 Web Crypto 不具备的算法。它是新增端适配，不是重写桌面端和 Android 端。

不建议把“强制安全删除”“输错次数自动销毁”“纯离线时间锁”作为安全承诺。这些功能在 SSD、Android
存储、可复制密文和可回拨时钟的现实条件下无法可靠兑现，容易形成虚假的安全感。

## 2. 现有能力基线

### 2.1 已有产品能力

| 能力域 | 桌面端 | Android | 共享协议/核心 | 当前判断 |
|---|---:|---:|---:|---|
| 通用文件、文件夹、多文件加解密 | ✅ | ✅ | `volume` / `.ergou` | 已形成主业务 |
| Picocrypt `.pcv` 兼容读取 | ✅ | ✅ | `header` / `volume` | 应长期保留读兼容 |
| Argon2id 档位与跨端参数记录 | ✅ | ✅ | v2.15+ Header | 已解决旧版固定 1 GiB 的主要互通问题 |
| 加密前压缩、归档、分卷 | ✅ | 部分 | `compress` / `fileops` | Zstandard 仍存在 Android 运行时能力差异 |
| Reed-Solomon 与可否认加密 | ✅ | ✅ | `encoding` / `volume` | 已有往返测试 |
| MP3/MP4/WAV 格式保持加密 | ✅ | ✅ | `mediacrypt` | 跨端可用，但元数据抗降级能力仍可增强 |
| EGTC-IMG 图片加密 | ✅ | ✅ | `imagecrypt` | 核心与 UI 已完成，待 Phase 8 发布闸门 |
| 图片抗重编码纠错载体 | ✅ | ✅ | `imagecrypt.robust` | 已有均衡/增强/极强档 |
| STEG-V2 文件隐写（PNG/ZIP/PDF/WAV/FLAC/MP4） | ✅ | ✅ | `filestego` | 双端主线隐写能力 |
| 桌面 LSB 图片隐写 | ✅ | ❌ | `stego` | 与 STEG-V2 是两套格式，需决定是否统一 |
| 古典/现代字符串密码 | ✅ | ✅ | `classical` | 应明确为教学/兼容工具，不等同主线安全容器 |
| 历史、日志、进度、取消、缓存管理 | ✅ | ✅ | 部分共享 | 产品化基础已经存在 |

### 2.2 已核实的“旧计划误差”

仓库内部分计划文档记录的是较早快照，不能继续直接作为待办清单：

- 桌面媒体加密已经在 `MediaCryptController` 中透传 `Argon2DesktopMode`；
- 桌面文件隐写已经在 `FileStegoController` 中写入 `Argon2Params`；
- Android 已通过 `KdfPreflight.peekMediaMetadata` 和 `peekStego` 做媒体/隐写预检；
- 图片加密已完成 Android UI，且抗重编码纠错已经双端接入；
- 多文件处理、缓存占用统计与清理也已落地。

因此本计划不重复安排上述事项，后续应同步订正旧计划的状态，避免同一工作被再次立项。

### 2.3 现有工程优势

- 协议实现已经有明确分层：`crypto`、`encoding`、`header`、`volume`、`mediacrypt`、
  `imagecrypt`、`filestego`。
- Android 直接编译大部分共享 Java 核心，桌面与移动不是两套独立密码学实现。
- 图片协议已有冻结规范、永久语料、Desktop ↔ Android 双向产物验证和真实 ART 测试。
- 写临时文件、认证成功后提交、取消清理等事务语义已经在多个主流程中出现，可抽成统一能力。
- 当前静态盘点包含 104 个测试文件（91 个桌面测试、8 个 Android JVM 测试、5 个设备测试），
  已有建立更严格发布闸门的基础。

### 2.4 当前结构性约束

1. **共享核心仍通过 Gradle Copy 任务同步源码**。`android/app/build.gradle.kts` 把
   `src/main/java` 复制进构建目录并按路径排除桌面类。新增包或平台依赖时容易发生“桌面可编译、
   Android 同步后才失败”，也不利于未来第三端。
2. **格式探测与能力判断散落**。`FileInputGuard`、`KdfPreflight`、各 Codec 的 `peek`、UI 路由分别
   维护一部分判断，新增格式时容易出现入口不一致。
3. **Zstandard 是已知双端能力缺口**。通用卷与隐写可以在桌面生成 Android 不能处理的压缩载荷，
   目前主要依靠移动端预检拒绝，而不是完成互通。
4. **协议族较多但缺统一能力描述**：`.ergou/.pcv`、EGTD、EGTC-AVE、EGTC-IMG、STEG-V2、旧 LSB
   隐写均有自己的版本与错误语义。
5. **媒体元数据需要更强的降级保护**。载荷 MAC 是密钥化的，但是否启用完整性、KDF 参数、档位等
   元数据本身还应由明确的 Header MAC 认证，避免攻击者通过改写标志诱导进入弱校验路径。
6. **整文件认证不适合断点恢复与随机验证**。现有主卷方案安全可用，但超大文件失败后通常需要从头
   处理，也不便于浏览器和不稳定移动环境。
7. **文档存在版本漂移**。README、CHANGELOG、旧迁移计划和当前代码状态并不完全一致，发布时会给
   用户和维护者造成错误预期。

## 3. 规划原则与评级标准

### 3.1 必须遵守的设计原则

- **协议先于界面**：先冻结字节布局、认证范围、拒绝顺序、资源上限和错误分类，再接双端 UI。
- **新写旧读**：新版本默认写最新格式，但旧 `.pcv/.ergou` 只读能力不能被删除。
- **认证后提交**：解密、迁移、隐写提取与 Web 导出都不得留下未经认证的最终文件。
- **能力可探测**：不支持的格式或 KDF 必须在读取大载荷前明确拒绝，不能运行到中途崩溃。
- **双端同语料**：桌面和 Android 必须消费同一份黄金文件，不能各自生成样本后只做同端往返。
- **浏览器不降级密码学语义**：Web 端若不支持某个历史档位，应明确拒绝或建议迁移，不能偷偷降低
  KDF 参数或跳过认证。
- **安全功能不夸大**：格式保持、公开恢复、隐写、强制解密等模式必须持续显示它们的真实边界。

### 3.2 评级说明

- 重要程度：`S` 发布/安全/互通底座，`A` 高价值主业务，`B` 明显增强，`C` 小众扩展。
- 实现难度：`L` 低、`M` 中、`H` 高、`VH` 很高。
- 优先级：`P0` 下一稳定版前，`P1` 下一主版本，`P2` 中期，`P3` 机会型需求。
- 双端稳定性：`高` 表示现有共享 Java 核心可承载；`中` 表示需要平台桥；`低` 表示依赖外部服务、
  不可控格式或系统限制。

## 4. 总体能力路线图

| ID | 能力 | 业务价值 | 重要 | 难度 | 优先级 | 双端稳定性 |
|---|---|---|---:|---:|---:|---:|
| F0 | 图片 Phase 8、畸形输入与真实 CI 发布闸门 | 把 2.9.0 从“已实现”变成“可稳定发布” | S | M | P0 | 高 |
| F1 | 共享核心正式模块化，取消 Copy 源码同步 | 降低双端漂移，为 Web/CLI 铺路 | S | H | P0 | 高 |
| F2 | 统一格式检查器与平台能力矩阵 | 用户可在操作前知道“是什么、能否处理、为何不能” | S | M | P0 | 高 |
| F3 | Zstandard Android 互通 | 关闭桌面可写、移动不可读的已知缺口 | S | M-H | P0 | 高 |
| F4 | 批量兼容检查与事务式重加密迁移 | 把旧 1 GiB KDF、`.pcv`、旧协议迁到当前格式 | A | H | P1 | 高 |
| F5 | Ed25519 数字签名与可信联系人 | 验证发件人身份和文件来源 | A | M-H | P1 | 高 |
| F6 | X25519 多接收者密钥信封 | 无需共享口令，可一份文件安全发给多人 | A | H | P1 | 高 |
| F7 | 分块认证卷 v3（保留旧格式读取） | 大文件、局部校验、断点恢复、Web 流式处理 | S | VH | P1-P2 | 高 |
| F8 | 身份密钥与恢复包 | 让签名/收件人加密可真正使用和迁移 | A | H | P1 | 中-高 |
| F9 | EGTC-IMG 输入格式扩展 | 低成本支持 TIFF/HEIF/AVIF/JPEG 2000/QOI | B | M | P2 | 高 |
| F10 | STEG-V2 与旧 LSB 隐写统一 | 减少“双端都有隐写但格式不同”的困惑 | B | H | P2 | 中-高 |
| F11 | 媒体格式增强与元数据 v3 | RF64、元数据认证、后续 FLAC/WebM 研究 | B | H | P2 | 高 |
| F12 | 可复现构建、SBOM、依赖与安全扫描 | 提升加密工具发布可信度 | A | M | P1 | 高 |
| W0-W5 | Web/PWA 第三端 | 覆盖无法安装 iOS 包的用户 | A | H-VH | 分阶段 | 见第 8 节 |

## 5. P0：先完成稳定性底座

### 5.1 F0：发布闸门与协议回归

#### 目标

关闭图片计划 Phase 8，并把同样的质量标准扩展到卷、媒体和隐写协议。

#### 实现要点

- 让 `.github/workflows/android-ci.yml` 的真实 ART 互操作作业至少完成一次远端主分支运行并保留产物；
- 固化 Android 生成的 EGTC-IMG 黄金产物，增加“旧 writer → 新 reader”和“新 writer → 旧稳定
  reader”兼容用例；
- 为每个协议建立 `valid/invalid/adversarial` 三类语料：截断、长度溢出、重复块、乱序块、错误版本、
  KDF 超限、路径穿越、压缩炸弹；
- 引入属性测试/模糊测试，优先覆盖所有 Header、metadata、PNG chunk、MP4 box、归档入口；
- 建立峰值内存、吞吐、取消延迟与临时空间基线，不只记录成功/失败；
- 统一发布清单：协议版本、可写版本、可读版本、桌面版本、Android 版本、黄金语料版本。

#### 验收标准

- 任一协议写侧变化必须触发 Desktop JVM、Android JVM、ART 和互操作语料测试；
- 所有畸形输入必须在设定资源上限内失败，不产生最终输出，不抛 `OutOfMemoryError`；
- README、CHANGELOG、协议规范与产品版本在同一提交更新。

### 5.2 F1：共享核心模块化

#### 目标

把“复制源码 + 排除目录”改成真正的依赖关系，避免新增类被意外带入 Android 或漏入测试。

#### 建议结构

```text
core-protocol/       纯字节协议、密码学编排、错误类型、探测模型
core-io/             顺序读写、随机访问、事务输出、临时空间抽象
platform-desktop/    Path、JavaFX、ImageIO、桌面设置、日志
platform-android/    URI/SAF、Bitmap、DataStore、ForegroundService、JNI
app-desktop/         JavaFX 页面
app-android/         Compose 页面
interop-corpus/      所有端共用的黄金语料与生成说明
```

不建议一次性迁移所有包。先抽取 `exception/password/crypto/encoding/header/imagecrypt`，验证桌面与
Android 都以构建依赖引用；再迁移 `volume/mediacrypt/filestego`。构建系统可暂时保留 Maven + Gradle，
但依赖版本必须由一个版本目录或生成任务校验。最终是否统一为 Gradle 应单独决策，不应与协议改动在
同一提交完成。

#### 必要接口

- `SeekableSource`：长度、有界读取、随机读取；
- `TransactionalSink`：创建临时输出、提交、回滚；
- `TempWorkspace`：按任务管理临时文件并在下次启动清理崩溃残留；
- `PlatformCapabilities`：内存、可用空间、原生 KDF、压缩 codec、图片桥能力；
- `CancellationToken` 和统一 `ProgressEvent`。

所有新增 Java 类型和方法必须按项目约定提供标准 JavaDoc，并为参数、返回值和异常写清契约。

### 5.3 F2：统一格式检查器与能力矩阵

#### 用户能力

用户选择文件后先得到一张“文件说明卡”：

- 格式与协议版本；
- 是否加密、签名、压缩、分卷、隐写、格式保持；
- KDF 内存/轮次、预计耗时与当前设备是否可执行；
- 是否需要密码、密钥文件、收件人私钥或归档密码；
- 桌面、Android、Web 三端可否读取；
- 风险提示，例如公开恢复、无完整性、旧协议、超高内存档位。

#### 核心模型

```text
ArtifactInspector.inspect(source) -> ArtifactDescriptor
ArtifactDescriptor + PlatformCapabilities -> CompatibilityDecision
CompatibilityDecision -> SUPPORTED / SUPPORTED_WITH_WARNING / UNSUPPORTED
```

`ArtifactDescriptor` 只描述已探测事实，`CompatibilityDecision` 才结合当前平台下结论。UI 不再自行解析
扩展名或异常文本。现有 `FileInputGuard`、`KdfPreflight` 和各 Codec 的 `peek` 应逐步改为调用这一层。

#### 为什么是 P0

Web 端不可能第一版支持所有功能。没有统一能力矩阵时，只能复制一套浏览器判断；有了它，任何端都能
在读大文件前给出一致、可国际化、可测试的拒绝原因。

### 5.4 F3：关闭 Zstandard 双端缺口

#### 推荐方案

抽象 `CompressionCodec`，协议字段继续保留 codec ID，不再把 `ZstdCompressor` 直接散布在业务层。

- 桌面端可继续使用 `zstd-jni`；
- Android 端优先编译并打包受控版本的原生 libzstd，沿用现有 CMake/JNI 能力；
- 若引入纯 Java decoder，只作为兼容读取路径，必须先完成性能与压缩炸弹限制验证；
- 解压 API 必须接受最大输出字节数、压缩比上限、取消令牌和进度回调；
- 建立桌面压缩 → Android 解压、Android 压缩 → 桌面解压的永久语料。

完成后再在 Android 解锁“加密前压缩”；完成前保持当前明确拒绝，不允许静默回退。

## 6. P1：安全分享、身份与迁移

### 6.1 F4：批量兼容检查与重加密迁移

#### 业务场景

- 将旧 `.pcv`、旧 `.ergou`、1 GiB KDF 文件迁到当前均衡档；
- 将无完整性或旧媒体元数据升级到认证元数据；
- 批量检查一组文件是否能在 Android/Web 打开；
- 为长期归档生成迁移报告，但不强迫用户立刻改写文件。

#### 两阶段实现

1. **只读审计**：扫描目录，生成 JSON/CSV 报告，不要求密码，不修改文件。
2. **事务式迁移**：用户提供必要凭据后，旧 reader 解密到任务私有临时空间，新 writer 重加密，
   验证新文件后再提交；默认保留旧文件并生成映射清单。

长期应让 `Decryptor` 与 `Encryptor` 支持流连接，减少明文临时文件。第一版可以使用权限受限的临时文件，
但必须在 UI 明确说明、崩溃恢复时清理，并禁止“迁移成功即自动删除旧文件”。

### 6.2 F5：Ed25519 数字签名

#### 产品边界

签名解决“是谁发的、内容是否被替换”，密码/MAC 解决“持有秘密的人能否解密与验证”。二者不能合并
成一个含糊的“完整性”开关。

#### 第一版设计

- 新建独立、规范化的 `EGTC-SIG v1` 签名清单；
- 对文件内容摘要、文件名建议值、长度、MIME、签名时间声明、签名者公钥指纹和协议版本签名；
- 默认产生 detached signature（例如 `.egsig`），避免立刻修改所有现有容器；
- 验证结果分为“内容有效”“签名密码学有效”“联系人受信任”三个层级；
- 联系人信任必须由用户核对指纹或扫描二维码建立，不能因文件携带一个公钥就自动显示为可信。

桌面与 Android 均可用 Bouncy Castle 共享实现。Web 端后续可以使用 Web Crypto Ed25519 或受控 WASM，
但仍需运行时能力探测和黄金向量。

### 6.3 F6：X25519 多接收者密钥信封

#### 用户价值

发送者不再通过聊天软件另发共享密码。每个文件使用随机内容密钥，再为一个或多个接收者分别封装该
内容密钥；同一密文可发给多人，增加接收者时不需要重新加密大载荷。

#### 协议草案方向

```text
EnvelopeHeader
  version / suite / payloadId
  senderIdentity? / signature?
  recipientCount
  recipientEntry[]:
    recipientKeyId
    ephemeralPublicKey
    wrappedContentKey
    entryAuthentication
EncryptedPayload
PayloadAuthentication
```

- 密钥协商使用 X25519，域分离的 HKDF 派生 key-encryption-key；
- 接收者条目、算法 ID、载荷 ID 必须被认证，防止删除/替换接收者或算法降级；
- 可同时保留一个密码信封，便于没有身份密钥的接收者；
- 不把联系人昵称写进公开 Header，只保存不可逆 key ID；
- 第一版不实现群组成员动态撤销。已下载的密文无法通过修改服务端状态收回，这是离线文件的本质限制。

### 6.4 F8：身份密钥与恢复包

签名和收件人加密上线前必须先完成密钥生命周期：

- 本地生成签名密钥与收件人密钥，使用不同 key ID 和用途；
- Android 可用系统 Keystore/生物识别包裹本地解锁密钥；
- 桌面端先使用密码加密的跨平台密钥库，Windows DPAPI 只能作为可选便利层，不能成为唯一恢复方式；
- 导出 `EGTC-KEYBUNDLE v1`，由独立恢复密码保护，支持打印/二维码分片但不显示明文私钥；
- 公钥卡片可以安全分享，包含名称建议、用途、指纹、创建时间和撤销声明；
- 私钥丢失无法恢复历史收件人密文，产品必须在首次启用时要求用户确认备份。

### 6.5 F12：发布供应链能力

- 生成 CycloneDX/SPDX SBOM；
- 对 Maven、Gradle、NDK vendored 源码和前端依赖做许可证与已知漏洞检查；
- 发布包附 SHA-256 和项目签名；
- 固定 JDK/Gradle/NDK 版本并建立可复现构建差异报告；
- Android release CI 必须使用隔离的签名步骤，不把签名材料写入构建日志或产物缓存；
- 对协议变更建立人工 review checklist，禁止只有 UI 测试而无黄金向量更新。

## 7. P1-P2：分块认证卷 v3

### 7.1 为什么需要新格式

现有卷格式的优势是兼容 Picocrypt 并且已经稳定；它不应被原地修改成完全不同的数据布局。新的需求
——大文件局部认证、断点恢复、并行验证、浏览器流式写出——适合新建 `.ergou` 内部 v3 格式或新扩展，
旧 reader 继续保留。

### 7.2 目标能力

- 固定大小的独立认证块，例如 1–8 MiB，块号、明文长度、总文件 ID 纳入认证；
- Header 和最终 manifest 单独认证；
- 解密块认证通过后才向事务输出提交，不把未认证数据暴露为最终文件；
- 中断后可以验证已有块并继续写，避免重新处理全部大文件；
- 支持并行校验，但输出顺序和错误定位必须确定；
- 分卷只是传输层，不再改变密码学块边界；
- 为未来 Web 端限定可实现的算法套件和资源上限。

### 7.3 必须先写的协议内容

- suite ID 与算法迁移规则；
- nonce/计数器构造与唯一性证明；
- 每块 AAD 的精确字节编码；
- 截断、重复、重排、拼接两个文件块时的拒绝行为；
- 最后块、空文件、超大文件、文件夹 manifest 的处理；
- KDF 参数上限和平台能力协商；
- 与签名、多接收者信封、RS 纠错的分层关系。

密码套件的最终选择必须经过单独密码学评审。不要仅为了 Web Crypto 方便就直接改变现有算法，也不要
自创未经分析的 AEAD 组合。可以先用协议测试桩和确定性向量验证布局，再接真实算法。

### 7.4 验收矩阵

- Desktop writer → Android reader；Android writer → Desktop reader；
- 正常、偏执、密码、密钥文件、收件人信封、空文件、边界块；
- 每个块单字节损坏、删除、重复、调序、尾部截断、跨文件拼接；
- 取消后续传、应用崩溃后清理、磁盘满、目标文件已存在；
- 1 MiB、1 GiB、超 4 GiB 的峰值内存和吞吐；
- Web 端加入后沿用同一语料，而不是另建“Web 格式”。

## 8. Web 端与 Apple 用户方案

### 8.1 可行性结论

**可以在当前项目基础上增加网页启动能力，不需要重写现有桌面端和 Android 端。** 但“网页端”有
两个完全不同的安全模型，必须让用户选择，而不是混在一个实现里。

| 方案 | 现有 Java 源码复用 | 文件是否离开 Apple 设备 | iOS 适配工作 | 推荐用途 |
|---|---:|---:|---:|---|
| A. 可信 Java 网关 + Web UI | 高 | 会上传到用户信任的网关主机 | 低-中 | 最快交付、局域网/自托管 |
| B. 浏览器本地 PWA + WASM | 协议/语料高，Java 源码低 | 否 | 高 | 长期正式 Apple 方案 |
| C. 直接把现有 Java 应用整体编译到 WASM | 表面高、实际不稳定 | 否 | 很高 | 不建议作为主线 |

### 8.2 为什么现有 Java 核心不能原样放进 Safari

现有核心包含 `java.nio.file.Path/Files`、随机访问文件、JNI Argon2、`zstd-jni`、Bouncy Castle、
`Unsafe` 离堆路径、JavaFX/ImageIO 桥和线程模型。即使现代 Safari 已支持 WebAssembly GC，它只降低
Java 等 GC 语言编译到 WASM 的门槛，并不会自动提供 Java NIO 文件系统、JNI 动态库或现有第三方库
的浏览器兼容实现。

另外，Web Crypto 标准列出的常用算法包括 AES、HMAC、SHA-2、HKDF、PBKDF2、Ed25519、X25519 等，
但项目当前协议还依赖 Argon2id、XChaCha20、BLAKE2b、SHA-3、Serpent 和 Reed-Solomon。浏览器端
需要经过审计、版本固定的 WASM 实现，不能假设 `crypto.subtle` 可以直接替代。

### 8.3 方案 A：可信 Java 网关

#### 架构

```text
iPhone/iPad Safari
       │ HTTPS + 配对令牌
       ▼
Web Gateway（用户的 PC/NAS/私有服务器）
       │ 调用正式 Java core
       ▼
事务临时目录 → 认证 → 下载结果 → 定时清理
```

#### 可复用内容

`volume`、`imagecrypt`、`mediacrypt`、`filestego`、`fileops` 和绝大部分密码学核心都可直接复用。
新增的是 HTTP 上传下载、会话、配对、限额和 Web UI。

#### 安全要求

- 默认只绑定本机；开启局域网必须显式确认，并显示监听地址；
- 使用 HTTPS，一次性二维码包含短期配对令牌和证书指纹；
- 密码不写日志、不持久化、不进入 URL；
- 上传文件进入按会话隔离的私有目录，结果下载或超时后清理；
- 对上传大小、并发数、压缩展开大小、操作时间设置硬上限；
- 防 CSRF、跨站 WebSocket/请求、目录穿越和同名覆盖；
- 不应默认提供公网 SaaS。若服务器运营者可看到文件和密码，它不再是“本地加密工具”的同一信任模型。

#### 判断

这是最快让 Apple 用户通过网页使用完整功能的方式，但 Apple 设备仍依赖一台运行网关的可信主机。
如果用户要求“只用 iPhone、没有任何其它主机”，必须走方案 B。

### 8.4 方案 B：浏览器本地 PWA

#### 推荐结构

```text
web/
  app/                 TypeScript UI、PWA manifest、Service Worker
  worker/              文件编排、进度、取消、能力预检
  protocol/            Header/manifest/错误分类的浏览器实现
  crypto-wasm/         固定版本的 Argon2/XChaCha/BLAKE2/SHA3/RS/Serpent
  fixtures/            直接引用 interop-corpus 的黄金语料
```

所有重计算都放入 Worker。Service Worker 只缓存带哈希的静态资源，不缓存用户文件、密码或明文。

#### 文件 I/O 策略

- 输入使用标准 `<input type="file">`/`File`，不能把 `showOpenFilePicker` 当作唯一入口；
- 工作文件写入 Origin Private File System（OPFS）的随机 `.part` 项；
- 认证成功后再通过下载或 Web Share 导出；
- 应用启动时清理超时的 `.part`，但不得误删已提交结果；
- Private Browsing 下 OPFS 不可用时，显示明确限制并禁用大文件操作；
- 使用 `StorageManager.estimate()` 做空间预检，存储仍可能被系统回收，因此 OPFS 只作暂存，不作唯一备份。

WebKit 官方资料显示 OPFS 自 iOS 15.2 起可用，而 Safari 17 起完整支持 Storage API 并提高配额；因此
建议第一版支持基线定为 **iOS/iPadOS 17+**，同时在运行时检测实际 API，不能只看 User-Agent。

#### 浏览器安全基线

- 强 CSP：默认拒绝第三方脚本、`eval`、远程字体和任意连接；
- WASM、JS、CSS 全部随同一版本发布并使用内容哈希，禁止从公共 CDN 动态加载密码学代码；
- 默认无分析 SDK、无崩溃文件上传、无密码强度联网查询；
- 每次启动做算法自检与黄金向量短测，自检失败则禁止加解密；
- 明确显示“本地处理，文件不会上传”，并用自动化网络测试验证该承诺；
- 页面失焦或系统挂起不能被视为可靠锁屏，恢复时应重新确认敏感操作状态；
- 不在 localStorage/IndexedDB 存密码或明文文件名历史。

### 8.5 Web 功能分期

#### W0：技术验证与支持边界（P0，1–2 周）

- 在真实 iPhone/iPad 上验证 Worker、WASM、OPFS、下载、Web Share、前后台切换；
- 基准 64 MiB/3/4、256 MiB/3/4 和历史 1 GiB Argon2；
- 验证 10/100/500 MiB 文件的峰值内存、临时空间、取消和页面被系统回收后的恢复；
- 结论必须写成支持矩阵。预计 1 GiB 档在 iPhone 上应直接标为“不支持，请先迁移”，而不是冒险执行。

#### W1：协议常量与语料共享（P0，1–2 周）

- 将协议常量、错误码和语料索引变成可校验的数据源；
- 浏览器只读解析 `.ergou`、EGTC-IMG、EGTC-AVE、STEG-V2 的 Header；
- 完成统一“文件说明卡”，尚不开放写操作。

#### W2：EGTC-IMG v1 本地恢复 MVP（P1，3–5 周）

- 先做 `peek/verify/decrypt`，支持公开恢复与固定 64 MiB 密码模式；
- 从桌面、Android 永久语料恢复并逐字节比较；
- 错密码、破损、取消和空间不足不留下最终文件；
- 真机基准通过后再开放 Web writer，避免出现只能由 Web 自己读取的产物。

选择图片协议作为首个本地 MVP，是因为其协议已经冻结、KDF 固定为 64 MiB、跨端语料最完整，且不
需要先支持文件夹归档、密钥文件、分卷和 Picocrypt 历史分支。

#### W3：低内存 `.ergou` 解密（P1-P2，4–8 周）

- 先支持 v2.15/v2.16、密码模式、无密码模式和受控 KDF 上限；
- 按协议真实需要补齐 Header RS、XChaCha20、可选 Serpent、MAC 与 Zstandard；
- keyfile、分卷、可否认、压缩归档逐项开放，每项都需要跨三端语料；
- 旧 1 GiB 文件提供迁移说明，不在浏览器里强行执行。

#### W4：Web writer 与分块卷 v3（P2）

优先写分块认证 v3，而不是让 Web 重复承担所有旧 writer 的组合复杂度。Web、桌面、Android 三端
同时通过互操作闸门后才能默认写入。

#### W5：安装体验与离线运行（P2）

- 可添加到主屏幕，但普通 Safari 标签页仍必须能用；
- 离线缓存仅包含静态应用资源；
- 版本升级时若仍有任务，不自动替换 Worker；
- 设置页提供“清除网页暂存”和占用统计，语义与现有双端缓存管理一致。

### 8.6 不推荐方案 C：整体 Java → WASM

Safari 18.2 以后对 WASM GC 的支持让 Java/Kotlin 编译目标更现实，但项目的主要阻碍不是 GC，而是
平台 I/O、JNI、密码学库、压缩库、ImageIO/JavaFX 和移动内存边界。可以做一个小型 spike 验证纯
协议类能否编译，但不应以“最大化源码复用”为理由锁定整个 Web 架构。若 spike 无法同时通过 iOS
真机性能、包体和黄金向量，应及时终止，不影响方案 B。

### 8.7 Web 发布验收

- 浏览器生成文件必须被桌面和 Android 读取；两端生成文件必须被浏览器读取；
- CI 可用桌面 Chromium/Firefox/WebKit 做基础回归，但 Playwright WebKit 不能替代真实 iOS Safari；
- 每个正式版本至少在一台最低支持 iPhone、一台当前 iPhone 和一台 iPad 上跑真实文件矩阵；
- DevTools/代理观察不到文件、密码、派生密钥或明文上传；
- 刷新、关闭标签、系统杀进程、磁盘满后均不出现“看似成功但未认证”的文件；
- 首屏展示精确版本和支持协议，不允许服务端 HTML 与旧缓存 WASM 混用。

## 9. P2 能力扩展

### 9.1 F9：EGTC-IMG 更多输入格式

EGTC-IMG 的普通模式封装的是原文件字节，并不需要完整解码原图。因此 TIFF、HEIF/HEIC、AVIF、
JPEG 2000、QOI 等格式可以先通过有界魔数/容器品牌探测加入：

- 为每个格式冻结 `formatId`、MIME、推荐后缀和冲突处理；
- 普通模式允许封装与逐字节恢复；
- 抗重编码模式若平台没有可靠 decoder，则明确禁用，不阻塞普通模式；
- HEIF/AVIF 需解析 ISO-BMFF `ftyp` 兼容品牌，不能只看扩展名；
- SVG/EPS 等主动内容格式不建议直接预览，若支持只能作为普通字节文件恢复。

### 9.2 F10：统一隐写格式

以 STEG-V2 为长期主线：

1. 先让桌面端识别旧 `StegoMetadata` 并提供“迁移为 STEG-V2”；
2. 把 LSB 算法改成处理平台无关的 `RasterBuffer`，桌面/Android 分别提供像素解码桥；
3. STEG-V2 metadata 增加 carrier scheme ID，区分 PNG chunk、尾附、LSB；
4. Android 开放 LSB 前先完成桌面 ↔ Android 像素顺序、alpha、色彩空间黄金语料；
5. UI 明确 LSB 经聊天软件重编码通常会损坏，抗传输应优先使用 EGTC-IMG 纠错载体。

### 9.3 F11：媒体元数据 v3 与格式扩展

优先级顺序建议：

1. 为 EGTC-AVE metadata 增加 Header MAC，认证格式、档位、KDF、nonce、完整性开关和范围描述；
2. 保持 v1/v2 读取，新文件写 v3；篡改或移除完整性标志必须失败，而不是降级；
3. 支持 RF64，解决当前 `WavParser` 明确拒绝 >4 GiB WAV 的限制；
4. 再评估 FLAC 格式保持。FLAC 帧 CRC 和位流语义比“文件隐写到 FLAC metadata”复杂，不能因为已有
   `FlacCarrierAdapter` 就认为格式保持加密可直接复用；
5. WebM/MKV、AAC/ADTS 等只在有真实样本矩阵和解析库策略后立项。

## 10. 明确不建议或需要改写目标的功能

| 原始设想 | 结论 | 原因与可替代方案 |
|---|---|---|
| 安全删除原文件 | 不作“不可恢复”保证 | SSD 磨损均衡、TRIM、系统缓存、云同步和 Android SAF 使覆盖不可验证；只能提供普通删除、缓存清理和风险说明 |
| 多次输错自动焚烧密文 | 拒绝 | 攻击者可复制密文后离线尝试，反而容易误删用户唯一副本；保留设备本地限速和通知即可 |
| 纯离线时间锁加密 | 不宣称强安全 | 本地时钟可回拨、程序可修改；若使用在线密钥托管则是另一信任模型，应单独设计服务 |
| 任意大文件转英语单词序列 | 限定为恢复密钥/指纹 | 编码膨胀巨大、易抄错；可用于 128/256 位恢复秘密，不适合文件载荷 |
| 网络流量隐写 | 暂不进入产品主线 | 依赖网络环境和对端协议，双端稳定性低，并显著扩大安全与合规风险 |
| 继续增加 DES/3DES 等“现代密码”按钮 | 仅保留兼容/教学 | 不应与主线安全加密并列推荐；UI 应标出过时算法 |
| 公网云端代解密 | 默认拒绝 | 服务器会接触文件或凭据；若未来提供，必须作为明确的托管产品重新做威胁模型和隐私合规 |

## 11. 推荐实施顺序与工期级别

工期是相对量级，不是承诺日期；按 1–2 名熟悉当前仓库的开发者估计。

### 里程碑 A：稳定版收口（3–6 周）

- F0 图片 Phase 8 与全协议畸形输入基线；
- F2 统一格式检查器第一版；
- F3 Zstandard Android 互通；
- 订正 README、CHANGELOG、旧计划状态；
- F1 只完成核心模块边界和第一批包迁移，不同时做全构建系统迁移。

### 里程碑 B：兼容与迁移（3–5 周）

- F4 只读兼容报告；
- 事务式单文件迁移，再扩展批量队列；
- 双端共同使用迁移结果与失败报告格式。

### 里程碑 C：身份与安全分享（6–10 周）

- F5 detached signature；
- F8 密钥包、联系人和备份；
- F6 单接收者信封，再扩展多接收者；
- Android/桌面真实互发语料。

### 里程碑 D：Web 决策与 MVP（并行 6–10 周）

- W0 真机 spike 决定支持基线；
- 若急需完整功能，先交付自托管 Java 网关；
- 同时推进 W1/W2，本地 PWA 先支持 EGTC-IMG 恢复；
- W0 不通过时不承诺通用卷大文件 Web writer。

### 里程碑 E：卷 v3（8–16 周）

- 协议评审、确定性向量、纯内存模型；
- Desktop/Android reader；
- 双端 writer 与断点恢复；
- Web reader/writer；
- 完成三端互操作后才设为默认。

## 12. 每项功能的统一完成定义

任何标记为“双端完成”的能力必须同时满足：

1. 有冻结或版本化协议，字段、字节序、字符规范化、认证范围和资源上限明确；
2. 桌面和 Android 使用同一核心，或有同一黄金向量证明实现一致；
3. 四方向通过：Desktop→Desktop、Android→Android、Desktop→Android、Android→Desktop；
4. 错密码、篡改、截断、取消、空间不足、同名冲突均不留下最终半成品；
5. 进度、取消、错误分类、历史记录与中英文案接入；
6. 有最低版本兼容策略和旧文件回归；
7. 有峰值内存、临时空间和最大输入限制；
8. README、协议文档、CHANGELOG、UI 提示在同一版本交付；
9. Web 加入后扩展为六方向互操作，并增加真实 iOS Safari 闸门；
10. 任何安全降级都必须由用户显式选择并看到警告，不能静默发生。

## 13. 推荐的下一步决策

如果只能选择一个近期开发包，建议选择：

> **F0 + F2 + F3：发布闸门、统一格式检查器、Zstandard 双端互通。**

这三项不会制造新的协议孤岛，却能立即提高现有全部业务的稳定性，并为迁移工具与 Web 端提供统一的
能力预检。其后优先做 F4，帮助用户把历史文件迁到移动/Web 可处理的档位；再进入 F5/F6 的安全分享。

Web 端建议立即安排 W0 真机验证，但不要在验证前承诺“网页完整复刻全部桌面功能”。若 Apple 用户的
需求很紧迫，先交付自托管 Java 网关；若核心诉求是文件绝不离开手机，则直接投入本地 PWA，并接受
第一版只支持 EGTC-IMG 的事实。

## 14. Web 技术依据

- WebKit 的 OPFS 说明：iOS 15.2 起可用，Private Browsing 不可用，文件属于站点私有存储而非用户
  可直接访问的普通目录：<https://webkit.org/blog/12257/the-file-system-access-api-with-origin-private-file-system/>
- WebKit 的 Safari 17 Storage API 与配额策略说明：<https://webkit.org/blog/14445/webkit-features-in-safari-17-0/>
  和 <https://webkit.org/blog/14403/updates-to-storage-policy/>
- WebKit 的 Web Share 文件能力说明：<https://webkit.org/blog/11989/new-webkit-features-in-safari-15/>
- W3C Web Cryptography Level 2 的算法范围与“实现不强制支持全部算法”说明：
  <https://www.w3.org/TR/WebCryptoAPI/>
- WebKit 的 WASM GC 说明，明确 Java/Kotlin 等 GC 语言此前需要自带 GC，而 WASM GC 只改善语言映射：
  <https://webkit.org/blog/16301/webkit-features-in-safari-18-2/>
- WebKit 的 Safari 18.4 X25519 支持说明：<https://webkit.org/blog/16574/webkit-features-in-safari-18-4/>

