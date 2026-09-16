# EGTC-IMG v1 跨端互操作永久语料（v1）

本目录是**冻结资产**。它存在的唯一目的，是让"桌面端生成的图片密文能不能被 Android 端还原"
这句话可以被机器证明，而不是靠"两端都跑了一遍各自的单元测试"来推断。

## 为什么必须交换同一批字节

两端各自实现一遍协议再互相比对结果，**证明不了互操作性**：只要两边的实现同时犯了同一个错误，
测试照样全绿。本目录把桌面 JVM 实际生成的产物字节固化下来，Android 侧只读取、不重新生成，
因此任何一端偏离 v1 契约都会立刻暴露。

同理，`android/shared-test` 与宿主 JVM 上的 `KdfFourWayInteropTest` **不能**替代本语料 ——
它们跑在同一台 PC 的 JVM 上，完全没有经过 ART、APK 内依赖、native libargon2 与 Android 文件环境。

> 本语料已经证明过自己的价值：Phase 4 首次在 ART 上运行时，立刻暴露出
> `Files.getFileStore` 在 Android 上抛 `SecurityException`（平台 `statvfs` 受 SELinux 约束），
> 而磁盘空间预检当时只捕获 `IOException`——**每一次图片加解密都会崩溃**。
> 这个问题在宿主 JVM 上完全不可见。

## 文件清单

| 文件 | 说明 |
|---|---|
| `corpus-input.png` | 原始输入（160 × 120 渐变，PNG） |
| `corpus-input.jpg` | 原始输入（同一图案，JPEG） |
| `desktop-corpus-input-png-public-v1.egimg.png` | 桌面生成的公开恢复产物 |
| `desktop-corpus-input-png-password-ascii-v1.egimg.png` | 桌面生成的密码保护产物（ASCII 口令） |
| `desktop-corpus-input-png-password-unicode-v1.egimg.png` | 桌面生成的密码保护产物（NFC 组合字符口令） |
| `desktop-corpus-input-jpg-*.egimg.png` | 同上三种，输入为 JPEG |
| `corpus.properties` | 输入、口令、协议中间值、恢复名与全部 SHA-256 |

`corpus.properties` 的字段含义：

| 键 | 说明 |
|---|---|
| `corpus.version` / `corpus.generator` | 语料版本与生成端标识 |
| `corpus.jdk` / `corpus.bouncycastle` / `corpus.appVersion` | 生成环境，用于复现与排查 |
| `password.ascii` / `password.unicode` / `password.unicode.nfd` | 测试口令的三条形态（一次性测试值，非任何真实凭据） |
| `password.*.utf8Hex` | **规范化后**的 UTF-8 字节，两端都必须导出完全相同的值 |
| `input.N.file/length/sha256` | 原始输入的身份 |
| `entry.N.id/input/file/mode/passwordKey` | 条目与输入的对应关系 |
| `entry.N.canvasWidth/canvasHeight/innerPlainLength` | 协议头字段，读取时会被重新解析并逐字段比对 |
| `entry.N.argon2Salt/hkdfSalt/nonce/keyConfirm/authTag` | 协议中间值，公开模式的 `argon2Salt` 为空 |
| `entry.N.artifactLength/artifactSha256` | 产物身份：语料被误改时立刻发现 |
| `entry.N.restoredName` | 预期恢复文件名（含 `.restored` 标记与魔数决定的扩展名） |
| `entry.N.restoredLength/restoredSha256` | **核心断言**：恢复结果必须与原始输入逐字节一致 |

文件以 **UTF-8** 写出。读取方必须显式指定 UTF-8 —— `Properties.load(InputStream)` 的默认编码是
ISO-8859-1，会把组合字符口令读成乱码，进而派生出不同的密钥，并报出误导性的"文件已损坏"。

## 覆盖矩阵

| 输入 | 公开恢复 | 密码保护（ASCII） | 密码保护（NFC 组合字符） |
|---|:---:|:---:|:---:|
| `corpus-input.png` | ✅ | ✅ | ✅ |
| `corpus-input.jpg` | ✅ | ✅ | ✅ |

NFC 组合字符口令用的是 `café-中文`，语料里同时记下它的 NFD 形态。它钉住了"密码必须经
NFC + UTF-8 规范化"这条约束：若某一端漏了 NFC，两端会派生出不同的密钥，keyConfirm 阶段就会失败。

## 重新生成

语料**只应在本协议版本提升或有意变更测试素材时**重新生成：

```bash
mvn -q test-compile
java -cp "target/classes;target/test-classes;<deps>" \
     hbnu.project.ergoutreecrypt.imagecrypt.interop.InteropCorpusGenerator \
     src/test/resources/imagecrypt/interop/v1
```

生成器会重写目录内容（**不会**重建本 README，重跑后请确认它仍在）。
`corpus.properties` 的输出是确定性的（按键排序、不含时间戳），因此重新生成的 diff 只会反映
真正的内容变化。

产物字节会随 `SecureRandom` 变化，**这是正常的**：语料冻结的不是"某次运行的产物"，而是
"这份产物的字节能被另一端正确还原"。因此每次重新生成后，`artifactSha256` 会变，
而 `restoredSha256` 必须不变。

## 双端如何使用

| 使用方 | 方式 |
|---|---|
| 桌面 JVM | `ImageCryptInteropCorpusTest` 通过 classpath 读取本目录 |
| Android ART | Gradle 把本目录同步到 `app/src/androidTest/assets/imagecrypt/interop/`，由 `ImageCryptInteropTest` 读取 |

Android 侧同步的是**同一份文件**，不存在两边各存一份副本而逐渐漂移的可能。

## 如何跑完整闸门

### 方向一：Desktop → Android（在设备上还原本目录的产物）

```bash
cd android
./gradlew :app:installDebug :app:installDebugAndroidTest
adb shell am instrument -w \
  -e class hbnu.project.ergoutreecrypt.android.ImageCryptInteropTest \
  hbnu.project.ergoutreecrypt.debug.test/androidx.test.runner.AndroidJUnitRunner
```

### 方向二：Android → Desktop（设备生成，桌面还原）

```bash
# 上一步已把设备产物写入应用外部私有目录，拉回本机
adb pull /sdcard/Android/data/hbnu.project.ergoutreecrypt.debug/files/imagecrypt-interop-out <本地目录>

# 交给桌面 JVM 校验（未提供目录时该用例会跳过并打印这段命令）
mvn test -Dtest=ImageCryptAndroidArtifactTest \
  -Dimagecrypt.android.export=<本地目录>
```

> ⚠️ **不要用 `./gradlew connectedDebugAndroidTest`**：它在结束时**卸载被测应用**，
> 设备上导出的产物会随之消失，方向二就没得可拉了。设备侧用例本身在两种方式下都能通过，
> 但只有 `installDebug` + `am instrument` 才能把产物留在设备上。
>
> 另外，测试进程用的是**被测应用**的上下文（`targetContext`）而不是测试 APK 的上下文：
> 真实流程读写的是应用自己的私有目录，而且测试运行器包的数据目录在部分设备上不会被预先创建。
>
> OnePlus/ColorOS 可能把没有前台 Activity 的 instrumentation 目标进程冻结在
> `do_freezer_trap`。若测试长时间无输出，可在另一个终端执行：
> `adb -s <serial> shell am start -n hbnu.project.ergoutreecrypt.debug/hbnu.project.ergoutreecrypt.android.MainActivity`。
> 这会让同一个测试进程继续，不会清除已经生成的导出产物。

## 实测结果（2026-09-16）

| 方向 | 环境 | 结果 |
|---|---|---|
| Desktop → Android | ART，API 36，x86_64 模拟器 | ✅ 6 份产物逐字节还原 |
| Desktop → Android | ART，API 26，x86_64 模拟器 | ✅ 6 份产物逐字节还原 |
| Desktop → Android | ART，API 36，arm64-v8a 真机（OnePlus PLK110） | ✅ 6 份产物逐字节还原 |
| Android → Desktop | JDK 21.0.4，读取上述三档 Android 导出产物 | ✅ 每档 6 份产物逐字节还原 |
| Argon2 三执行路径 | API 26 x86_64、API 36 x86_64、API 36 arm64（native libargon2 均可用，未跳过） | ✅ 与 BC 堆内、离堆逐字节一致 |
| NFC 组合字符口令 | 桌面与上述三档 Android ART | ✅ NFC 与 NFD 导出相同字节 |

## 尚未覆盖

- 本语料目前只由**桌面端**生成。Android 端生成的产物经 instrumentation 导出后由桌面 JVM
  校验，但尚未作为永久黄金文件归档（计划在 Phase 8 固化）。
- `image-crypt-interop` CI 作业尚未完成首次远端运行；工作流当前只存在于尚未推送的本地提交中。
