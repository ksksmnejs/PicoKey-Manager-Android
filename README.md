# PicoKey Manager for Android

[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Platform](https://img.shields.io/badge/Platform-Android%208.0%2B-green.svg)](https://www.android.com/)
[![Hardware testing](https://img.shields.io/badge/%E7%9C%9F%E6%9C%BA%E9%AA%8C%E8%AF%81-%E6%9C%AA%E8%BF%9B%E8%A1%8C-critical.svg)](#验证状态)
[![Authored by](https://img.shields.io/badge/%E4%BB%A3%E7%A0%81%E4%B8%8E%E6%96%87%E6%A1%A3-AI%20%E7%94%9F%E6%88%90-8A2BE2.svg)](#ai-生成声明)

简体中文 | [English](README.en.md)

一个通过 USB OTG 连接**开发板**（板子运行 Pico HSM / Pico FIDO / Pico OpenPGP 固件）的安卓应用。
用 OTG 转接线把设备插到手机上，就能读取设备信息、修改 PHY 配置（USB VID/PID、LED 引脚
与亮度、启用的 USB 接口）、让 LED 闪一下、重启设备，或进入刷机模式写入新固件。

支持的芯片：**RP2040、RP2350、ESP32-S2、ESP32-S3**——见[支持的开发板](#支持的开发板)。

**下载**：已编译好的 APK 在本仓库的 [Releases](../../releases) 页面，取最新版本安装即可。
旧版本也保留在同一个页面，随时可以回退；各版本改了什么见 [CHANGELOG.md](CHANGELOG.md)。

**升级可以直接覆盖安装，不需要先卸载**——所有版本都用同一个签名密钥构建。

仓库里还有一个**网页版刷写工具** `picokey-commissioner.html`，已通过 GitHub Pages 部署，
用手机 Chrome 打开即可（WebUSB 要求 HTTPS，Pages 正好免费提供）：

```
https://ksksmnejs.github.io/PicoKey-Manager-Android/
```

它由 `.github/workflows/static.yml` 自动部署，不需要任何操作。

**它能做什么**：只做一件事——给处于下载模式的 ESP32-S2 / S3 刷入固件（走的是 esptool
ROM 协议，不需要安装任何工具）。

**它不能做什么**：无法改 VID/PID、无法开安全启动/安全锁，也无法读取运行中的设备信息。
原因是 Chrome 从 67 起（CVE-2018-6125）就屏蔽了浏览器对智能卡（CCID）接口的访问，
而 PicoKey 固件正常运行时用的正是 CCID——固件跑起来以后，浏览器根本看不到这块板子。
这些操作请用安卓 App（它走 Android USB Host API，不受此限制）。

---

## AI 生成声明

**本仓库的代码由 AI 编写，并非固件上游作者的作品。** 设备出现异常时，
请优先怀疑这个 App，而不是怀疑你的板子或固件。

**这份文档同样由 AI 撰写，可能存在错误。** 文中的技术细节——USB ID、芯片差异、
曲线兼容性、Secure Boot 支持情况——来自公开资料整理，未经逐项实测核对。
与固件官方文档或上游仓库冲突时，**以上游为准**。

如果发现错漏，欢迎开 Issue 指出；涉及安全的操作（写入 PHY、安全启动、刷写固件）
请以固件官方文档和你的板子说明书为准，不要只依赖本文。

---

## 验证状态

协议层有自动化自检覆盖，但**全部代码从未在真实开发板上运行过**：

- 协议自检与模拟链路全部通过，但测试用的是**模拟设备**，不是真机响应。
- USB 权限弹窗的实际行为、OTG 供电、不同厂商对 HID 接口的占用情况均未实测。
- 写入 PHY 后的实际效果未验证。

**所以第一次请只读取、确认数值无误，再考虑写入。**

---

## 支持的开发板

PicoKeys 固件跑在四种芯片上。协议层完全一样，差别全在**刷机方式、进入刷机模式的方式、
以及安全特性**上。

| 芯片 | 典型板子 | 刷机方式 | Secure Boot / Lock |
| --- | --- | --- | --- |
| **RP2040** | Raspberry Pi Pico / Pico W | UF2（刷机模式下变成 U 盘） | ❌ 无硬件保护 |
| **RP2350** | Pico 2、Waveshare RP2350-One/Zero/Tiny | UF2（刷机模式下变成 U 盘） | ✅ 完整支持 |
| **ESP32-S2** | ESP32-S2 开发板 | esptool / DFU | ⚠️ 存疑 |
| **ESP32-S3** | ESP32-S3 SuperMini、DevKitC | esptool / DFU | ⚠️ 存疑 |

### RP2040 与 RP2350 的安全性完全不同

- RP2350 有 OTP（一次性可编程）区，可存放加密所有密钥的主密钥，配合 Secure Boot /
  Secure Lock 能抵抗 flash 被读出。
- **RP2040 没有这套硬件**。它的 flash 内容可被直接读取，板子丢了私钥就暴露。

如果安全性是目的，请用 RP2350 或 ESP32-S3，别用 RP2040。

### ESP32 上会遇到的两个坑

**下载模式下设备名会变。** 进下载模式后设备自报为 **"USB JTAG/serial debug unit"**，
那不是固件的 CCID 接口，对它发指令不会有任何回应。日志里看到这个名字，说明板子
卡在下载模式——**拔掉、什么都不按、重新插**。

**Secure Boot 支持情况不确定。** 官方声称 ESP32-S3 支持，社区分叉（LibreKeys）标注的是
`No (// TODO)`，两边说法不一致。先点「读取安全启动状态」，读不出来或值异常就**不要硬写**——
OTP 熔丝烧错了是物理级不可逆的。

### 出厂 VID/PID：你可能什么都不用配

2026 年 1 月起固件出厂就用树莓派正式分配的 USB ID：

| 固件 | VID:PID |
| --- | --- |
| Pico HSM | `2E8A:10FD` |
| Pico FIDO | `2E8A:10FE` |
| Pico OpenPGP | `2E8A:10FF` |

更早的固件用占位 ID `FEFF:FCFD`，那种才必须改。**如果你的目的只是"当个能用的 FIDO2 密钥"
且 VID/PID 已是上表中的值，那就什么都不用配。** 改 VID/PID 主要是为了伪装成 YubiKey
（让某些网站或 Yubico Authenticator 认）。

---

## 功能

- **设备扫描** — 列出所有可用通道：
  - `CCID` — 功能最全：设备信息、PHY、安全启动、重启
  - `rescue`（vendor `0xFF`）— 固件未启动时的备用通道
  - `FIDO HID` — WINK 闪灯、`authenticatorGetInfo`
- **PHY 配置读写** — USB VID/PID、产品名、LED GPIO 与亮度、USB 接口开关、启用曲线
- **安全启动** — 读取状态、设置启动密钥槽、永久锁定
- **设备信息** — 平台、产品、固件版本、Flash 用量
- **维护** — 重启、进入刷机模式、WINK 闪灯
- **固件刷写** — 用系统文件管理器选一个固件文件写入，见[固件刷写](#固件刷写)
- **中英双语界面** — 右上角切换，选择会被记住
- **协议自检** — 用假 USB 管道把协议栈跑一遍，不需要硬件

---

## 使用方法

1. 用 **OTG 转接线**连接开发板。**上电时不要按住任何按键**——部分板子按键上电会
   直接进入刷机模式，此时它不作为固件设备出现，App 连不上。
2. 打开 App → **扫描 USB 设备**，列表里会出现每个可用通道。
3. 点一个连接。手机会弹 USB 授权对话框，**必须点允许**（只弹一次；拒了要去系统设置里
   重新开启）。
4. 设备页操作：读取设备信息 / 读取 PHY 配置 / 写入 PHY 配置 / WINK / 进入刷机模式。

设备没被识别时，先点**运行协议自检**——它不需要硬件。全绿说明 App 本身没问题，
问题在 OTG 线、供电或转接头上。

### 首次使用的建议顺序

1. **先只读取，不写入** — 能读到设备信息就说明链路通了
2. 改 VID/PID 时，留空字段会自动继承设备当前值，不会冲掉 LED GPIO 这类板子特定配置
3. **启用曲线至少勾 P-256**（ES256，WebAuthn 最通用的默认算法），**不要勾 secp256k1** —
   官方文档警告部分旧安卓设备不支持它，启用后设备可能无法识别
4. **安全启动留到最后**，且需满足：已注册通行密钥并日常验证过、有备份、确认刷的是官方
   原版固件、接受不可逆后果

---

## 固件刷写

App 里有「固件刷写」页（扫描页底部进入），处理两种机制完全不同的路径：

| 板子 | 底层机制 | 本 App 的做法 |
|---|---|---|
| RP2040 / RP2350 | 刷机模式下 flash 变成 U 盘，拷入 `.uf2` 即完成 | 把 UF2 交给系统文件管理器，由你存到 `RPI-RP2` / `RP2350` 盘里 |
| ESP32-S2 / S3 | USB Serial/JTAG 上的 esptool ROM 协议，没有 UF2 bootloader | 直接实现该协议，不需要外部工具 |

点「选择固件文件」，App 会**调用手机上的系统文件管理器**（Android 的存储访问框架）让你挑一个
`.uf2` 或 `.bin`。

系统文件管理器能看到完整存储——内部存储、SD 卡、OTG 优盘、网盘都行。App 自己不去遍历目录，
所以不需要任何存储权限。

加载后 App 会识别文件类型并显示大小；确认为 **UF2** 或 **ESP 镜像**时才进一步显示适用芯片。若识别为 ZIP、gzip 或网页，会明确提示——那说明拿到的不是固件本体。

固件文件需要你自己准备（例如从上游开源仓库 `polhenarejos/pico-fido` 的 Releases 下载），本 App 不联网、也不内置任何固件。

⚠️ **两条刷写路径都没有在真机上验证过。** 第一次建议只做识别、不刷写，对着日志确认每一步。

---

## 已知限制

- 需要 Android 8.0（API 26）以上、支持 USB host 的设备和一根 OTG 转接线。
- 没有热插拔监听，拔线后回到扫描页重新连接即可。
- "安全通道 / DKEK"相关功能不可用（依赖的加密库未打包），其余功能正常。
- **RP2040 没有 OTP 保护**，flash 可被直接读出；需防物理提取请用 RP2350 或 ESP32-S3。
- 三种固件（HSM / FIDO / OpenPGP）**不能共存**，切换需先刷 Pico Nuke 清空。
  建议按用途各用一块板子，而不是来回切换。
- **「用户存在」（按物理按键）取决于板子上有没有真的焊按键。** 多数 Pico 板出厂只有
  BOOTSEL，没有用户按键；没焊按键、或 PHY 里的「确认按键 GPIO」与实际接线不一致时，
  注册通行密钥只验证 PIN 就能通过，不会要求触摸。可用设备页的
  **「测试用户存在（物理按键）」** 实测：立刻返回说明没在等你按键，等待后才返回才是真的
  生效了。
- 签名密钥 `tools/debug.keystore.b64` 随仓库公开，因此每次自动构建的签名都一致、
  升级可以直接覆盖安装。代价是任何人都能用它签出同包名的 APK——debug 密钥本就不是安全
  边界（Android 官方设计如此）。

  **下面这条只有自行构建这个 App 的人才用得上**，普通用户不必理会：想换成自己的密钥，
  把密钥 base64 编码后存成仓库 Secret `ANDROID_KEYSTORE_BASE64`，它会优先生效、
  仓库里那把被忽略。

---

## 故障排查

- **设备扫得到、一连就失败** — 多半是 USB 权限弹窗被拒。Android 只弹一次，
  拒了要去系统设置里重新允许，或卸载重装 App。
- **日志里出现 "USB JTAG/serial debug unit"（ESP32）** — 板子在下载模式，
  固件没有正常运行。拔掉、什么都不按、重新插。
- **ESP32 上安全启动读不出来** — 大概率该功能在这块板子上没实现。不要硬写，OTP 不可逆。

---

## 许可证

上游 `pypicokey` 为 AGPL-3.0-or-later，`picokeyapp/pk/` 下的文件沿用该许可
（见 `LICENSE`）；安卓移植与界面部分同样以 AGPL-3.0-or-later 发布。

随包的字体 `assets/fonts/NotoSansSC-Regular-subset.ttf` 来自
[Noto Sans SC](https://fonts.google.com/noto/specs/NotoSansSC)，
以 SIL Open Font License 1.1 授权（允许嵌入与再分发），不受本项目 AGPL 约束。
