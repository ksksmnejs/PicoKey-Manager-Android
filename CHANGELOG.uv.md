# 更新日志（UV 配置分支）

这是 `uv-config` 分支**自己的**更新日志，与主线 `CHANGELOG.md` 完全独立。

两者分开是必须的：主线的 CI 从 `CHANGELOG.md` 取版本号，分支的 CI 从本文件取。
如果共用一份，任一分支构建时都会改写对方的版本号，两条线的版本序列会互相踩。

因此本分支的版本号从 **0.3.0** 起（主线当时是 0.2.3），tag 不会撞。

格式与主线一致：

```markdown
## [vX.Y.Z] - YYYY-MM-DD

### 新增
- 某某功能
```

---

## [v0.3.0] - 2026-10-02

### 新增

- **用户验证策略配置（authenticatorConfig，CTAP 0x0D）** —— 设备页新增一节，
  填写设备的 FIDO2 PIN 后可以：
  - **切换 alwaysUv**：这是「每次都要输 PIN」和「只要按一下按键」之间的开关。
    alwaysUv 开启时每次注册都要用户验证，平台用 PIN 满足它，物理按键从不参与；
    关掉之后 makeCredUvNotRqd 才可能为 true，非驻留凭证可只凭按键创建
  - **设置最小 PIN 长度**：只能增大，不可撤销（想改回只能重置认证器，会删掉全部凭证）
- 显示当前 alwaysUv / makeCredUvNotRqd / clientPin 状态，取自连接时的 getInfo
- 密码学全部自实现（P-256 ECDH、AES-256-CBC、HMAC-SHA-256），**不引入 cryptography 依赖**——
  否则每次 CI 都要编译 Rust 工具链，构建时间和失败率都会显著上升

### 说明

- 仅支持 PIN/UV auth protocol 1。protocol 2 的密钥派生若写错，失败表现与「PIN 错误」
  完全一致，在无法真机验证的情况下不可接受
- 只在 **FIDO HID 通道**可用；CCID 通道下两个按钮自动置灰
- 网页版 **不提供**此功能：CTAP 只走 HID（接口类 0x03），而 Chrome 的受保护接口
  清单屏蔽了 HID，网页连不上 FIDO 通道
