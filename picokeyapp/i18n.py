"""
Bilingual UI strings.

Why this exists
---------------
The app was originally written with hard-coded Chinese text, which rendered as
tofu boxes on Android: Kivy's bundled font (Roboto) has no CJK glyphs. The fix
is two-fold - ship a CJK font (see picokeyapp/fonts.py) and put every visible
string behind `t()` so the whole UI can switch between 简体中文 and English.

Usage
-----
    from .i18n import t, set_lang, get_lang
    t('btn_scan')                  # -> '扫描 USB 设备' / 'Scan USB devices'
    t('scan_found', n=3)           # -> '找到 3 个通道…'

Keys are stable English identifiers; adding a language means adding a dict.
"""

from __future__ import annotations

LANGS = ("zh", "en")
DEFAULT_LANG = "zh"

# Language names are always shown in their own language, like every decent
# language picker does.
LANG_NAMES = {"zh": "简体中文", "en": "English"}

_current = DEFAULT_LANG

STRINGS = {
    # ------------------------------------------------------------ generic
    "app_title": {"zh": "PicoKey Manager", "en": "PicoKey Manager"},
    "language": {"zh": "语言", "en": "Language"},
    "btn_scan": {"zh": "扫描 USB 设备", "en": "Scan USB devices"},
    "btn_selftest": {"zh": "运行协议自检（无需硬件）", "en": "Run protocol self-test (no hardware)"},
    "btn_logs": {"zh": "查看日志", "en": "View log"},
    "btn_back": {"zh": "返回", "en": "Back"},
    "btn_clear": {"zh": "清空", "en": "Clear"},
    "btn_disconnect": {"zh": "断开连接", "en": "Disconnect"},
    "btn_back_scan": {"zh": "返回扫描页", "en": "Back to scan"},

    # ------------------------------------------------------------ scan page
    "scan_intro": {
        "zh": "把开发板用 OTG 转接线插到手机上，然后点“扫描 USB 设备”。上电时不要按住按键。",
        "en": "Plug the board into the phone with an OTG adapter, then press “Scan USB devices”. Hold no buttons while powering up.",
    },
    "scanning": {"zh": "扫描中…", "en": "Scanning…"},
    "scan_none_hint": {
        "zh": "没找到可用设备。检查 OTG 线和供电，或点“查看日志”。",
        "en": "No device found. Check the OTG cable and power, or open the log.",
    },
    "scan_none_item": {"zh": "（无设备）", "en": "(no device)"},
    "scan_found": {"zh": "找到 {n} 个通道，点一个连接：", "en": "{n} channel(s) found, tap one to connect:"},
    "connecting": {"zh": "连接中（手机上要允许 USB 权限）…", "en": "Connecting (allow USB access on the phone)…"},
    "connected": {"zh": "已连接", "en": "Connected"},

    # ---------------------------------------------------------- device page
    "not_connected": {"zh": "未连接", "en": "Not connected"},
    "lbl_platform": {"zh": "平台", "en": "Platform"},
    "lbl_product": {"zh": "产品", "en": "Product"},
    "lbl_version": {"zh": "版本", "en": "Version"},
    "lbl_channel": {"zh": "通道", "en": "Channel"},
    "lbl_flash": {"zh": "Flash", "en": "Flash"},
    "lbl_files": {"zh": "文件数", "en": "Files"},
    "lbl_firmware": {"zh": "固件", "en": "Firmware"},
    "lbl_protocol": {"zh": "协议版本", "en": "Protocol"},
    "lbl_device_ver": {"zh": "设备版本", "en": "Device version"},
    "lbl_caps": {"zh": "能力", "en": "Capabilities"},
    "lbl_cid": {"zh": "CID", "en": "CID"},
    "flash_line": {
        "zh": "Flash：已用 {used:.1f}KB / 共 {total:.1f}KB，剩余 {free:.1f}KB",
        "en": "Flash: {used:.1f}KB used / {total:.1f}KB total, {free:.1f}KB free",
    },
    "files_line": {"zh": "文件数：{n}，固件：{size:.1f}KB", "en": "Files: {n}, firmware: {size:.1f}KB"},

    "btn_refresh": {"zh": "重新读取设备信息", "en": "Re-read device info"},
    "btn_read_phy": {"zh": "读取 PHY 配置", "en": "Read PHY config"},
    "field_vid": {"zh": "VID (hex)", "en": "VID (hex)"},
    "field_pid": {"zh": "PID (hex)", "en": "PID (hex)"},
    "field_led_gpio": {"zh": "LED GPIO", "en": "LED GPIO"},
    "field_led_btness": {"zh": "LED 亮度 (0-255)", "en": "LED brightness (0-255)"},
    "field_led_driver": {"zh": "LED 驱动", "en": "LED driver"},
    "btn_write_phy": {"zh": "写入 PHY 配置（会重启设备）", "en": "Write PHY config (reboots device)"},
    "btn_wink": {"zh": "WINK：让 LED 闪一下（FIDO）", "en": "WINK: blink the LED (FIDO)"},
    "btn_reboot": {"zh": "重启设备", "en": "Reboot device"},
    "btn_reboot_bootsel": {"zh": "重启到刷机模式（用于写入固件）", "en": "Reboot to flashing mode (for firmware)"},

    # ------------------------------------------------------------ log page
    "log_title": {"zh": "日志 / APDU", "en": "Log / APDU"},
    "log_empty": {
        "zh": "（暂无日志。日志会随连接、读取、刷写等操作自动累积。）",
        "en": "(No log entries yet. Lines appear as the device connects, reads and flashes.)",
    },

    # ------------------------------------------------------------- channels
    "ch_ccid_title": {"zh": "CCID 智能卡通道", "en": "CCID smartcard channel"},
    "ch_ccid_detail": {
        "zh": "走 CCID 帧的 APDU，功能最全（设备信息 / PHY / 重启）",
        "en": "APDU over CCID frames, full feature set (info / PHY / reboot)",
    },
    "ch_rescue_title": {"zh": "救援通道 (vendor 0xFF)", "en": "Rescue channel (vendor 0xFF)"},
    "ch_rescue_detail": {
        "zh": "固件没起来或 PC/SC 不可用时的备用通道，同样是 CCID 帧",
        "en": "Fallback when firmware is down or PC/SC is unusable, same CCID frames",
    },
    "ch_fido_title": {"zh": "FIDO HID 通道", "en": "FIDO HID channel"},
    "ch_fido_detail": {
        "zh": "CTAPHID：WINK 闪灯、读 authenticatorGetInfo",
        "en": "CTAPHID: WINK blinking, authenticatorGetInfo",
    },

    # ------------------------------------------------------- status messages
    "msg_processing": {"zh": "处理中…", "en": "Working…"},
    "msg_refreshed": {"zh": "已刷新", "en": "Refreshed"},
    "msg_reading": {"zh": "读取中…", "en": "Reading…"},
    "msg_writing_phy": {"zh": "写入 PHY…", "en": "Writing PHY…"},
    "msg_reading_phy": {"zh": "读取 PHY…", "en": "Reading PHY…"},
    "ka_processing": {"zh": "设备处理中…", "en": "Device is processing…"},
    "ka_upneeded": {"zh": "请触摸开发板上的按键", "en": "Touch the button on the board"},
    "ka_unknown": {"zh": "设备繁忙（状态 %s）", "en": "Device busy (status %s)"},
    "msg_winking": {"zh": "发送 WINK…", "en": "Sending WINK…"},
    "msg_rebooting": {"zh": "重启中…", "en": "Rebooting…"},
    "msg_phy_read": {
        "zh": "PHY 已读取：VID={vid} PID={pid} LED_GPIO={gpio} 亮度={btness}",
        "en": "PHY read: VID={vid} PID={pid} LED_GPIO={gpio} brightness={btness}",
    },
    "msg_phy_written": {"zh": "PHY 已写入，设备正在重启", "en": "PHY written, device is rebooting"},
    "msg_phy_written_log": {
        "zh": "PHY 写入完成，重新插拔或重新扫描即可连回。",
        "en": "PHY write done. Re-plug or re-scan to reconnect.",
    },
    "msg_wink_sent": {"zh": "已发送 WINK，看设备 LED", "en": "WINK sent - watch the device LED"},
    "msg_reboot_sent": {"zh": "已发送重启命令", "en": "Reboot command sent"},
    "msg_disconnected": {"zh": "已断开", "en": "Disconnected"},
    "msg_selftest_running": {"zh": "自检中…", "en": "Self-testing…"},
    "msg_selftest_done": {"zh": "自检完成，详见日志", "en": "Self-test done, see the log"},
    "msg_failed": {"zh": "失败：{err}", "en": "Failed: {err}"},
    "msg_closed_error": {"zh": "关闭时出错：{err}", "en": "Error while closing: {err}"},
    "msg_connected_log": {"zh": "已连接：{label}", "en": "Connected: {label}"},
    "msg_getinfo_failed": {"zh": "getInfo 失败：{err}", "en": "getInfo failed: {err}"},
    "msg_reconnect_needed": {"zh": "请重新读取或重新连接", "en": "Re-read or reconnect"},

    # ---------------------------------------------------------------- errors
    "err_no_apdu": {"zh": "这个操作需要 CCID / 智能卡通道，当前连的是 FIDO HID 通道。请回到扫描页，选 CCID（智能卡）通道连接。", "en": "This needs the CCID / smart-card channel, but the FIDO HID one is in use. Go back to the scan page and pick the CCID channel."},
    "err_no_ctap": {"zh": "这是 FIDO HID 通道的功能（WINK、用户存在测试），当前连的是 CCID / 智能卡通道。请回到扫描页，选 FIDO HID 通道连接。", "en": "That is a FIDO HID channel feature (WINK, user presence test), but the CCID one is in use. Go back to the scan page and pick the FIDO HID channel."},
    "err_phy_read": {"zh": "读取 PHY 失败", "en": "Reading PHY failed"},
    "err_not_android": {"zh": "USB Host 只在安卓真机上可用（当前：{plat}）", "en": "USB host only works on a real Android device (current: {plat})"},
    "err_permission_denied": {
        "zh": "USB 权限被拒绝（弹窗里要点“允许”，并且只弹一次）",
        "en": "USB permission denied (tap Allow in the dialog - it is asked only once)",
    },
    "err_no_permission": {"zh": "UsbManager 仍然没有权限", "en": "UsbManager still has no permission"},
    "err_not_fido": {"zh": "这个 HID 接口不像 FIDO 设备（报告描述符里没有 usage page 0xF1D0）", "en": "This HID interface does not look like FIDO (no 0xF1D0 usage page in the report descriptor)"},
    "err_claim_failed": {"zh": "接口占用失败（多半是内核 HID 驱动占着）", "en": "Could not claim the interface (a kernel HID driver probably holds it)"},
    "err_open_device": {"zh": "打不开设备：USB 权限没给，或设备被别的 App 占用。确认弹窗点了「允许」；若之前拒过，需卸载重装 App（或到系统设置撤销 USB 权限）后重插。", "en": "Cannot open the device: USB permission denied, or another app holds it. Make sure Allow was tapped; if permission was denied earlier, reinstall the app (or revoke the USB permission in system settings) and replug."},
    "err_no_endpoints": {"zh": "这个接口没有可用的 IN/OUT 端点", "en": "This interface has no usable IN/OUT endpoints"},

    # ------------------------------------------------------------- self-test
    "selftest_title": {"zh": "协议自检", "en": "Protocol self-test"},
    "selftest_cbor": {"zh": "CBOR 编解码", "en": "CBOR codec"},
    "selftest_ccid": {"zh": "CCID 组帧 / APDU", "en": "CCID framing / APDU"},
    "selftest_ctap": {"zh": "CTAPHID / FIDO", "en": "CTAPHID / FIDO"},
    "selftest_errors": {"zh": "—— 错误处理 ——", "en": "—— Error handling ——"},
    "selftest_passed": {
        "zh": "全部通过：协议层行为与上游一致。",
        "en": "All checks passed: protocol behaviour matches upstream.",
    },
}


# ---------------------------------------------------------------------------
# Commissioning (the extra PHY options and curves) and secure boot.
# Kept in a second block so the general UI strings above stay readable.
# ---------------------------------------------------------------------------
STRINGS.update({
    # ------------------------------------------------------------ sections
    "sec_phy": {"zh": "—— PHY 配置 ——", "en": "—— PHY configuration ——"},
    "sec_opts": {"zh": "—— 选项 ——", "en": "—— Options ——"},
    "sec_curves": {"zh": "—— 启用曲线（HSM）——", "en": "—— Enabled curves (HSM) ——"},
    "sec_security": {"zh": "—— 安全启动 ——", "en": "—— Secure boot ——"},
    "skip_no_source": {
        "zh": "已打包环境无源码，跳过（仅源码环境检查）",
        "en": "packaged build has no source on disk; skipped",
    },
    "sec_firmware": {"zh": "—— 固件与重启 ——", "en": "—— Firmware & reboot ——"},

    # ------------------------------------------------------- extra PHY fields
    "field_usb_product": {"zh": "USB 产品名", "en": "USB product"},
    "btn_probe_secure": {
        "zh": "诊断：列出可读对象",
        "en": "Diagnose: list readable objects",
    },
    "msg_probe_running": {"zh": "正在探测…", "en": "Probing…"},
    "msg_probe_done": {"zh": "探测完成，见日志", "en": "Probe finished, see the log"},
    "probe_title": {
        "zh": "救援通道可读对象（INS 1E，仅读取，无副作用）：",
        "en": "Rescue applet readable objects (INS 1E, read-only, no side effects):",
    },
    "probe_footer": {
        "zh": "已知：P1=01 是 PHY 配置，P1=02 是 Flash 信息，P1=03 是安全状态。若表中没有返回"
             "安全状态的对象，说明当前固件没有实现安全启动。安全启动的写命令是 INS 1C、P1=02、"
             "数据两字节 [密钥槽, 是否锁定]；同一个 1C 配 P1=01 才是写 PHY——两者靠 P1 区分，"
             "不是靠 INS。早期版本误用过 INS 1D，上游并不存在该指令。",
        "en": "Known: P1=01 is the PHY config, P1=02 is the flash info, P1=03 is the secure "
             "state. If no object in the list reports a secure state, this firmware has no "
             "secure-boot support. The secure-boot write is INS 1C with P1=02 and a two-byte "
             "body [bootkey slot, lock flag]; 1C with P1=01 is what writes the PHY — the two "
             "are told apart by P1, not by INS. An earlier build mistakenly used INS 1D, "
             "which does not exist upstream.",
    },
    "selftest_ui": {"zh": "界面通道控制", "en": "UI channel gating"},
    "selftest_failed": {
        "zh": "有 {n} 项未通过：",
        "en": "{n} check(s) failed:",
    },
    "selftest_flasher_skew": {
        "zh": "flasher.py 与本次自检版本不一致（缺少「非幂等命令不重发」保护）。"
             "请上传包内的全部文件，而不是只传其中几个——只传 selftest.py 会出现这种"
             "「同一份代码在不同环境结果不一致」的现象。",
        "en": "flasher.py does not match this self-test (the \"never resend a "
             "non-idempotent command\" guard is missing). Upload every file in "
             "the package, not just some of them — shipping selftest.py alone "
             "is what produces failures here that do not happen elsewhere.",
    },
    "hint_channel_apdu": {
        "zh": "当前是 CCID / 智能卡通道：PHY、安全启动、重启可用。WINK 与按键测试需要 FIDO HID 通道，已置灰，请回到扫描页换通道连接。",
        "en": "The CCID / smart card channel is in use: PHY, secure boot and reboot work here. WINK and the presence test need the FIDO HID channel and are greyed out — go back to the scan page and connect on that channel instead.",
    },
    "hint_channel_ctap": {
        "zh": "当前是 FIDO HID 通道：WINK 与按键测试可用。PHY、安全启动、重启需要 CCID / 智能卡通道，已置灰，请回到扫描页换通道连接。\n\n"
             "这不是本 App 的限制：上游 PicoForge 说明，7.0/7.2 固件才有走 FIDO 的老配置通道，"
             "7.4 及更高（含当前设备所用的 8.0）只能通过 rescue / PCSC 模式改硬件配置。",
        "en": "The FIDO HID channel is in use: WINK and the presence test work here. PHY, secure boot and reboot need the CCID / smart card channel and are greyed out — go back to the scan page and connect on that channel instead.\n\n"
             "This is not an app limitation: upstream PicoForge documents that only firmware 7.0/7.2 has the legacy FIDO-only configuration path, while 7.4 and later (including the 8.0 firmware) require rescue / PCSC mode for hardware configuration changes.",
    },
    "hint_secure_unsupported": {
        "zh": "上游 PicoForge 只标称支持到固件 7.6，当前设备固件为 8.0。安全启动这类命令在新固件上可能尚未开放或已变更，"
             "报 6A86/6A82 时多半是固件不接受，而不是本 App 用错了参数。",
        "en": "Upstream PicoForge only claims support up to firmware 7.6, and the device reports 8.0. Commands such as secure boot may not be exposed yet, or may have changed, on newer builds — a 6A86/6A82 usually means the firmware refuses rather than that this app sent wrong parameters.",
    },
    "err_secure_write": {
        "zh": "安全启动/安全锁没有写入成功：%s\n\n这是不可逆操作（会烧写 OTP/eFuse），请确认固件确实支持该命令后再试，不要反复重试。",
        "en": "Secure boot / secure lock was not written: %s\n\nThis is irreversible (it burns OTP/eFuse). Confirm the firmware really supports the command before trying again, and do not retry blindly.",
    },
    "hint_led_driver": {
        "zh": "必须与实际硬件匹配：板载彩灯（WS2812/NeoPixel）选 WS2812 或 NEOPIXEL，普通单色 LED 选 PICO。选错灯完全不亮 —— 彩灯需要 800kHz 精准时序，普通 GPIO 输出不了。\n\nGPIO 填真实引脚号（ESP32-S3 板载彩灯通常是 48），不是 Arduino 里 RGB_BUILTIN 的虚拟编号 97。",
        "en": "Must match the actual hardware: WS2812 or NEOPIXEL for an on-board addressable LED, PICO for a plain single-colour LED. A wrong choice means the LED stays dark entirely — addressable LEDs need precise 800 kHz timing that a plain GPIO cannot produce.\n\nEnter the real pin number (ESP32-S3 on-board LEDs are usually 48), not Arduino's virtual RGB_BUILTIN value of 97.",
    },
    "hint_up_btn": {
        "zh": "用于「用户存在」检测的物理按键 GPIO。ESP32-S3 的 BOOT 键通常接 GPIO0；多数 Pico 板出厂只有 BOOTSEL。写入后需重启才生效。\n\n重要：即便按键配置正确，注册/登录时只要用了 PIN，固件就会按规范跳过按键（pinUvAuthParam 已带 UP 标志），这是设计如此，改 PHY 也强制不了。",
        "en": "GPIO of the physical button used for user-presence checks. On ESP32-S3 the BOOT button is usually GPIO0; most Pico boards ship with only BOOTSEL. A reboot is required after writing.\n\nImportant: even with the button configured correctly, whenever a PIN is used during registration/login the firmware skips the button on purpose (the pinUvAuthParam already carries the UP flag). That is by design and no PHY change can force it.",
    },
    "btn_test_presence": {"zh": "测试用户存在（物理按键）", "en": "Test user presence (button)"},
    "msg_testing_presence": {"zh": "等待按键…（请触摸板子上的确认键）", "en": "Waiting for the button… (touch the confirm button)"},
    "msg_presence_ok": {"zh": "已确认按键（用时 %.1f 秒）", "en": "Button confirmed (took %.1f s)"},
    "msg_presence_instant": {
        "zh": "设备 %.2f 秒就返回了，没有等待按键。这个测试本身不带 PIN，按理应当等待，所以说明它认为按键已被按下 —— 多半是该 GPIO 上没有真正的按键，或电平一直被读成「已按下」。另外注意：真正注册/登录时如果用了 PIN，固件按规范会跳过按键，那是设计如此，与这里的结果无关。",
        "en": "It answered in %.2f s without waiting. This test carries no PIN, so it should have waited — the device therefore believes the button is already pressed, which usually means there is no real button on that GPIO or the level reads as pressed all the time. Separately: during real registration/login, if a PIN is used the firmware skips the button on purpose; that is by design and unrelated to this result.",
    },
    "msg_presence_failed": {"zh": "用户存在检测失败：{err}。确认板子焊了物理按键，且上面的「确认按键 GPIO」与实际接线一致。", "en": "User presence failed: {err}. Make sure a physical button is soldered and the Confirm button GPIO above matches the wiring."},
    "lbl_up": {"zh": "用户存在(UP)", "en": "User presence (UP)"},
    "up_on": {"zh": "已启用（需要按物理按键）", "en": "Enabled (a physical press is required)"},
    "up_off": {"zh": "未启用（无需按键，仅 PIN 即可）", "en": "Not enabled (no press needed, PIN alone suffices)"},
    "up_unknown": {"zh": "设备未报告 —— 请用下面的「测试用户存在」按钮实测", "en": "Not reported — measure it with the Test user presence button below"},
    "field_up_btn": {"zh": "确认按键 GPIO", "en": "Confirm button GPIO"},

    # ----------------------------------------------------------------- OPTS
    "opt_wcid": {"zh": "WCID", "en": "WCID"},
    "opt_dimm": {"zh": "呼吸灯", "en": "DIMM"},
    "opt_no_reset": {"zh": "禁电源复位", "en": "No power reset"},
    "opt_led_steady": {"zh": "LED 常亮", "en": "LED steady"},

    # ---------------------------------------------------------------- curves
    "cv_secp256r1": {"zh": "P-256", "en": "P-256"},
    "cv_secp384r1": {"zh": "P-384", "en": "P-384"},
    "cv_secp521r1": {"zh": "P-521", "en": "P-521"},
    "cv_secp256k1": {"zh": "secp256k1", "en": "secp256k1"},
    "cv_bp256r1": {"zh": "BP-256", "en": "BP-256"},
    "cv_bp384r1": {"zh": "BP-384", "en": "BP-384"},
    "cv_bp512r1": {"zh": "BP-512", "en": "BP-512"},
    "cv_ed25519": {"zh": "Ed25519", "en": "Ed25519"},
    "cv_ed448": {"zh": "Ed448", "en": "Ed448"},
    "cv_curve25519": {"zh": "X25519", "en": "X25519"},
    "cv_curve448": {"zh": "X448", "en": "X448"},
    "curves_all": {"zh": "全选", "en": "All"},
    "curves_none": {"zh": "全不选", "en": "None"},
    "curves_value": {"zh": "曲线位图：0x{v:08X}", "en": "Curve bitmap: 0x{v:08X}"},

    # ----------------------------------------------------------- secure boot
    "btn_read_secure": {"zh": "读取安全启动状态", "en": "Read secure boot status"},
    "btn_secure_boot": {"zh": "设置安全启动密钥", "en": "Set secure boot key"},
    "field_bootkey": {"zh": "启动密钥槽 (0-15)", "en": "Boot key slot (0-15)"},
    "chk_lock": {"zh": "永久锁定（不可撤销）", "en": "Lock permanently (irreversible)"},
    "lbl_secure_enabled": {"zh": "安全启动", "en": "Secure boot"},
    "lbl_secure_locked": {"zh": "已锁定", "en": "Locked"},
    "lbl_bootkey": {"zh": "启动密钥槽", "en": "Boot key slot"},
    "lbl_yes": {"zh": "是", "en": "Yes"},
    "lbl_no": {"zh": "否", "en": "No"},
    "hint_bootkey": {
        "zh": "锁定后该密钥不可再更改，请确认槽位正确。",
        "en": "Once locked the key cannot be changed. Check the slot first.",
    },

    # Irreversible-write confirmation. It used to be a log line printed after
    # the write had already happened, which is the wrong moment by definition.
    "dlg_secure_title": {"zh": "确认写入安全启动？", "en": "Confirm secure boot write?"},
    "dlg_secure_body": {
        "zh": "这会把启动密钥烧进 OTP/eFuse，无法撤销。\n\n"
             "密钥槽：{slot}\n永久锁定：{lock}\n\n"
             "! 如果勾选了永久锁定，后果不只是「只能跑签名固件」：\n"
             "上游文档明确说明，启用安全锁会同时使除官方 Pico Key 之外的所有密钥失效——"
             "此后只有官方签名的固件能被识别，无法再自行编译或刷入自定义固件。\n\n"
             "烧错槽位可能导致板子再也无法启动未签名固件。确认无误请输入 CONFIRM。",
        "en": "This burns the boot key into OTP/eFuse and cannot be undone.\n\n"
              "Key slot: {slot}\nLock permanently: {lock}\n\n"
              "! If permanent lock is ticked, the consequence is larger than "
              "\"signed firmware only\": upstream documents that enabling the "
              "secure lock also invalidates every key except the official Pico "
              "Key one. Only officially signed firmware will be recognised "
              "afterwards, and compiling or flashing custom builds will no "
              "longer be possible.\n\n"
              "Burning the wrong slot may leave the board unable to run unsigned "
              "firmware. Type CONFIRM to proceed.",
    },
    "dlg_secure_typed_hint": {"zh": "在此输入 CONFIRM", "en": "Type CONFIRM here"},
    "dlg_secure_typed_bad": {"zh": "输入不正确，请重新输入 CONFIRM", "en": "Not accepted — type CONFIRM again"},
    "dlg_secure_go": {"zh": "确认写入", "en": "Write it"},
    "btn_cancel": {"zh": "取消", "en": "Cancel"},

    # ------------------------------------------------- erase whole flash
    "fw_sec_recovery": {"zh": "恢复", "en": "Recovery"},
    "fw_erase_btn": {"zh": "整片擦除（ESP32）", "en": "Erase whole flash (ESP32)"},
    "fw_erase_note": {
        "zh": "固件起不来时，只重刷是不够的——让它起不来的那份配置仍然留在 flash 里，"
              "刷完还是同样的状态。先整片擦除才能真正清干净。\n"
              "ESP32 的 ROM 下载模式烧不掉，这一步随时可以重试。",
        "en": "When the firmware will not start, re-flashing alone is not enough: "
              "whatever stopped it booting is still in flash, so it comes back up "
              "in the same state. Erase the whole chip first to actually clear it.\n"
              "The ESP32 ROM download mode cannot be bricked, so this is always "
              "safe to retry.",
    },
    "dlg_erase_title": {"zh": "确认整片擦除？", "en": "Erase the whole flash?"},
    "dlg_erase_body": {
        "zh": "这会清空 flash 上的全部内容：固件、配置、以及所有已注册的密钥。\n\n"
              "擦除后板子将无法使用，直到重新刷入固件。\n\n"
              "建议先确认设备已进入 ROM 下载模式（拔掉，按住 BOOT 键不放再插上）。",
        "en": "This clears everything on the flash: the firmware, its configuration, "
              "and every credential stored on it.\n\n"
              "The board will not work again until firmware is flashed back onto it.\n\n"
              "Make sure the device is in ROM download mode first (unplug, hold BOOT "
              "while plugging back in).",
    },
    "dlg_erase_go": {"zh": "确认擦除", "en": "Erase it"},
    "fw_erasing": {"zh": "正在擦除整片 flash…", "en": "Erasing the whole flash…"},
    "fw_erase_done": {
        "zh": "整片擦除完成。现在可以重新刷入固件了。",
        "en": "Flash erased. The firmware can be flashed again now.",
    },

    # Shown when a board has a serial interface but the ROM never answered.
    # Without this the scan just says "nothing found", which reads as a broken
    # board when it actually means "BOOT was not held while plugging in".
    "fw_scan_not_confirmed": {
        "zh": "搜到了串口设备，但它没有回应下载握手——固件多半正在运行，"
              "不在下载模式。请拔掉，按住 BOOT 键不放再插上，然后重新扫描。",
        "en": "A serial device was found but it did not answer the download "
              "handshake - the firmware is most likely running, not in download "
              "mode. Unplug, hold BOOT while plugging back in, then scan again.",
    },

    # Shown on the scan page when the board only offers its rescue interface,
    # which is what a half-configured or crashed firmware looks like.
    "hint_rescue_only": {
        "zh": "只看到救援通道，说明固件没有正常跑起来（灯也不亮的话尤其如此）。\n"
              "这是可以救回来的：断开 USB，按住 BOOT 键不放再插上（进 ROM 下载模式），"
              "整片擦除后重新刷一次固件即可。ESP32 的 ROM 下载模式烧不掉。",
        "en": "Only the rescue channel showed up, which means the firmware is not "
              "running normally (especially if the LED is dark too).\n"
              "This is recoverable: unplug, hold BOOT while plugging back in to enter "
              "ROM download mode, erase the flash and re-flash the firmware. "
              "The ESP32 ROM download mode cannot be bricked.",
    },

    "msg_secure_reading": {"zh": "读取安全启动状态…", "en": "Reading secure boot status…"},
    "msg_secure_writing": {"zh": "写入安全启动配置…", "en": "Writing secure boot config…"},
    "msg_secure_done": {"zh": "安全启动状态：{state}", "en": "Secure boot status: {state}"},
    "msg_secure_set": {"zh": "安全启动已设置（槽 {slot}），设备将重启", "en": "Secure boot set (slot {slot}); device will reboot"},
    "msg_no_data": {"zh": "（无数据）", "en": "(no data)"},

    "err_bootkey_range": {"zh": "启动密钥槽必须在 0-15 之间", "en": "Boot key slot must be between 0 and 15"},
    "err_secure_unavailable": {
        "zh": "这块板子没有返回安全启动状态 —— 多半是固件未实现该功能，或当前接口不支持。不要硬写：OTP 熔丝烧错不可逆。",
        "en": "This board did not report a secure-boot state — the firmware most likely does not implement it, or the current interface does not support it. Do not force it: OTP fuses are irreversible.",
    },
    "err_usb_product_long": {"zh": "USB 产品名过长（最多 31 字符）", "en": "USB product name too long (31 chars max)"},

    # ------------------------------------------------------------ diagnostics
    "diag_preload_title": {"zh": "Java 类预加载", "en": "Java class preload"},
    "diag_preload_ok": {"zh": "全部就绪（可在子线程使用 USB）", "en": "All ready (USB usable from worker threads)"},
    "diag_preload_missing": {"zh": "缺失：{names}", "en": "Missing: {names}"},

    # ------------------------------------------------------------ firmware
    "btn_firmware": {"zh": "固件刷写", "en": "Flash firmware"},
    "sec_firmware": {"zh": "固件刷写", "en": "Firmware"},
    "fw_intro": {
        "zh": "给板子刷固件。RP2040/RP2350 用 UF2 文件，ESP32 走串口下载协议——两者机制完全不同，App 会根据识别结果走对应流程。",
        "en": "Flash firmware onto the board. RP2040/RP2350 take a UF2 file, ESP32 uses the serial download protocol — mechanically unrelated, and this app picks the right flow from the detected format.",
    },
    # ---- 用系统文件管理器选文件（SAF）----
    "fw_pick_hint": {
        "zh": "点下面的按钮，用手机上的文件管理器选择固件文件（.uf2 或 .bin）。",
        "en": "Tap the button below and pick the firmware file (.uf2 or .bin) with the phone's file manager.",
    },
    "fw_pick_failed": {
        "zh": "读取所选文件失败。",
        "en": "Could not read the selected file.",
    },
    "fw_pick_empty": {
        "zh": "这个文件是空的，可能不是固件。",
        "en": "That file is empty - it is probably not firmware.",
    },
    "fw_no_file_manager": {
        "zh": "没找到文件管理器，无法选择文件。",
        "en": "No file manager found, cannot pick a file.",
    },
    "fw_pick_file": {"zh": "选择固件文件", "en": "Pick firmware file"},
    "fw_no_file": {"zh": "未选择文件", "en": "No file chosen"},
    "fw_kind": {"zh": "识别结果", "en": "Detected"},
    "fw_size": {"zh": "大小", "en": "Size"},
    "fw_target": {"zh": "适用芯片", "en": "Target chip"},
    "fw_empty": {"zh": "空文件", "en": "empty file"},
    "fw_uf2": {"zh": "UF2，{n} 个块", "en": "UF2, {n} blocks"},
    "fw_esp": {"zh": "ESP 镜像，{n} 个段", "en": "ESP image, {n} segments"},
    "fw_zip": {"zh": "ZIP 压缩包，请先解压", "en": "ZIP archive - extract it first"},
    "fw_gzip": {"zh": "gzip 压缩，请先解压", "en": "gzip - decompress first"},
    "fw_html": {"zh": "这是网页不是固件，可能下载到了错误地址", "en": "this is a web page - probably the wrong URL"},
    "fw_unknown": {"zh": "无法识别的格式", "en": "unrecognised format"},
    "fw_family_rp2040": {"zh": "RP2040", "en": "RP2040"},
    "fw_family_rp2350": {"zh": "RP2350", "en": "RP2350"},
    "sec_uv": {"zh": "用户验证策略（FIDO HID）", "en": "User verification policy (FIDO HID)"},
    "uv_explain": {
        "zh": "alwaysUv 开启时，每次注册都要做用户验证，平台会用 PIN 来满足它——于是物理按键永远不参与。"
              "关掉它之后，makeCredUvNotRqd 才可能为 true，非驻留凭证可以只凭按键创建。"
              "需要设备的 PIN，并且只在 FIDO HID 通道可用。",
        "en": "With alwaysUv on, every registration needs user verification and the platform satisfies that with the PIN, so the physical button is never consulted. "
              "Turning it off is what lets makeCredUvNotRqd become true, after which a non-discoverable credential can be created on a button press alone. "
              "Needs the device PIN, and only works on the FIDO HID channel.",
    },
    "uv_state_unknown": {"zh": "尚未读取", "en": "not read yet"},
    "uv_always_uv": {"zh": "alwaysUv", "en": "alwaysUv"},
    "uv_make_cred": {"zh": "makeCredUvNotRqd", "en": "makeCredUvNotRqd"},
    "uv_client_pin": {"zh": "clientPin", "en": "clientPin"},
    "uv_on": {"zh": "开启", "en": "on"},
    "uv_off": {"zh": "关闭", "en": "off"},
    "uv_not_reported": {"zh": "未上报", "en": "not reported"},
    "uv_unsupported": {
        "zh": "此固件没有上报 authnrCfg，可能不支持 authenticatorConfig。",
        "en": "This firmware does not report authnrCfg, so authenticatorConfig may be unsupported.",
    },
    "uv_pin": {"zh": "PIN", "en": "PIN"},
    "uv_pin_hint": {"zh": "设备的 FIDO2 PIN", "en": "the device's FIDO2 PIN"},
    "uv_pin_required": {"zh": "请先填写设备的 PIN。", "en": "Enter the device PIN first."},
    "btn_toggle_always_uv": {"zh": "切换 alwaysUv（需要 PIN）", "en": "Toggle alwaysUv (needs the PIN)"},
    "btn_set_min_pin": {"zh": "设置最小 PIN 长度（不可逆）", "en": "Set the minimum PIN length (cannot be undone)"},
    "uv_working": {"zh": "正在与设备协商…", "en": "Negotiating with the device…"},
    "uv_toggled": {"zh": "alwaysUv 已切换。再点一次可切回。", "en": "alwaysUv toggled. Tap again to switch back."},
    "uv_set_min_title": {"zh": "设置最小 PIN 长度", "en": "Set the minimum PIN length"},
    "uv_set_min_body": {
        "zh": "最小 PIN 长度只能增大，不能减小。想改回去只能重置整个认证器，那会删掉全部凭证。",
        "en": "The minimum PIN length can only ever increase. Lowering it again requires a full authenticator reset, which deletes every credential.",
    },
    "uv_set_min_go": {"zh": "设置", "en": "Set"},
    "uv_set_min_hint": {"zh": "新的最小长度（4-63）", "en": "new minimum length (4-63)"},
    "uv_bad_length": {"zh": "请填一个 4 到 63 之间的数字。", "en": "Enter a number between 4 and 63."},
    "uv_min_set": {"zh": "最小 PIN 长度已设为 %d。", "en": "Minimum PIN length set to %d."},
    "fw_flash_esp": {"zh": "刷入 ESP32（会覆盖现有固件）", "en": "Flash ESP32 (overwrites current firmware)"},
    "fw_save_uf2": {"zh": "交给文件管理器保存（RP2040/RP2350）", "en": "Save via file manager (RP2040/RP2350)"},
    "fw_write_uf2": {"zh": "直接写入开发板（RP2040/RP2350）", "en": "Write straight to the board (RP2040/RP2350)"},
    "fw_write_uf2_hint": {
        "zh": "RP2040 / RP2350 在 BOOTSEL 模式下会变成一个 U 盘，正常情况下把 .uf2 拷进去即可。但手机常常挂载不了这个小盘，这条路径绕开挂载，直接通过 USB 写入，不需要储存权限。",
        "en": "An RP2040 / RP2350 in BOOTSEL mode becomes a tiny USB drive; normally the .uf2 is simply copied onto it. Phones often fail to mount that drive, so this path skips mounting entirely and writes over USB directly - no storage permission needed.",
    },
    "fw_uf2_need_uf2": {"zh": "请先选择一个 .uf2 文件。", "en": "Pick a .uf2 file first."},
    "fw_bad_uf2": {"zh": "这个文件不是有效的 UF2（每一块都必须是 512 字节且带正确的标志）。", "en": "This is not a valid UF2 (every block must be 512 bytes with the right magics)."},
    "fw_uf2_progress": {"zh": "写入 {i} / {n} 块…", "en": "Writing block {i} of {n}..."},
    "fw_uf2_copied": {"zh": "已拷贝到开发板，盘符消失即表示成功。", "en": "Copied to the board; the drive disappearing means it worked."},
    "fw_uf2_done": {"zh": "UF2 已写入，开发板会自动重启。", "en": "UF2 written; the board reboots on its own."},
    "uf2_csw_short": {"zh": "设备返回的状态包不完整（{n} 字节）。", "en": "The device returned a truncated status packet ({n} bytes)."},
    "uf2_csw_bad": {"zh": "设备返回的状态包标志不对。", "en": "The device returned a status packet with a wrong signature."},
    "uf2_csw_tag": {"zh": "状态包序号不匹配（收到 {got}，应为 {want}）。", "en": "Status packet tag mismatch (got {got}, expected {want})."},
    "uf2_not_aligned": {"zh": "数据长度不是 512 字节的整数倍。", "en": "The data is not a whole number of 512 byte blocks."},
    "uf2_write_status": {"zh": "写入被设备拒绝（状态 0x{status:02X}）。", "en": "The device refused the write (status 0x{status:02X})."},
    "uf2_mount_gone": {"zh": "开发板的盘符已经消失了。", "en": "The board's drive has already disappeared."},
    "fw_add_file": {"zh": "再添加一个文件（多文件刷写）", "en": "Add another file (multi-image flashing)"},
    "fw_clear_files": {"zh": "清空列表", "en": "Clear list"},
    "fw_guess_layout": {"zh": "按文件名自动填偏移", "en": "Fill offsets from file names"},
    "fw_flash_all": {"zh": "刷入全部 {n} 个文件", "en": "Flash all {n} files"},
    "fw_offset": {"zh": "偏移", "en": "Offset"},
    "fw_remove": {"zh": "移除", "en": "Remove"},
    "fw_multi_hint": {
        "zh": "ESP32-S3 需要三个文件写在不同位置：bootloader -> 0x0、分区表 -> 0x8000、固件 -> 0x10000。"
             "只刷固件到 0x0 会让板子把固件当 bootloader 加载，起不来、灯也不亮（灯由固件驱动）。",
        "en": "An ESP32-S3 needs three images at different offsets: bootloader at 0x0, partition table at 0x8000, firmware at 0x10000. "
             "Writing only the firmware at 0x0 makes the chip load it as a bootloader, so nothing runs and the LED stays dark (firmware drives the LED).",
    },
    "fw_multi_progress": {
        "zh": "正在写第 {i}/{n} 个文件：{p}%",
        "en": "Writing file {i}/{n}: {p}%",
    },
    "fw_no_files": {"zh": "列表是空的", "en": "The list is empty"},
    "fw_bad_offset": {
        "zh": "「{name}」的偏移「{value}」不是有效的十六进制数。",
        "en": "Offset '{value}' for '{name}' is not a valid hex number.",
    },
    "fw_duplicate_offset": {
        "zh": "有两个文件都写在 {offset:#x}，后者会覆盖前者。确认这是预期的操作吗？",
        "en": "Two files both target {offset:#x}; the later one overwrites the earlier. Is that intended?",
    },
    "fw_scan_bootloader": {"zh": "扫描处于下载模式的设备", "en": "Scan for a device in download mode"},
    # 分区标题（三个小节，替代原来散落的说明文字）
    "fw_sec_device": {"zh": "1. 选择板子", "en": "1. Pick the board"},
    "fw_sec_image": {"zh": "2. 选择固件", "en": "2. Pick the firmware"},
    "fw_sec_write": {"zh": "3. 写入", "en": "3. Write"},
    "fw_merged_image": {
        "zh": "识别为整片镜像（内含 bootloader，偏移 0x10000 处有应用程序头），应写到 0x0，不需要另外两个文件",
        "en": "Whole-flash image (contains a bootloader; an app header sits at 0x10000) - write it to 0x0, no other files needed",
    },
    "fw_erase_first": {"zh": "写入前先整片擦除", "en": "Erase whole flash before writing"},
    "fw_erase_first_hint": {
        "zh": "勾选后，刷写会先擦除整片 flash 再写入。固件起不来时只重刷是不够的——让它起不来的那份配置还留在 flash 里，刷完还是老样子。先擦才能真正清干净。擦除会清掉所有密钥。",
        "en": "When this is on, flashing erases the whole chip first. Re-flashing alone is not enough when the firmware will not start: whatever stopped it booting is still in flash, so it comes back in the same state. Erasing wipes every credential too.",
    },
    "log_file_at": {"zh": "日志同时写入文件：", "en": "Log is also written to:"},
    "fw_sec_multi": {"zh": "2b. 多个文件与偏移（ESP32）", "en": "2b. Several files and offsets (ESP32)"},
    # 不再在 UI 里讲具体手势：不同板子进下载模式的方式不同，说死会误导。
    # 只提示"让板子进入刷机模式"，具体做法看板子自己的说明。
    "fw_enter_mode_hint": {
        "zh": "让板子进入刷机模式后再点扫描。不同板子进入方式不同，请参考板子的说明。",
        "en": "Put the board into flashing mode before scanning. The gesture differs per board - check the board's documentation.",
    },
    "fw_save_hint": {
        "zh": "已打开文件管理器，把 UF2 存到板子出现的那个 U 盘里即可。",
        "en": "File manager opened - save the UF2 to the drive the board exposes.",
    },
    "fw_confirm_body": {
        "zh": "刷写会覆盖板子上的现有固件和所有已存数据。如果这是板上唯一的密钥，先确认别处有备份。确定继续吗？",
        "en": "Flashing overwrites the current firmware and everything stored on the board. If this is the only key, make sure a backup exists elsewhere. Continue?",
    },
    "fw_confirm_title": {"zh": "确认刷写？", "en": "Flash now?"},
    "fw_working": {"zh": "刷写中… {n}%", "en": "Flashing… {n}%"},
    "fw_done": {"zh": "刷写完成，请拔插板子。", "en": "Flashing finished - unplug and reconnect the board."},
    "fw_no_cdc": {"zh": "没找到串口接口", "en": "no serial interface found"},
    "fw_esp_nosync": {"zh": "bootloader 没有响应，板子在下载模式吗？", "en": "bootloader did not answer - is the board in download mode?"},
    "fw_esp_timeout": {"zh": "bootloader 超时未响应", "en": "no response from the bootloader"},
    "fw_esp_short": {"zh": "响应被截断", "en": "truncated response"},
    "fw_esp_mismatch": {"zh": "响应不匹配（收到 op {got}，期望 {want}）—— 上一条命令的应答来晚了。该命令不能重复发送，已停止，未执行第二次", "en": "unexpected response (got op {got}, wanted {want}) - an earlier reply arrived late. This command must not be sent twice, so it was not repeated"},
    "fw_esp_mismatch_stale": {
        "zh": "响应不匹配（收到 op {got}，期望 {want}）—— 已丢弃迟到的应答并继续等待，仍没等到该命令的回应。命令没有重复发送，但设备可能已在执行",
        "en": "unexpected response (got op {got}, wanted {want}) - overdue frames were dropped and no reply to this command arrived. It was not sent twice, but the board may already be running it",
    },
    "fw_esp_mismatch_retried": {"zh": "响应不匹配（收到 op {got}，期望 {want}）—— 已自动重同步一次仍失败", "en": "unexpected response (got op {got}, wanted {want}) - still wrong after one resync"},
    "fw_esp_status": {"zh": "bootloader 返回状态 {code}", "en": "bootloader returned status {code}"},
    "fw_saf_failed": {"zh": "打不开文件管理器：{err}", "en": "could not open the file manager: {err}"},
    "fw_no_bootloader": {"zh": "没找到处于下载模式的设备", "en": "no device in download mode found"},
    "fw_found_bootloader": {"zh": "找到 {kind} 设备：{name}", "en": "found {kind} device: {name}"},
    "fw_kind_uf2": {"zh": "UF2（RP2040/RP2350）", "en": "UF2 (RP2040/RP2350)"},
    "fw_kind_esp32": {"zh": "ESP32 串口下载", "en": "ESP32 serial download"},
    "fw_warn_unverified": {
        "zh": "注意：这条刷写路径没有在真机上验证过。ESP32 失败可以重来（ROM 下载模式能救），但请先看日志确认每一步。",
        "en": "Note: this flashing path has not been verified on real hardware. An ESP32 failure is recoverable (the ROM download mode can rescue it), but read the log for each step.",
    },

    # ------------------------------------------------------------ diagnostics
    "diag_inset": {"zh": "状态栏高度 {value}dp，已为顶部留出空间", "en": "status bar is {value}dp, top inset applied"},
})


def set_lang(code: str) -> str:
    global _current
    if code in LANGS:
        _current = code
    return _current


def get_lang() -> str:
    return _current


def t(key: str, default: str = None, **kwargs) -> str:
    """Translate `key` into the current language, then format it.

    `default` is used when the key is missing from STRINGS, so a module can
    carry its own English fallback instead of leaking the raw key to the user.
    """
    entry = STRINGS.get(key)
    if entry is None:
        text = default if default is not None else key
    else:
        text = entry.get(_current) or entry.get(DEFAULT_LANG) or key
    try:
        return text.format(**kwargs) if kwargs else text
    except Exception:
        return text


def lang_name(code: str) -> str:
    return LANG_NAMES.get(code, code)
