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
    "err_no_apdu": {"zh": "这个操作需要 CCID / 智能卡通道，当前连的是 FIDO HID 通道。请回到扫描页，选 CCID（智能卡）通道连接。", "en": "This needs the CCID / smart-card channel, but you are on the FIDO HID one. Go back to the scan page and pick the CCID channel."},
    "err_no_ctap": {"zh": "WINK 需要 FIDO HID 通道，当前连的是 CCID / 智能卡通道。请回到扫描页，选 FIDO HID 通道连接。", "en": "WINK needs the FIDO HID channel, but you are on the CCID one. Go back to the scan page and pick the FIDO HID channel."},
    "err_phy_read": {"zh": "读取 PHY 失败", "en": "Reading PHY failed"},
    "err_not_android": {"zh": "USB Host 只在安卓真机上可用（当前：{plat}）", "en": "USB host only works on a real Android device (current: {plat})"},
    "err_permission_denied": {
        "zh": "USB 权限被拒绝（弹窗里要点“允许”，并且只弹一次）",
        "en": "USB permission denied (tap Allow in the dialog - it is asked only once)",
    },
    "err_no_permission": {"zh": "UsbManager 仍然没有权限", "en": "UsbManager still has no permission"},
    "err_not_fido": {"zh": "这个 HID 接口不像 FIDO 设备（报告描述符里没有 usage page 0xF1D0）", "en": "This HID interface does not look like FIDO (no 0xF1D0 usage page in the report descriptor)"},
    "err_claim_failed": {"zh": "接口占用失败（多半是内核 HID 驱动占着）", "en": "Could not claim the interface (a kernel HID driver probably holds it)"},
    "err_open_device": {"zh": "打不开设备：USB 权限没给，或设备被别的 App 占用。确认弹窗点了「允许」；若之前拒过，需卸载重装 App（或到系统设置撤销 USB 权限）后重插。", "en": "Cannot open the device: USB permission denied, or another app holds it. Make sure you tapped Allow; if you denied it earlier, reinstall the app (or revoke the USB permission in system settings) and replug."},
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
    "sec_firmware": {"zh": "—— 固件与重启 ——", "en": "—— Firmware & reboot ——"},

    # ------------------------------------------------------- extra PHY fields
    "field_usb_product": {"zh": "USB 产品名", "en": "USB product"},
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

    "msg_secure_reading": {"zh": "读取安全启动状态…", "en": "Reading secure boot status…"},
    "msg_secure_writing": {"zh": "写入安全启动配置…", "en": "Writing secure boot config…"},
    "msg_secure_done": {"zh": "安全启动状态：{state}", "en": "Secure boot status: {state}"},
    "msg_secure_set": {"zh": "安全启动已设置（槽 {slot}），设备将重启", "en": "Secure boot set (slot {slot}); device will reboot"},
    "msg_no_data": {"zh": "（无数据）", "en": "(no data)"},

    "err_bootkey_range": {"zh": "启动密钥槽必须在 0-15 之间", "en": "Boot key slot must be between 0 and 15"},
    "err_secure_unavailable": {"zh": "安全启动不可用（设备未返回数据）", "en": "Secure boot unavailable (device returned no data)"},
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
        "en": "Tap the button below and pick the firmware file (.uf2 or .bin) with your phone's file manager.",
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
    "fw_flash_esp": {"zh": "刷入 ESP32（会覆盖现有固件）", "en": "Flash ESP32 (overwrites current firmware)"},
    "fw_save_uf2": {"zh": "交给文件管理器保存（RP2040/RP2350）", "en": "Save via file manager (RP2040/RP2350)"},
    "fw_scan_bootloader": {"zh": "扫描处于下载模式的设备", "en": "Scan for a device in download mode"},
    # 分区标题（三个小节，替代原来散落的说明文字）
    "fw_sec_device": {"zh": "1. 选择板子", "en": "1. Pick the board"},
    "fw_sec_image": {"zh": "2. 选择固件", "en": "2. Pick the firmware"},
    "fw_sec_write": {"zh": "3. 写入", "en": "3. Write"},
    # 不再在 UI 里讲具体手势：不同板子进下载模式的方式不同，说死会误导。
    # 只提示"让板子进入刷机模式"，具体做法看板子自己的说明。
    "fw_enter_mode_hint": {
        "zh": "让板子进入刷机模式后再点扫描。不同板子进入方式不同，请参考板子的说明。",
        "en": "Put the board into flashing mode before scanning. The gesture differs per board - check your board's documentation.",
    },
    "fw_save_hint": {
        "zh": "已打开文件管理器，把 UF2 存到板子出现的那个 U 盘里即可。",
        "en": "File manager opened - save the UF2 to the drive the board exposes.",
    },
    "fw_confirm_body": {
        "zh": "刷写会覆盖板子上的现有固件和所有已存数据。如果这是板上唯一的密钥，先确认别处有备份。确定继续吗？",
        "en": "Flashing overwrites the current firmware and everything stored on the board. If this is your only key, make sure a backup exists elsewhere. Continue?",
    },
    "fw_confirm_title": {"zh": "确认刷写？", "en": "Flash now?"},
    "fw_working": {"zh": "刷写中… {n}%", "en": "Flashing… {n}%"},
    "fw_done": {"zh": "刷写完成，请拔插板子。", "en": "Flashing finished - unplug and reconnect the board."},
    "fw_no_cdc": {"zh": "没找到串口接口", "en": "no serial interface found"},
    "fw_esp_nosync": {"zh": "bootloader 没有响应，板子在下载模式吗？", "en": "bootloader did not answer - is the board in download mode?"},
    "fw_esp_timeout": {"zh": "bootloader 超时未响应", "en": "no response from the bootloader"},
    "fw_esp_short": {"zh": "响应被截断", "en": "truncated response"},
    "fw_esp_mismatch": {"zh": "响应不匹配（收到 op {got}，期望 {want}）—— 已自动重同步一次仍失败", "en": "unexpected response (got op {got}, wanted {want}) - still wrong after one resync"},
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
