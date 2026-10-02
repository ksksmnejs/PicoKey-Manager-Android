"""
PicoKey Manager for Android - Kivy front-end.

Feature set (mirrors the desktop PicoKey App's commissioning role)
------------------------------------------------------------------
The desktop app exists because PicoKey firmware is portable but cannot know
board specifics at build time: LED wiring, GPIO mapping, board identity and
device options have to be commissioned on the target board. Almost all of that
maps onto the PHY configuration block, plus secure boot and reboot:

    board identity     VID/PID, USB product string
    LED                GPIO, brightness, driver (PICO/WS2812/...), steady flag
    GPIO mapping       LED GPIO, confirm-button (user presence) GPIO
    USB behaviour      CCID / WCID / HID / KB interfaces, WCID + DIMM options
    crypto             enabled curves bitmap (HSM)
    secure boot        boot key slot, permanent lock
    maintenance        flash usage, reboot, reboot to BOOTSEL, WINK

Not included: 1-click firmware switching. The desktop app ships the firmware
images; this project has none to bundle (and no right to redistribute them),
so loading firmware goes through "reboot to BOOTSEL" instead.

Localisation
------------
All visible text goes through picokeyapp.i18n.t(). The screen KV is a template
with @@key@@ placeholders substituted at build time, so switching language is
just a matter of rebuilding the widget tree.

The CJK font is registered before anything is drawn (see fonts.py): Kivy's
bundled Roboto has no Chinese glyphs, which is why the first release showed
tofu boxes on a phone.
"""

from __future__ import annotations

import json
import os
import re
import threading
import traceback

from kivy.app import App
from kivy.clock import Clock
from kivy.core.window import Window
from kivy.lang import Builder
from kivy.metrics import dp
from kivy.properties import (BooleanProperty, ListProperty, NumericProperty,
                             StringProperty)
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.screenmanager import Screen, ScreenManager
from kivy.uix.textinput import TextInput
from kivy.utils import platform

from picokeyapp import ctap, ctapcfg, detect, flasher, fonts, i18n, usbhost
from picokeyapp.pk import PicoKey, PhyData, PhyLedDriver, PhyOpt, PhyUsbItf

# Imported from the defining module rather than the package, because the
# package __init__ is a separate file that has to be uploaded alongside this
# one. If the two ever get out of step - a partial upload, say - importing
# from the package raises ImportError at module load, and the app dies before
# a single widget exists. That is the worst possible failure mode: a black
# screen and no way to tell why.
try:
    from picokeyapp.pk.PicoKey import SecureBootError
except ImportError:                                     # pragma: no cover
    class SecureBootError(Exception):
        """Fallback when PicoKey.py has not caught up with main.py yet."""

_PLACEHOLDER = re.compile(r"@@([a-z_0-9]+)@@")
_TOKEN = re.compile(r"\{\{([A-Z_0-9]+)\}\}")
_SETTINGS_FILE = "ui_settings.json"

# (i18n key, bit value) - must match PhyCurve in picokeyapp/pk/PhyData.py.
CURVES = [
    ("cv_secp256r1", 0x001),
    ("cv_secp384r1", 0x002),
    ("cv_secp521r1", 0x004),
    ("cv_secp256k1", 0x008),
    ("cv_bp256r1", 0x010),
    ("cv_bp384r1", 0x020),
    ("cv_bp512r1", 0x040),
    ("cv_ed25519", 0x080),
    ("cv_ed448", 0x100),
    ("cv_curve25519", 0x200),
    ("cv_curve448", 0x400),
]
ALL_CURVES = 0
for _k, _bit in CURVES:
    ALL_CURVES |= _bit

# ---------------------------------------------------------------------------
# Static rules, loaded exactly once. No translatable text lives here.
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Colour palette, applied through the KV rules below. Keeping it in one place
# means the whole app can be re-themed by editing these six values.
# ---------------------------------------------------------------------------
C_BG = (0.071, 0.086, 0.110, 1)        # window background
C_SURFACE = (0.137, 0.165, 0.204, 1)   # buttons / cards
C_PRIMARY = (0.180, 0.486, 0.965, 1)   # primary action
C_DANGER = (0.753, 0.224, 0.169, 1)    # destructive action
C_TEXT = (0.902, 0.918, 0.941, 1)
C_MUTED = (0.604, 0.647, 0.694, 1)


def _rgba(color) -> str:
    return ", ".join(f"{v:.3f}" for v in color)


# Static rules, loaded exactly once. No translatable text lives here.
# Every widget defaults to the bundled CJK font; without it Chinese labels
# render as tofu boxes because Roboto has no CJK glyphs.
KV_RULES = f"""
<Label>:
    font_name: 'AppFont'
    color: {_rgba(C_TEXT)}

<TextInput>:
    font_name: 'AppFont'
    font_size: '15sp'
    foreground_color: {_rgba(C_TEXT)}
    background_color: 0.09, 0.11, 0.14, 1
    padding: dp(10), dp(10)
    halign: 'left'

# A toggle used for the option / curve / interface switches.
<Chip@ToggleButton>:
    font_name: 'AppFont'
    font_size: '13sp'
    background_color: ({_rgba(C_SURFACE)}) if self.state == 'normal' else ({_rgba(C_PRIMARY)})
    background_normal: ''
    background_down: ''
    color: {_rgba(C_TEXT)}
    bold: (True if self.state == 'down' else False)

# Buttons size themselves to their own text.
#
# A Button with the default text_size=None never wraps, so a long label
# (English strings are noticeably longer than the Chinese ones) is drawn on a
# single line and clipped by the fixed dp(52) height - the classic "button and
# text do not match" look. Binding text_size to the width makes the label wrap,
# and binding height to texture_size lets the button grow to fit the wrapped
# text instead of cutting it off.
<MenuButton@Button>:
    font_name: 'AppFont'
    size_hint_y: None
    height: max(dp(52), self.texture_size[1] + dp(24))
    font_size: '16sp'
    # max() guards the first layout pass, where width can still be ~0 and
    # width - 24 would be a negative text_size.
    text_size: max(dp(1), self.width - dp(24)), None
    halign: 'center'
    valign: 'center'
    background_color: {_rgba(C_SURFACE)}
    background_normal: ''
    background_down: ''
    color: {_rgba(C_TEXT)}
    # Disabled while a USB operation is running: without this, tapping twice
    # queues a second transfer on a transport that is already mid-exchange.
    disabled: app.busy
    opacity: 0.45 if self.disabled else 1

<PrimaryButton@MenuButton>:
    background_color: {_rgba(C_PRIMARY)}
    bold: True

<DangerButton@MenuButton>:
    background_color: {_rgba(C_DANGER)}
    bold: True

<SectionLabel@Label>:
    font_name: 'AppFont'
    size_hint_y: None
    height: dp(34)
    font_size: '15sp'
    bold: True
    halign: 'left'
    text_size: self.size
    color: 0.55, 0.78, 1, 1

# Wrapping body text. Every Label that holds more than a couple of words needs
# BOTH text_size (so it wraps) and a height driven by texture_size (so it is
# not clipped) - setting one without the other is what makes text overlap or
# get cut off.
<InfoLabel@Label>:
    font_name: 'AppFont'
    size_hint_y: None
    height: self.texture_size[1] + dp(6)
    text_size: self.width, None
    font_size: '13sp'
    halign: 'left'
    valign: 'top'
    color: 0.7, 0.75, 0.8, 1

<FieldLabel@Label>:
    font_name: 'AppFont'
    size_hint_x: 0.42
    halign: 'left'
    valign: 'center'
    text_size: self.size
    font_size: '14sp'
    color: {_rgba(C_MUTED)}

<Row@BoxLayout>:
    size_hint_y: None
    height: dp(44)
    spacing: dp(6)
"""

# ---------------------------------------------------------------------------
# Screens. @@key@@ placeholders are replaced by _kv() with the current
# language's string; {{TOKEN}} blocks are generated programmatically.
# ---------------------------------------------------------------------------
# The screen manager skeleton. Loaded once and never rebuilt - it owns no
# translatable text, so it does not need to be.
KV_ROOT = """
ScreenManager:
    id: sm
    ScanScreen:
        name: 'scan'
    DeviceScreen:
        name: 'device'
    LogScreen:
        name: 'log'
    FirmwareScreen:
        name: 'firmware'
"""

# Firmware page. Kept separate from the device page on purpose: flashing talks
# to the board in bootloader mode, which is a different USB personality from
# the running firmware, so mixing the two flows would mean connecting twice.
KV_FIRMWARE = """
BoxLayout:
    orientation: 'vertical'
    canvas.before:
        Color:
            rgba: 0.071, 0.086, 0.110, 1.000
        Rectangle:
            pos: self.pos
            size: self.size
    # Top padding is dp(12) PLUS the Android status-bar height. Kivy lays out
    # from y=0 of the window, so without this inset the title row sits under
    # the clock/notch icons on any modern phone.
    padding: [dp(12), dp(12) + app.top_inset, dp(12), dp(12)]
    spacing: dp(8)
    Label:
        text: '@@sec_firmware@@'
        font_size: '20sp'
        bold: True
        size_hint_y: None
        height: dp(36)
    ScrollView:
        GridLayout:
            cols: 1
            size_hint_y: None
            height: self.minimum_height
            spacing: dp(8)
            padding: 0, dp(4)
            InfoLabel:
                text: '@@fw_intro@@'
                font_size: '14sp'
            InfoLabel:
                text: '@@fw_warn_unverified@@'
                color: 1, 0.72, 0.42, 1

            SectionLabel:
                text: '@@fw_sec_device@@'
            InfoLabel:
                text: '@@fw_enter_mode_hint@@'
            MenuButton:
                text: '@@fw_scan_bootloader@@'
                on_release: app.fw_scan()
            InfoLabel:
                id: fw_dev
                text: app.fw_dev_text
                font_size: '14sp'

            SectionLabel:
                text: '@@fw_sec_image@@'
            InfoLabel:
                text: '@@fw_pick_hint@@'
            MenuButton:
                text: '@@fw_pick_file@@'
                on_release: app.fw_pick()
            InfoLabel:
                id: fw_info
                text: app.fw_info_text
                font_size: '14sp'

            SectionLabel:
                text: '@@fw_sec_multi@@'
            InfoLabel:
                text: '@@fw_multi_hint@@'
                font_size: '13sp'
            GridLayout:
                id: fw_files
                cols: 1
                size_hint_y: None
                height: self.minimum_height
                spacing: dp(6)
            BoxLayout:
                size_hint_y: None
                height: dp(48)
                spacing: dp(6)
                MenuButton:
                    text: '@@fw_add_file@@'
                    on_release: app.fw_pick()
                MenuButton:
                    text: '@@fw_guess_layout@@'
                    on_release: app.fw_guess_offsets()
            BoxLayout:
                size_hint_y: None
                height: dp(48)
                spacing: dp(6)
                MenuButton:
                    text: '@@fw_clear_files@@'
                    on_release: app.fw_clear_files()

            SectionLabel:
                text: '@@fw_sec_write@@'
            DangerButton:
                id: btn_flash_all
                text: '@@fw_flash_esp@@'
                on_release: app.fw_flash()
            MenuButton:
                text: '@@fw_save_uf2@@'
                on_release: app.fw_save_uf2()

            SectionLabel:
                text: '@@fw_sec_recovery@@'
            InfoLabel:
                text: '@@fw_erase_note@@'
                color: 1, 0.72, 0.42, 1
            DangerButton:
                text: '@@fw_erase_btn@@'
                on_release: app.fw_erase()

            MenuButton:
                text: '@@btn_back_scan@@'
                on_release: app.go('scan')
"""

# Screen bodies. Each one is an ANONYMOUS root widget, deliberately: a rule
# like `<ScanScreen>:` is registered against the class, and re-loading it does
# not replace the old rule - it ADDS another one, so every language switch
# piled another full set of widgets onto the screen (3 buttons, then 6, then
# 9...). An anonymous root produces an instance and no class rule, so nothing
# can accumulate. (Builder.unload_string does not reliably undo class rules.)
KV_SCAN = """
BoxLayout:
    orientation: 'vertical'
    canvas.before:
        Color:
            rgba: 0.071, 0.086, 0.110, 1.000
        Rectangle:
            pos: self.pos
            size: self.size
    # Top padding is dp(12) PLUS the Android status-bar height. Kivy lays out
    # from y=0 of the window, so without this inset the title row sits under
    # the clock/notch icons on any modern phone.
    padding: [dp(12), dp(12) + app.top_inset, dp(12), dp(12)]
    spacing: dp(10)
    BoxLayout:
        size_hint_y: None
        height: dp(44)
        spacing: dp(6)
        Label:
            text: '@@language@@'
            size_hint_x: 0.32
            halign: 'left'
            text_size: self.size
            font_size: '15sp'
        Spinner:
            id: lang_spinner
            values: app.lang_values
            text: app.lang_current
            font_name: 'AppFont'
            font_size: '15sp'
            on_text: app.on_lang_change(self.text)
    Label:
        text: '@@app_title@@'
        font_size: '22sp'
        bold: True
        size_hint_y: None
        height: dp(40)
    Label:
        # Height follows the text instead of being a fixed dp(60). Some strings
        # here are long - the "found a serial device but it did not answer the
        # handshake" hint, for one - and a fixed height clipped them, so the
        # wrapped remainder was drawn straight over the scan button below.
        id: status
        text: app.status_text
        size_hint_y: None
        height: max(dp(60), self.texture_size[1] + dp(10))
        text_size: self.width, None
        halign: 'left'
        valign: 'top'
        shorten: False
        font_size: '14sp'
        color: 0.7, 0.75, 0.8, 1
    PrimaryButton:
        text: '@@btn_scan@@'
        on_release: app.scan()
    ScrollView:
        GridLayout:
            id: list_box
            cols: 1
            size_hint_y: None
            height: self.minimum_height
            spacing: dp(6)
    MenuButton:
        text: '@@btn_selftest@@'
        on_release: app.selftest()
    MenuButton:
        text: '@@btn_firmware@@'
        on_release: app.go('firmware')
    MenuButton:
        text: '@@btn_logs@@'
        on_release: app.go('log')
"""

KV_DEVICE = """
BoxLayout:
    orientation: 'vertical'
    canvas.before:
        Color:
            rgba: 0.071, 0.086, 0.110, 1.000
        Rectangle:
            pos: self.pos
            size: self.size
    # Top padding is dp(12) PLUS the Android status-bar height. Kivy lays out
    # from y=0 of the window, so without this inset the title row sits under
    # the clock/notch icons on any modern phone.
    padding: [dp(12), dp(12) + app.top_inset, dp(12), dp(12)]
    spacing: dp(6)
    Label:
        # Same story as the scan-page status: the device summary grows with the
        # number of lines the firmware reports, and dp(150) cut it off.
        id: info
        text: app.device_text
        size_hint_y: None
        height: max(dp(120), self.texture_size[1] + dp(10))
        text_size: self.width, None
        font_size: '15sp'
        halign: 'left'
        valign: 'top'
    InfoLabel:
        text: app.channel_hint
    ScrollView:
        GridLayout:
            cols: 1
            size_hint_y: None
            height: self.minimum_height
            spacing: dp(6)
            padding: 0, dp(6)

            MenuButton:
                id: btn_refresh
                text: '@@btn_refresh@@'
                disabled: app.busy or app.blocked_apdu
                on_release: app.refresh()
            PrimaryButton:
                id: btn_read_phy
                text: '@@btn_read_phy@@'
                disabled: app.busy or app.blocked_apdu
                on_release: app.read_phy()

            SectionLabel:
                text: '@@sec_phy@@'
            Row:
                FieldLabel:
                    text: '@@field_vid@@'
                TextInput:
                    id: vid
                    multiline: False
                    input_filter: 'int'
            Row:
                FieldLabel:
                    text: '@@field_pid@@'
                TextInput:
                    id: pid
                    multiline: False
                    input_filter: 'int'
            Row:
                FieldLabel:
                    text: '@@field_usb_product@@'
                TextInput:
                    id: usb_product
                    multiline: False
            Row:
                FieldLabel:
                    text: '@@field_led_gpio@@'
                TextInput:
                    id: led_gpio
                    multiline: False
                    input_filter: 'int'
            Row:
                FieldLabel:
                    text: '@@field_led_btness@@'
                TextInput:
                    id: led_btness
                    multiline: False
                    input_filter: 'int'
            Row:
                FieldLabel:
                    text: '@@field_led_driver@@'
                Spinner:
                    id: led_driver
                    values: ['PICO', 'PIMORONI', 'WS2812', 'CYW43', 'NEOPIXEL', 'NONE']
                    text: 'PICO'
                    font_name: 'AppFont'
                    font_size: '15sp'
            InfoLabel:
                text: '@@hint_led_driver@@'
            Row:
                FieldLabel:
                    text: '@@field_up_btn@@'
                TextInput:
                    id: up_btn
                    multiline: False
                    input_filter: 'int'
            InfoLabel:
                text: '@@hint_up_btn@@'

            SectionLabel:
                text: '@@sec_opts@@'
            GridLayout:
                cols: 2
                size_hint_y: None
                height: dp(88)
                Chip:
                    id: opt_wcid
                    text: '@@opt_wcid@@'
                Chip:
                    id: opt_dimm
                    text: '@@opt_dimm@@'
                Chip:
                    id: opt_no_reset
                    text: '@@opt_no_reset@@'
                Chip:
                    id: opt_led_steady
                    text: '@@opt_led_steady@@'

            SectionLabel:
                text: '@@sec_curves@@'
            {{CURVE_GRID}}
            BoxLayout:
                size_hint_y: None
                height: dp(40)
                spacing: dp(6)
                Button:
                    font_name: 'AppFont'
                    text: '@@curves_all@@'
                    on_release: app.curves_all()
                Button:
                    font_name: 'AppFont'
                    text: '@@curves_none@@'
                    on_release: app.curves_none()
            Label:
                id: curves_value
                text: app.curves_text
                size_hint_y: None
                height: max(dp(26), self.texture_size[1] + dp(8))
                font_size: '13sp'
                halign: 'left'
                valign: 'top'
                text_size: self.width, None
                color: 0.7, 0.75, 0.8, 1

            GridLayout:
                cols: 4
                size_hint_y: None
                height: dp(44)
                Chip:
                    id: itf_ccid
                    text: 'CCID'
                    state: 'down'
                Chip:
                    id: itf_wcid
                    text: 'WCID'
                    state: 'down'
                Chip:
                    id: itf_hid
                    text: 'HID'
                    state: 'down'
                Chip:
                    id: itf_kb
                    text: 'KB'

            DangerButton:
                id: btn_write_phy
                text: '@@btn_write_phy@@'
                disabled: app.busy or app.blocked_apdu
                on_release: app.write_phy()

            SectionLabel:
                text: '@@sec_security@@'
            Label:
                id: sec_status
                text: app.secure_text
                size_hint_y: None
                height: max(dp(28), self.texture_size[1] + dp(8))
                font_size: '14sp'
                halign: 'left'
                valign: 'top'
                text_size: self.width, None
                color: 0.8, 0.85, 0.9, 1
            PrimaryButton:
                id: btn_read_secure
                text: '@@btn_read_secure@@'
                disabled: app.busy or app.blocked_apdu
                on_release: app.read_secure()
            MenuButton:
                id: btn_probe_secure
                text: '@@btn_probe_secure@@'
                disabled: app.busy or app.blocked_apdu
                on_release: app.probe_secure()
            Row:
                FieldLabel:
                    text: '@@field_bootkey@@'
                TextInput:
                    id: bootkey
                    multiline: False
                    input_filter: 'int'
                    text: '0'
            Chip:
                id: chk_lock
                size_hint_y: None
                height: dp(40)
                text: '@@chk_lock@@'
            DangerButton:
                id: btn_secure_boot
                text: '@@btn_secure_boot@@'
                disabled: app.busy or app.blocked_apdu
                on_release: app.set_secure_boot()

            SectionLabel:
                text: '@@sec_firmware@@'
            MenuButton:
                id: btn_wink
                text: '@@btn_wink@@'
                disabled: app.busy or app.blocked_ctap
                on_release: app.wink()
            MenuButton:
                id: btn_test_presence
                text: '@@btn_test_presence@@'
                disabled: app.busy or app.blocked_ctap
                on_release: app.test_presence()

            SectionLabel:
                text: '@@sec_uv@@'
            InfoLabel:
                text: '@@uv_explain@@'
                font_size: '13sp'
            InfoLabel:
                id: lbl_uv_state
                text: app.uv_state_text
                font_size: '13sp'
            BoxLayout:
                size_hint_y: None
                height: dp(44)
                spacing: dp(6)
                Label:
                    text: '@@uv_pin@@'
                    size_hint_x: 0.3
                    font_size: '13sp'
                    halign: 'left'
                    valign: 'middle'
                    text_size: self.size
                TextInput:
                    id: inp_pin
                    size_hint_x: 0.7
                    font_size: '14sp'
                    multiline: False
                    password: True
                    hint_text: '@@uv_pin_hint@@'
            DangerButton:
                id: btn_toggle_always_uv
                text: '@@btn_toggle_always_uv@@'
                disabled: app.busy or app.blocked_ctap
                on_release: app.toggle_always_uv()
            DangerButton:
                id: btn_set_min_pin
                text: '@@btn_set_min_pin@@'
                disabled: app.busy or app.blocked_ctap
                on_release: app.ask_set_min_pin()
            MenuButton:
                id: btn_reboot
                text: '@@btn_reboot@@'
                disabled: app.busy or app.blocked_apdu
                on_release: app.reboot(False)
            MenuButton:
                id: btn_reboot_bootsel
                text: '@@btn_reboot_bootsel@@'
                disabled: app.busy or app.blocked_apdu
                on_release: app.reboot(True)
            MenuButton:
                text: '@@btn_disconnect@@'
                on_release: app.disconnect()
            MenuButton:
                text: '@@btn_back_scan@@'
                on_release: app.go('scan')
            MenuButton:
                text: '@@btn_logs@@'
                on_release: app.go('log')
"""

KV_LOG = """
BoxLayout:
    orientation: 'vertical'
    canvas.before:
        Color:
            rgba: 0.071, 0.086, 0.110, 1.000
        Rectangle:
            pos: self.pos
            size: self.size
    # Top padding is dp(12) PLUS the Android status-bar height. Kivy lays out
    # from y=0 of the window, so without this inset the title row sits under
    # the clock/notch icons on any modern phone.
    padding: [dp(12), dp(12) + app.top_inset, dp(12), dp(12)]
    spacing: dp(8)
    Label:
        text: '@@log_title@@'
        font_size: '20sp'
        size_hint_y: None
        height: dp(36)
    ScrollView:
        Label:
            id: logview
            # An empty log and a broken log look identical otherwise: both are
            # just a black rectangle. Say which one it is.
            text: app.log_text if app.log_text else '@@log_empty@@'
            size_hint_y: None
            height: max(self.texture_size[1], dp(400))
            text_size: self.width, None
            font_size: '12sp'
            halign: 'left'
            valign: 'top'
            color: 0.8, 0.85, 0.9, 1
    MenuButton:
        text: '@@btn_clear@@'
        on_release: app.clear_log()
    MenuButton:
        text: '@@btn_back@@'
        on_release: app.go('device' if app.connected else 'scan')
"""


class UserError(Exception):
    """An expected, explainable failure - wrong channel, missing permission.

    These carry the advice the user needs in their own message. Printing a
    stack trace under them just buries that advice under several screens of
    frames that are identical every time.
    """


# Failures whose message already says what to do. Printing a traceback under
# them costs screen space and buys nothing, so _fail() skips it for these.
QUIET_ERRORS = (
    UserError,
    ctapcfg.ConfigError,
    SecureBootError,
    flasher.FirmwareError,
    ctap.CTAPError,
    ValueError,          # bad numeric input in a field
)


class ScanScreen(Screen):
    pass


class DeviceScreen(Screen):
    pass


class LogScreen(Screen):
    pass


class FirmwareScreen(Screen):
    pass


def _kv_escape(text: str) -> str:
    """Make a translated string safe inside a KV single-quoted literal."""
    return text.replace("\\", "\\\\").replace("'", "\\'").replace("\n", "\\n")


def _curve_grid_kv() -> str:
    """Generate the curve toggles; 11 entries are painful to keep by hand.

    Indentation here is relative; _kv() re-indents everything but the first
    line to the column where the {{CURVE_GRID}} placeholder actually sits, so
    this function does not need to know the template's own indentation.
    """
    rows, per_row = [], 3
    # Relative indentation only. _kv() re-indents everything but the first line
    # to the column where the {{CURVE_GRID}} placeholder actually sits, which
    # keeps this function independent of the template's own indentation.
    BODY = " " * 4
    for i in range(0, len(CURVES), per_row):
        chunk = CURVES[i:i + per_row]
        rows.append("GridLayout:\n")
        rows.append(BODY + "cols: %d\n" % per_row)
        rows.append(BODY + "size_hint_y: None\n")
        rows.append(BODY + "height: dp(40)\n")
        for j, (key, _bit) in enumerate(chunk):
            rows.append(BODY + "Chip:\n")
            rows.append(BODY + "    id: cv%d\n" % (i + j))
            rows.append(BODY + "    text: '@@%s@@'\n" % key)
            rows.append(BODY + "    on_release: app.curves_changed()\n")
    return "".join(rows)


class PicoKeyApp(App):
    status_text = StringProperty("")
    device_text = StringProperty("")
    log_text = StringProperty("")
    secure_text = StringProperty("")
    curves_text = StringProperty("")
    # Extra top inset (Kivy dp) so content clears the Android status bar.
    # 0 on desktop; set from the framework dimension at build time.
    top_inset = NumericProperty(0)
    lang_values = ListProperty([i18n.LANG_NAMES[c] for c in i18n.LANGS])
    lang_current = StringProperty(i18n.LANG_NAMES[i18n.DEFAULT_LANG])
    # Bound to `disabled:` in the MenuButton rule - greys the buttons out while
    # a USB operation is in flight, which stops double taps from queueing a
    # second transfer on a transport that is already mid-exchange.
    busy = BooleanProperty(False)
    # A device exposes CCID and FIDO HID as two separate channels, and each
    # command only works on one of them. Greying out the buttons that need the
    # channel you are not on is worth more than any error message: the failure
    # only ever surfaced as "needs CCID, you are on HID" *after* the tap, with
    # a stack trace behind it, and people read that as a crash.
    blocked_apdu = BooleanProperty(False)
    blocked_ctap = BooleanProperty(False)
    channel_hint = StringProperty("")
    uv_state_text = StringProperty("")
    connected = False

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.title = i18n.t("app_title")
        self.kind = None               # 'apdu' | 'ctap'
        self.transport = None
        self.pk = None
        self.channel = None
        self._channels = []
        self._switching_lang = False
        self._rules_loaded = False
        # structured device data, so the info block can be re-rendered when the
        # language changes without talking to the device again
        self._dev = None
        self._secure = None
        self._phy = None
        # firmware page state
        self._fw_data = None
        self._fw_dev = None
        self._fw_kind = None
        # Multi-image flashing: a list of {"name", "data", "offset"} dicts.
        # Empty means the plain single-file path, which stays the default.
        self._fw_files = []
        # authenticatorGetInfo of the current CTAP connection, kept so the UV
        # section can show alwaysUv without another round trip to the device.
        self._ctap_info = None
        # Log lines are buffered here and flushed on the main thread; see log().
        self._log_lock = threading.Lock()
        self._log_pending = []

    # ------------------------------------------------------------ plumbing

    def build(self):
        """Never let a startup failure be a silent exit.

        An exception raised here - a KV parse error, a missing translation, a
        half-finished upload - used to kill the process before any window
        existed. On a phone that is indistinguishable from a crash on launch,
        and there is nothing to go on: no dialog, no log, no way to tell what
        broke. Showing the traceback on screen instead turns "it just closes"
        into something that can actually be reported and fixed.
        """
        try:
            return self._build_impl()
        except Exception:
            return self._crash_screen(traceback.format_exc())

    @staticmethod
    def _crash_screen(detail: str):
        """A plain error screen, built without touching the app's own KV."""
        from kivy.uix.boxlayout import BoxLayout
        from kivy.uix.label import Label
        from kivy.uix.scrollview import ScrollView

        root = BoxLayout(orientation="vertical", padding=[12, 24, 12, 12])
        root.add_widget(Label(
            text="启动失败 / Startup failed", size_hint_y=None, height=40,
            font_size="18sp", bold=True, color=(1, 0.4, 0.35, 1)))
        scroll = ScrollView()
        body = Label(text=detail, font_size="11sp",
                     size_hint_y=None, halign="left", valign="top",
                     color=(0.9, 0.9, 0.9, 1))
        body.bind(texture_size=lambda _w, size: setattr(
            body, "height", max(size[1], 1)))
        body.text_size = (None, None)
        scroll.add_widget(body)
        root.add_widget(scroll)
        return root

    def _build_impl(self):
        # Must happen before any widget exists, otherwise the first labels are
        # laid out with Roboto and never re-measure.
        if not fonts.register():
            self._font_warning = True

        # pyjnius can only resolve Java classes from the thread that has the
        # Android class loader attached. Doing it here (UI thread) caches them,
        # which is what lets the USB code run from worker threads later.
        if platform == "android":
            # Status-bar inset must be read before the screens are built,
            # otherwise the first layout pass uses 0 and the title row is
            # drawn under the notch until something forces a re-layout.
            self.top_inset = usbhost.status_bar_height_dp()
            if self.top_inset:
                self.log(i18n.t("diag_inset", value=int(self.top_inset)))
            missing = usbhost.preload_java_classes()
            self.log(i18n.t("diag_preload_title") + ": "
                     + (i18n.t("diag_preload_ok") if not missing
                        else i18n.t("diag_preload_missing", names=", ".join(missing))))

        self._load_language()
        self.status_text = i18n.t("scan_intro")
        self.device_text = i18n.t("not_connected")
        root = self._build_root()
        self._fill_screens(root)
        return root

    def _kv(self, template: str) -> str:
        """Fill in the @@key@@ and {{TOKEN}} holes of one screen template."""
        def rep(match):
            return _kv_escape(i18n.t(match.group(1)))

        kv = _TOKEN.sub(self._expand_token(template), template)
        return _PLACEHOLDER.sub(rep, kv)

    @staticmethod
    def _expand_token(template):
        """Return the replacement for a {{TOKEN}} placeholder.

        The placeholder already carries the template's leading whitespace, but
        that only reaches the first generated line - the rest would land at
        column 0 and break the parser. So every line after the first gets the
        placeholder's own indent added back.
        """
        def replace(match):
            name = match.group(1)
            if name != "CURVE_GRID":
                return ""
            # indentation of the line the placeholder sits on
            head = template[:match.start()]
            indent = head[head.rfind("\n") + 1:] if "\n" in head else head
            if indent.strip():
                indent = ""
            text = _curve_grid_kv()
            lines = text.split("\n")
            out = [lines[0]]
            for line in lines[1:]:
                out.append(indent + line if line.strip() else line)
            return "\n".join(out)

        return replace

    def _build_root(self):
        """Create the screen manager. Called once, at startup."""
        if not self._rules_loaded:
            Builder.load_string(KV_RULES)
            self._rules_loaded = True
        return Builder.load_string(KV_ROOT)

    def _fill_screens(self, root=None):
        """(Re)build the contents of all three screens in the current language.

        `root` is explicit because build() runs before App.root is assigned.

        Each body is an anonymous widget, so this can be called as often as
        needed without accumulating class rules. The old content is removed
        first - the widgets are simply dropped, no Builder state involved.
        """
        root = root if root is not None else self.root
        for name, template in (("scan", KV_SCAN), ("device", KV_DEVICE),
                               ("log", KV_LOG), ("firmware", KV_FIRMWARE)):
            screen = root.get_screen(name)
            old = getattr(screen, "content", None)
            if old is not None:
                screen.remove_widget(old)
            content = Builder.load_string(self._kv(template))
            screen.content = content          # keeps .ids reachable, see ids_of()
            screen.add_widget(content)

    # ----------------------------------------------------------- language

    def _settings_path(self) -> str:
        try:
            folder = self.user_data_dir
            os.makedirs(folder, exist_ok=True)
            return os.path.join(folder, _SETTINGS_FILE)
        except Exception:
            return _SETTINGS_FILE

    def _load_language(self):
        try:
            with open(self._settings_path(), "r", encoding="utf-8") as fh:
                code = json.load(fh).get("language")
            if code in i18n.LANGS:
                i18n.set_lang(code)
        except Exception:
            pass
        self.lang_current = i18n.LANG_NAMES[i18n.get_lang()]
        self.lang_values = [i18n.LANG_NAMES[c] for c in i18n.LANGS]

    def _save_language(self, code: str):
        try:
            with open(self._settings_path(), "w", encoding="utf-8") as fh:
                json.dump({"language": code}, fh)
        except Exception:
            pass

    def on_lang_change(self, display_name: str):
        if self._switching_lang:
            return
        code = None
        for candidate, name in i18n.LANG_NAMES.items():
            if name == display_name:
                code = candidate
                break
        if code is None or code == i18n.get_lang():
            return
        self.set_language(code)

    def ids_of(self, screen_name: str):
        """ids of a screen body.

        They live on the content widget, not on the Screen itself, because the
        body is built as an anonymous root.
        """
        screen = self.root.get_screen(screen_name)
        return getattr(screen, "content", screen).ids

    def set_language(self, code: str):
        """Switch language and rebuild the UI with the new strings."""
        i18n.set_lang(code)
        self._save_language(code)
        self.lang_current = i18n.LANG_NAMES[code]
        self.title = i18n.t("app_title")

        if self._dev is None:
            self.status_text = i18n.t("scan_intro")
        else:
            self.status_text = i18n.t("connected")
        self._render_device_text()
        self._render_secure_text()
        self._render_curves_text()

        # No need to touch the Window at all: the screen manager stays put and
        # only the three bodies are rebuilt, so every binding keeps working and
        # the buttons stay tappable.
        self._switching_lang = True
        try:
            self._fill_screens()
        finally:
            self._switching_lang = False

        # The scan list and the PHY inputs are built imperatively, so they have
        # to be repopulated on the freshly built bodies.
        if self._channels:
            self._render_channel_list(self._channels)
        self._fill_phy_fields()
        self.log(f"[i18n] language -> {code}")

    # --------------------------------------------------------------- log

    def log(self, msg: str):
        """Append one line to the log, from any thread.

        Half the log calls happen inside `_worker`'s `fn()`, which runs on a
        background thread. `log_text` is a Kivy StringProperty bound to a
        Label, so assigning to it from there drives texture creation off the
        main thread - and Kivy's GL context is only valid on the main one.
        The damage does not show up as a crash: the log area just stops
        painting and renders as a black rectangle, which is exactly what
        "the log disappeared" looks like.

        So the text is queued here and appended from the main thread, the same
        way the keepalive callback already does it.
        """
        with self._log_lock:
            self._log_pending.append(str(msg))
        Clock.schedule_once(self._flush_log)

    def _flush_log(self, _dt):
        with self._log_lock:
            if not self._log_pending:
                return
            lines = self._log_pending
            self._log_pending = []
        self.log_text += "".join(line + "\n" for line in lines)
        if len(self.log_text) > 20000:
            self.log_text = self.log_text[-20000:]

    def clear_log(self):
        self.log_text = ""

    def go(self, name: str):
        self.root.current = name

    # ------------------------------------------------------------ firmware

    fw_dev_text = StringProperty("")
    fw_info_text = StringProperty("")

    def _fw_reset(self):
        self._fw_data = None
        self._fw_kind = None
        self._fw_files = []
        self._render_fw_files()
        self.fw_info_text = i18n.t("fw_no_file")

    def fw_scan(self):
        """Look for a board sitting in bootloader mode.

        An ESP32-S3 exposes a CDC interface whether or not its firmware is
        running, so "has a serial interface" is not evidence of download mode.
        The ESP candidate is therefore confirmed by a real ROM handshake before
        it is offered - otherwise the app cheerfully reports a healthy board as
        ready to flash and then fails (or worse, appears to succeed) later.
        """
        def work():
            # Everything that touches the Java USB objects happens HERE, in
            # the worker thread. Only plain strings cross back to the UI, so
            # the Clock callback never has to touch a Java object.
            devices = usbhost.enumerate_devices()
            found = []
            for dev in devices:
                kind = flasher.classify_bootloader(dev)
                if not kind:
                    continue
                try:
                    name = dev.label()
                except Exception:
                    name = f"USB {dev.vid:04X}:{dev.pid:04X}"
                # UF2 boards are a mass-storage drive: seeing the drive *is*
                # the confirmation. ESP boards need the handshake.
                confirmed = True
                if kind == "esp32":
                    confirmed = flasher.verify_download_mode(dev)
                    if not confirmed:
                        self.log(f"fw_scan: {name} has a serial interface but "
                                 f"the ROM did not answer (firmware probably "
                                 f"running, not in download mode)")
                found.append((kind, dev, name, confirmed))
            return found

        def ok(found):
            self.busy = False
            self._fw_dev = None
            confirmed = [f for f in found if f[3]]
            if not confirmed:
                self.fw_dev_text = i18n.t("fw_no_bootloader")
                self.log("fw_scan: nothing in bootloader mode")
                if found:
                    self.status_text = i18n.t("fw_scan_not_confirmed")
                return
            kind, dev, name, _ = confirmed[0]
            self._fw_dev = dev
            label = i18n.t("fw_kind_uf2") if kind == "uf2" else i18n.t("fw_kind_esp32")
            self.fw_dev_text = i18n.t("fw_found_bootloader", kind=label, name=name)
            self.log(f"fw_scan: {kind} -> {name} (handshake ok)")

        self._worker(work, on_ok=ok, busy_text=i18n.t("scanning"))

    def fw_pick(self):
        """Pick a firmware file with the system file manager.

        On Android this goes through SAF; Kivy's own FileChooser is not used
        because scoped storage hides most of the phone from it.
        """
        from picokeyapp import saf

        if not saf.is_available():
            # Desktop / test environment: fall back to Kivy's chooser.
            self._fw_pick_fallback()
            return

        def on_result(uri):
            if uri is None:
                # Cancelled - not an error, say nothing.
                return
            try:
                data = saf.read_uri(uri)
            except Exception as exc:
                # Show the reason, not just "failed": without it a bad Uri and
                # a missing provider look identical and there is nothing to act on.
                detail = f"{type(exc).__name__}: {exc}"
                self.log(f"fw_pick: {detail}")
                self.fw_info_text = i18n.t("fw_pick_failed") + "\n" + detail
                return
            if not data:
                self.fw_info_text = i18n.t("fw_pick_empty")
                return
            name = saf.display_name(uri)
            if name:
                self.log(f"fw_pick: {name} ({len(data)} bytes)")
            self._fw_accept(data, name=name or "")

        try:
            saf.open_picker(on_result)
        except saf.SafUnavailable as exc:
            self.log(f"fw_pick: SAF unavailable ({exc})")
            self.fw_info_text = i18n.t("fw_no_file_manager")
        except Exception as exc:
            self.log(f"fw_pick: {exc}")
            self.fw_info_text = i18n.t("fw_pick_failed")

    def _fw_pick_fallback(self):
        """Kivy FileChooser, for desktop runs where SAF does not exist."""
        from kivy.uix.filechooser import FileChooserListView
        from kivy.uix.popup import Popup

        chooser = FileChooserListView(path=".")

        def _picked(_):
            if not chooser.selection:
                return
            try:
                with open(chooser.selection[0], "rb") as fh:
                    self._fw_accept(fh.read())
            except Exception as exc:
                self.log(f"fw_pick: {exc}")
                self.fw_info_text = i18n.t("fw_unknown")
            popup.dismiss()

        popup = Popup(title=i18n.t("fw_pick_file"), content=chooser,
                      size_hint=(0.95, 0.9))
        chooser.bind(on_submit=_picked)
        popup.open()

    def _fw_accept(self, data: bytes, name: str = ""):
        """Store a firmware image and describe it."""
        self._fw_data = data
        # Every pick is appended, so picking bootloader, partition table and
        # app one after another gives a three-image flash. A single pick still
        # works: fw_flash() falls back to the plain path when the list holds
        # one file, which is the same thing written at offset 0.
        self._fw_files.append({
            "name": name or f"file{len(self._fw_files) + 1}",
            "data": data,
            # The first file keeps offset 0: a single combined image is written
            # at the start of flash, and silently moving it to 0x10000 would
            # break the case that used to work. Later files are guessed from
            # their names, and "fill offsets" re-guesses all of them.
            "offset": 0 if not self._fw_files else flasher.guess_offset(name),
        })
        self._render_fw_files()
        info = flasher.sniff(data)
        self._fw_kind = info["kind"]
        lines = [f"{i18n.t('fw_kind')}: {info['detail']}",
                 f"{i18n.t('fw_size')}: {len(data)} bytes"]
        if info["kind"] == "uf2":
            lines.append(f"{i18n.t('fw_target')}: "
                         f"{flasher.uf2_target_family(data)}")
            if not flasher.uf2_is_valid(data):
                lines.append("(UF2 blocks look damaged)")
        if info.get("chip"):
            lines.append(f"{i18n.t('fw_target')}: {info['chip']}")
        self.fw_info_text = "\n".join(lines)
        self.log(f"firmware: {info['kind']}, {len(data)} bytes")

    def _render_fw_files(self):
        """Rebuild the multi-image list from `self._fw_files`."""
        box = self.ids_of("firmware").get("fw_files")
        if box is None:
            return
        box.clear_widgets()
        for idx, item in enumerate(self._fw_files):
            row = BoxLayout(size_hint_y=None, height=dp(44), spacing=dp(6))
            name = Label(text=f"{item['name']} ({len(item['data'])} B)",
                         size_hint_x=0.5, font_size='12sp',
                         halign='left', valign='middle',
                         text_size=(None, None), shorten=True)
            off = TextInput(text=f"{item['offset']:#x}", size_hint_x=0.25,
                            font_size='13sp', multiline=False, halign='center')

            def _store(inst, value, _i=idx):
                # Kept as a string until flashing, so a half-typed value does
                # not have to be a valid number to survive a redraw.
                self._fw_files[_i]["offset_text"] = value

            off.bind(text=_store)
            off.text = f"{item['offset']:#x}"
            item["offset_text"] = off.text
            rm = Button(text=i18n.t("fw_remove"), size_hint_x=0.25,
                        font_size='12sp')

            def _remove(inst, _i=idx):
                self._fw_files.pop(_i)
                self._render_fw_files()

            rm.bind(on_release=_remove)
            row.add_widget(name)
            row.add_widget(off)
            row.add_widget(rm)
            box.add_widget(row)
        self._update_flash_label()

    def _update_flash_label(self):
        btn = self.ids_of("firmware").get("btn_flash_all")
        if btn is None:
            return
        n = len(self._fw_files)
        btn.text = (i18n.t("fw_flash_all", n=n) if n > 1
                    else i18n.t("fw_flash_esp"))

    def fw_guess_offsets(self):
        """Fill every offset in from its file name."""
        if not self._fw_files:
            self.status_text = i18n.t("fw_no_files")
            return
        for item in self._fw_files:
            item["offset"] = flasher.guess_offset(item["name"])
        self._render_fw_files()
        self.log("fw_offsets: guessed from file names")

    def fw_clear_files(self):
        """Drop the multi-image list and go back to the single-file path."""
        self._fw_files = []
        self._render_fw_files()
        self.fw_info_text = i18n.t("fw_no_file")

    def _fw_collect(self):
        """Turn the list into [(offset, data, name)] or raise UserError."""
        out = []
        for item in self._fw_files:
            raw = item.get("offset_text") or f"{item['offset']:#x}"
            try:
                value = int(str(raw).strip(), 16)
            except ValueError:
                raise UserError(i18n.t("fw_bad_offset",
                                       name=item["name"], value=raw))
            out.append((value, item["data"], item["name"]))
        return out

    def fw_flash(self):
        """Write the image(s) to an ESP32 in download mode."""
        if self._fw_files:
            self._fw_flash_multi()
            return
        if not self._fw_data:
            self.fw_info_text = i18n.t("fw_no_file")
            return
        kind = flasher.sniff(self._fw_data)["kind"]
        if kind != "esp":
            self.log(f"fw_flash: refusing to flash a '{kind}' image over serial")
            self.status_text = i18n.t("fw_unknown")
            return
        if self._fw_dev is None:
            self.status_text = i18n.t("fw_no_bootloader")
            return
        device = self._fw_dev
        image = self._fw_data

        def work():
            flasher.flash_esp32(device, image,
                                progress=lambda i, n: Clock.schedule_once(
                                    lambda dt: setattr(
                                        self, "status_text",
                                        i18n.t("fw_working", n=int(i * 100 / n)))))
            return True

        def ok(_):
            self.busy = False
            self.status_text = i18n.t("fw_done")
            self.log("fw_flash: done")

        self._worker(work, on_ok=ok, busy_text=i18n.t("fw_working", n=0))

    def _fw_flash_multi(self):
        """Write every file in the list at its own offset."""
        if self._fw_dev is None:
            self.status_text = i18n.t("fw_no_bootloader")
            return
        try:
            entries = self._fw_collect()
        except UserError as exc:
            self.status_text = str(exc)
            return
        device = self._fw_dev
        # Two images at the same address means one silently overwrites the
        # other, which reads as "it flashed fine but the board is still dead".
        seen = {}
        for offset, _, name in entries:
            if offset in seen:
                self.log(f"fw_flash: '{seen[offset]}' and '{name}' both at "
                         f"{offset:#x}")
            seen[offset] = name
        self.log("fw_flash: " + ", ".join(f"{n}@{o:#x}" for o, _, n in entries))

        def work():
            flasher.flash_esp32_multi(
                device, entries,
                progress=lambda i, n, done, blocks: Clock.schedule_once(
                    lambda dt: setattr(
                        self, "status_text",
                        i18n.t("fw_multi_progress", i=i, n=n,
                               p=int(done * 100 / blocks) if blocks else 0))))
            return True

        def ok(_):
            self.busy = False
            self.status_text = i18n.t("fw_done")
            self.log("fw_flash: done")

        self._worker(work, on_ok=ok, busy_text=i18n.t("fw_working", n=0))

    def fw_erase(self):
        """Erase the whole flash chip.

        The recovery step for a board whose firmware will not start. Re-flashing
        on its own is not enough: whatever bad configuration stopped it booting
        is still sitting in flash, so the board comes back up in exactly the
        same state. Erasing first is what clears it.

        ESP32 only. RP2040/RP2350 present as a U-disk, so there is nothing for
        us to erase over serial - those need the upstream nuke image.
        """
        if self._fw_dev is None:
            self.status_text = i18n.t("fw_no_bootloader")
            return
        dev = self._fw_dev

        self._ask_confirm(
            i18n.t("dlg_erase_title"),
            i18n.t("dlg_erase_body"),
            i18n.t("dlg_erase_go"),
            lambda: self._do_erase(dev),
        )

    def _do_erase(self, dev):
        def work():
            flasher.erase_esp32(dev)
            return True

        def ok(_):
            self.busy = False
            self.status_text = i18n.t("fw_erase_done")
            self.log("fw_erase: done")

        self._worker(work, on_ok=ok, busy_text=i18n.t("fw_erasing"))

    def fw_save_uf2(self):
        """Hand a UF2 to the system file manager (RP2040/RP2350 path)."""
        if self._fw_kind != "uf2":
            self.status_text = i18n.t("fw_unknown")
            return
        try:
            flasher.save_via_saf("firmware.uf2")
            self.status_text = i18n.t("fw_save_hint")
        except Exception as exc:
            self.log(f"fw_save_uf2: {exc}")
            self.status_text = i18n.t("fw_saf_failed", err=exc)

    # -------------------------------------------------------- worker glue

    def _worker(self, fn, on_ok=None, busy_text=None):
        if self.busy:
            return

        def run():
            try:
                result = fn()
            except Exception as exc:
                err, tb = exc, traceback.format_exc()
                # 'exc' is cleared at the end of the except block, so bind it
                # to a local name the deferred callback can safely capture.
                Clock.schedule_once(lambda dt: self._fail(err, tb))
                return
            if on_ok:
                # An exception raised inside a Clock callback propagates into
                # Kivy's main loop and takes the whole app down - which is what
                # "tapping scan crashes instantly" looks like on a phone. Wrap
                # the success path the same way the failure path already is.
                Clock.schedule_once(lambda dt: self._safe(on_ok, result))

        # Drives `disabled:` on every MenuButton, so setting it here is
        # what actually greys the buttons out.
        self.busy = True
        self.status_text = busy_text or i18n.t("msg_processing")
        threading.Thread(target=run, daemon=True).start()

    def _safe(self, fn, *args):
        """Run `fn` on the UI thread without letting it kill the app."""
        try:
            fn(*args)
        except Exception as exc:
            self._fail(exc, traceback.format_exc())

    def _on_keepalive(self, status: int):
        """Called from the worker thread while the device keeps us waiting.

        A FIDO operation that needs a button press answers with KEEPALIVE every
        100ms instead of the real response. Without this the UI just sits on
        "读取中…" and people assume it has hung and pull the cable.
        """
        if status == ctap.KA_UPNEEDED:
            text = i18n.t("ka_upneeded")
        elif status == ctap.KA_PROCESSING:
            text = i18n.t("ka_processing")
        else:
            text = i18n.t("ka_unknown", status=f"0x{status:02X}")
        Clock.schedule_once(lambda dt: setattr(self, "status_text", text))

    def _fail(self, exc, tb):
        self.busy = False
        self.log(f"[error] {exc}")
        # These carry their own explanation in the message. A traceback under
        # them says nothing the message does not, and pushes the one line the
        # user needs off the top of the log.
        if not isinstance(exc, QUIET_ERRORS):
            self.log(tb)
        try:
            self.status_text = i18n.t("msg_failed", err=exc)
        except Exception:
            self.status_text = str(exc)

    def _done(self, text=None):
        self.busy = False
        if text:
            self.status_text = text

    # --------------------------------------------------------------- scan

    def scan(self):
        def work():
            if platform != "android":
                raise RuntimeError(i18n.t("err_not_android", plat=platform))
            channels = detect.scan()
            self._channels = channels
            return channels

        self._worker(work, self._render_channel_list, i18n.t("scanning"))

    def _render_channel_list(self, channels):
        self._done()
        box = self.ids_of("scan").list_box
        box.clear_widgets()
        if not channels:
            self.status_text = i18n.t("scan_none_hint")
            box.add_widget(Label(text=i18n.t("scan_none_item"),
                                 font_name=fonts.FONT_NAME,
                                 size_hint_y=None, height=40))
            return
        self.status_text = i18n.t("scan_found", n=len(channels))
        for ch in channels:
            # A plain Button does not wrap: without text_size bound to the
            # width, a long channel label is drawn on one line and overflows
            # the fixed height, overlapping whatever follows.
            #
            # The height must follow texture_size, not size. texture_size is
            # only correct *after* the texture has been rebuilt, which happens
            # on the next frame - so setting the height inside a size handler
            # uses the previous, stale value and the widget ends up shorter
            # than what it draws. That is precisely how the hint text ended up
            # painted over the channel button above it.
            btn = Button(text=f"{ch.label}\n{ch.detail}",
                         font_name=fonts.FONT_NAME,
                         size_hint_y=None, font_size="13sp",
                         halign="center", valign="center")
            btn.bind(width=lambda _b, _w: setattr(
                btn, "text_size", (btn.width - 12, None)))
            btn.bind(texture_size=lambda _b, _t: setattr(
                btn, "height", max(btn.texture_size[1] + dp(16), 70)))
            btn.bind(on_release=lambda _b, c=ch: self.connect(c))
            box.add_widget(btn)

        # A board running its firmware normally offers CCID and/or the FIDO HID
        # interface. Seeing nothing but the rescue channel means the firmware is
        # not up - which is alarming to hit with no explanation, but is also the
        # one state that is always recoverable.
        if all(getattr(ch, "kind", None) == "rescue" for ch in channels):
            hint = Label(text=i18n.t("hint_rescue_only"),
                         font_name=fonts.FONT_NAME, font_size="13sp",
                         halign="left", valign="top",
                         size_hint_y=None, height=60,
                         color=(1, 0.86, 0.4, 1))
            hint.bind(width=lambda *_a: setattr(
                hint, "text_size", (hint.width - 12, None)))
            hint.bind(texture_size=lambda *_a: setattr(
                hint, "height", max(hint.texture_size[1] + dp(10), 60)))
            box.add_widget(hint)

    def connect(self, channel):
        def work():
            kind, transport = detect.connect(channel)
            self.kind = kind
            self.transport = transport
            self.channel = channel
            if kind == "apdu":
                self.pk = PicoKey(transport)
                return {"kind": "apdu", "summary": self.pk.summary(),
                        "flash": self.pk.flash_info()}
            transport.init()
            info = {}
            try:
                info = transport.get_info(on_keepalive=self._on_keepalive)
            except Exception as e:
                self.log(i18n.t("msg_getinfo_failed", err=e))
            return {"kind": "ctap", "init": transport._init_response, "info": info}

        def done(result):
            self._dev = result
            self.connected = True
            self._sync_channel()
            self._render_device_text()
            self._done(i18n.t("connected"))
            self.log(i18n.t("msg_connected_log", label=self.channel.label))
            if result["kind"] == "ctap":
                self.log("getInfo: " + str(result.get("info")))
            self._ctap_info = result.get("info") if result["kind"] == "ctap" else None
            self._uv_refresh_state()
            self.go("device")

        self._worker(work, done, i18n.t("connecting"))

    # ----------------------------------------------------- device info text

    def _sync_channel(self):
        """Grey out whatever the connected channel cannot do.

        `self.kind` is set by connect(); nothing else has to remember which
        commands belong to which channel.
        """
        if not self.connected:
            self.blocked_apdu = False
            self.blocked_ctap = False
            self.channel_hint = ""
            self._ctap_info = None
            self.uv_state_text = ""
            return
        self.blocked_apdu = self.kind != "apdu"
        self.blocked_ctap = self.kind != "ctap"
        self.channel_hint = i18n.t(
            "hint_channel_apdu" if self.kind == "apdu" else "hint_channel_ctap")

    def _render_device_text(self):
        if not self._dev:
            self.device_text = i18n.t("not_connected")
            return
        if self._dev["kind"] == "apdu":
            self.device_text = self._apdu_text()
        else:
            self.device_text = self._ctap_text()

    def _apdu_text(self):
        s = self._dev.get("summary") or {}
        lines = [
            f"{i18n.t('lbl_platform')}：{s.get('platform', '?')}",
            f"{i18n.t('lbl_product')}：{s.get('product', '?')}",
            f"{i18n.t('lbl_version')}：{s.get('version', '?')}",
            f"{i18n.t('lbl_channel')}：{s.get('connection', '?')}",
        ]
        flash = self._dev.get("flash")
        if flash and flash.get("total"):
            kb = lambda v: v / 1024.0
            lines.append(i18n.t("flash_line", used=kb(flash["used"]),
                                total=kb(flash["total"]), free=kb(flash["free"])))
            lines.append(i18n.t("files_line", n=flash["nfiles"],
                                size=kb(flash["size"])))
        return "\n".join(lines)

    def _ctap_text(self):
        init = self._dev.get("init") or {}
        caps = {}
        if self.transport is not None:
            try:
                caps = self.transport.capabilities
            except Exception:
                caps = {}
        dev_ver = init.get("device_version") or (0, 0, 0)
        # `options.up` from authenticatorGetInfo is the device telling us
        # whether it will insist on a physical press. When it is false (or
        # missing) a PIN alone satisfies every request, which is the usual
        # reason people never see the "touch your key" prompt.
        opts = (self._dev.get("info") or {}).get("options") or {}
        up = opts.get("up")
        if up is True:
            up_text = i18n.t("up_on")
        elif up is False:
            up_text = i18n.t("up_off")
        else:
            up_text = i18n.t("up_unknown")
        return "\n".join([
            f"{i18n.t('lbl_channel')}：FIDO HID (CTAPHID)",
            f"{i18n.t('lbl_protocol')}：{init.get('protocol_version')}",
            f"{i18n.t('lbl_device_ver')}：{dev_ver}",
            f"{i18n.t('lbl_caps')}：wink={caps.get('wink')} cbor={caps.get('cbor')}",
            f"{i18n.t('lbl_up')}：{up_text}",
            f"{i18n.t('lbl_cid')}：0x{init.get('cid', 0):08X}",
        ])

    # ----------------------------------------------------------- device ops

    def _require_apdu(self):
        if self.kind != "apdu" or self.pk is None:
            raise UserError(i18n.t("err_no_apdu"))
        return self.pk

    def refresh(self):
        def work():
            pk = self._require_apdu()
            pk = PicoKey(pk.device, connection_type=pk.connection_type)
            self.pk = pk
            return {"kind": "apdu", "summary": pk.summary(), "flash": pk.flash_info()}

        def done(result):
            self._dev = result
            self._render_device_text()
            self._done(i18n.t("msg_refreshed"))
            self.log("flash: " + str(result["flash"]))

        self._worker(work, done, i18n.t("msg_reading"))

    # ------------------------------------------------------------ PHY fields

    def _fill_phy_fields(self):
        """Push the last read PHY values back into the input widgets."""
        phy = self._phy
        if phy is None or not self.root:
            return
        try:
            ids = self.ids_of("device")
        except Exception:
            return
        if phy.vid is not None:
            ids.vid.text = f"{phy.vid:04X}"
        if phy.pid is not None:
            ids.pid.text = f"{phy.pid:04X}"
        if phy.usb_product:
            ids.usb_product.text = phy.usb_product
        if phy.led_gpio is not None:
            ids.led_gpio.text = str(phy.led_gpio)
        if phy.led_brightness is not None:
            ids.led_btness.text = str(phy.led_brightness)
        if phy.up_btn is not None:
            ids.up_btn.text = str(phy.up_btn)
        if phy.led_driver is not None:
            try:
                ids.led_driver.text = PhyLedDriver(phy.led_driver).name
            except Exception:
                pass
        opts = phy.opts or 0
        ids.opt_wcid.state = "down" if opts & int(PhyOpt.WCID) else "normal"
        ids.opt_dimm.state = "down" if opts & int(PhyOpt.DIMM) else "normal"
        ids.opt_no_reset.state = "down" if opts & int(PhyOpt.DISABLE_POWER_RESET) else "normal"
        ids.opt_led_steady.state = "down" if opts & int(PhyOpt.LED_STEADY) else "normal"
        curves = phy.enabled_curves
        if curves is not None:
            for i, (_key, bit) in enumerate(CURVES):
                ids[f"cv{i}"].state = "down" if curves & bit else "normal"
        itf = phy.enabled_usb_itf or 0
        ids.itf_ccid.state = "down" if itf & int(PhyUsbItf.CCID) else "normal"
        ids.itf_wcid.state = "down" if itf & int(PhyUsbItf.WCID) else "normal"
        ids.itf_hid.state = "down" if itf & int(PhyUsbItf.HID) else "normal"
        ids.itf_kb.state = "down" if itf & int(PhyUsbItf.KB) else "normal"
        self._render_curves_text()

    def read_phy(self):
        def work():
            phy = self._require_apdu().phy()
            if phy is None:
                raise RuntimeError(i18n.t("err_phy_read"))
            return phy

        def done(phy):
            self._phy = phy
            self._fill_phy_fields()
            self.log(f"PHY: {phy!r}")
            self._done(i18n.t("msg_phy_read",
                              vid=(f"{phy.vid:04X}" if phy.vid is not None else "—"),
                              pid=(f"{phy.pid:04X}" if phy.pid is not None else "—"),
                              gpio=phy.led_gpio, btness=phy.led_brightness))

        self._worker(work, done, i18n.t("msg_reading_phy"))

    def curves_all(self):
        ids = self.ids_of("device")
        for i in range(len(CURVES)):
            ids[f"cv{i}"].state = "down"
        self._render_curves_text()

    def curves_none(self):
        ids = self.ids_of("device")
        for i in range(len(CURVES)):
            ids[f"cv{i}"].state = "normal"
        self._render_curves_text()

    def curves_changed(self):
        self._render_curves_text()

    def _render_curves_text(self):
        value = self._current_curves()
        self.curves_text = i18n.t("curves_value", v=value)

    def _current_curves(self) -> int:
        if not self.root:
            return 0
        try:
            ids = self.ids_of("device")
        except Exception:
            return 0
        value = 0
        for i, (_key, bit) in enumerate(CURVES):
            if ids[f"cv{i}"].state == "down":
                value |= bit
        return value

    def _build_phy(self) -> PhyData:
        ids = self.ids_of("device")
        phy = PhyData()

        def hexval(text):
            text = (text or "").strip()
            return int(text, 16) if text else None

        def intval(text):
            text = (text or "").strip()
            return int(text) if text else None

        vid, pid = hexval(ids.vid.text), hexval(ids.pid.text)
        if vid is not None or pid is not None:
            phy.vidpid = bytearray(4)
            if vid is not None:
                phy.vid = vid
            if pid is not None:
                phy.pid = pid
        if ids.led_gpio.text.strip():
            phy.led_gpio = intval(ids.led_gpio.text) & 0xFF
        if ids.led_btness.text.strip():
            phy.led_brightness = intval(ids.led_btness.text) & 0xFF
        if ids.up_btn.text.strip():
            phy.up_btn = intval(ids.up_btn.text) & 0xFF
        product = (ids.usb_product.text or "").strip()
        if product:
            if len(product) > 31:
                raise ValueError(i18n.t("err_usb_product_long"))
            phy.usb_product = product
        try:
            phy.led_driver = int(PhyLedDriver[ids.led_driver.text])
        except Exception:
            phy.led_driver = None

        opts = 0
        if ids.opt_wcid.state == "down":
            opts |= int(PhyOpt.WCID)
        if ids.opt_dimm.state == "down":
            opts |= int(PhyOpt.DIMM)
        if ids.opt_no_reset.state == "down":
            opts |= int(PhyOpt.DISABLE_POWER_RESET)
        if ids.opt_led_steady.state == "down":
            opts |= int(PhyOpt.LED_STEADY)
        phy.opts = opts

        phy.enabled_curves = self._current_curves()

        itf = 0
        if ids.itf_ccid.state == "down":
            itf |= int(PhyUsbItf.CCID)
        if ids.itf_wcid.state == "down":
            itf |= int(PhyUsbItf.WCID)
        if ids.itf_hid.state == "down":
            itf |= int(PhyUsbItf.HID)
        if ids.itf_kb.state == "down":
            itf |= int(PhyUsbItf.KB)
        phy.enabled_usb_itf = itf
        return phy

    def write_phy(self):
        def work():
            pk = self._require_apdu()
            data = self._build_phy().serialize()
            self.log("PHY -> " + data.hex())
            pk.phy(data)
            return data

        def done(_data):
            self._done(i18n.t("msg_phy_written"))
            self.log(i18n.t("msg_phy_written_log"))

        self._worker(work, done, i18n.t("msg_writing_phy"))

    # ---------------------------------------------------------- secure boot

    def _render_secure_text(self):
        s = self._secure
        if not s:
            self.secure_text = i18n.t("msg_no_data")
            return
        yes = lambda b: i18n.t("lbl_yes") if b else i18n.t("lbl_no")
        self.secure_text = " | ".join([
            f"{i18n.t('lbl_secure_enabled')}: {yes(s.get('enabled'))}",
            f"{i18n.t('lbl_secure_locked')}: {yes(s.get('locked'))}",
            f"{i18n.t('lbl_bootkey')}: {s.get('boot_key')}",
        ])

    def read_secure(self):
        def work():
            info = self._require_apdu().secure_info()
            if not info:
                raise RuntimeError(i18n.t("err_secure_unavailable"))
            return info

        def done(info):
            self._secure = info
            self._render_secure_text()
            state = f"{info.get('enabled')}/{info.get('locked')}/{info.get('boot_key')}"
            self._done(i18n.t("msg_secure_done", state=state))
            self.log("secure: " + str(info))

        self._worker(work, done, i18n.t("msg_secure_reading"))

    def probe_secure(self):
        """List the rescue applet's readable objects.

        Read-only on purpose. The secure-boot command burns eFuse/OTP, so the
        only honest way to find out what a given build actually supports is to
        ask with reads first and look at the answer.
        """
        def work():
            pk = self._require_apdu()
            table = pk.probe_read_objects()
            lines = [i18n.t("probe_title")]
            for p1 in sorted(table):
                sw, data = table[p1]
                if sw is None:
                    lines.append(f"  P1={p1:02X}: {data.decode('utf-8', 'replace')}")
                elif sw == 0x9000:
                    preview = data.hex()[:48] + ("..." if len(data) > 24 else "")
                    lines.append(f"  P1={p1:02X}: 9000, {len(data)}B, {preview}")
                else:
                    lines.append(f"  P1={p1:02X}: SW={sw:04X}")
            lines.append("")
            lines.append(i18n.t("probe_footer"))
            return "\n".join(lines)

        def done(report):
            self._done(i18n.t("msg_probe_done"))
            self.log(report)
            self.go("log")

        self._worker(work, done, i18n.t("msg_probe_running"))

    def set_secure_boot(self):
        """Ask before burning anything.

        This writes eFuse/OTP, which cannot be undone. The only gate used to be
        a checkbox on a crowded screen, and the warning was printed to the log
        *after* the write had already happened - too late to be a warning, and
        invisible unless you went looking for it.
        """
        ids = self.ids_of("device")
        raw = (ids.bootkey.text or "").strip()
        try:
            slot = int(raw) if raw else 0
        except ValueError:
            slot = -1
        if not 0 <= slot <= 15:
            self._done(i18n.t("err_bootkey_range"))
            return

        lock = ids.chk_lock.state == "down"
        self._ask_secure_confirm(slot, lock)

    def _ask_confirm(self, title, body_text, go_label, on_yes, typed_word=None,
                     entry=False, entry_hint=""):
        """One dialog for every irreversible action.

        `typed_word` (e.g. "CONFIRM") makes the user type it before the action
        runs. Used for eFuse writes; plain erase relies on the button alone,
        which is enough for something that is destructive but recoverable.

        `entry` adds a free-text field whose contents are passed to `on_yes`,
        for the confirmation that also needs a value (a new minimum PIN
        length). It is separate from `typed_word` because that one is checked
        for an exact match and never handed to the caller.

        The message label sizes itself to its text. A fixed height clipped long
        strings and made them collide with the buttons below - the same bug
        that hit the scan page.
        """
        from kivy.uix.boxlayout import BoxLayout
        from kivy.uix.button import Button
        from kivy.uix.label import Label
        from kivy.uix.popup import Popup
        from kivy.uix.textinput import TextInput

        body = BoxLayout(orientation="vertical", spacing=10, padding=12)

        msg = Label(text=body_text, font_name=fonts.FONT_NAME,
                    font_size="14sp", halign="left", valign="top",
                    size_hint_y=None, height=60)
        msg.bind(width=lambda *_a: setattr(
            msg, "text_size", (msg.width - 12, None)))
        msg.bind(texture_size=lambda *_a: setattr(
            msg, "height", max(msg.texture_size[1] + dp(8), 60)))
        body.add_widget(msg)

        typed = None
        if typed_word:
            typed = TextInput(multiline=False, font_name=fonts.FONT_NAME,
                              hint_text=i18n.t("dlg_secure_typed_hint"),
                              size_hint_y=None, height=46, font_size="14sp")
            body.add_widget(typed)

        value_box = None
        if entry:
            value_box = TextInput(multiline=False, font_name=fonts.FONT_NAME,
                                  hint_text=entry_hint, input_filter="int",
                                  size_hint_y=None, height=46, font_size="14sp")
            body.add_widget(value_box)

        row = BoxLayout(orientation="horizontal", spacing=10,
                        size_hint_y=None, height=52)
        cancel = Button(text=i18n.t("btn_cancel"), font_name=fonts.FONT_NAME)
        go = Button(text=go_label, font_name=fonts.FONT_NAME)
        row.add_widget(cancel)
        row.add_widget(go)
        body.add_widget(row)

        popup = Popup(title=title, content=body,
                      size_hint=(0.94, 0.72), auto_dismiss=False)

        def _cancel(_):
            popup.dismiss()

        def _go(_):
            if typed_word and (typed.text or "").strip().upper() != typed_word:
                typed.text = ""
                typed.hint_text = i18n.t("dlg_secure_typed_bad")
                return
            popup.dismiss()
            if entry:
                on_yes((value_box.text or "").strip())
            else:
                on_yes()

        cancel.bind(on_release=_cancel)
        go.bind(on_release=_go)
        popup.open()

    def _ask_secure_confirm(self, slot, lock):
        self._ask_confirm(
            i18n.t("dlg_secure_title"),
            i18n.t("dlg_secure_body", slot=slot,
                   lock=i18n.t("lbl_yes") if lock else i18n.t("lbl_no")),
            i18n.t("dlg_secure_go"),
            lambda: self._do_secure_boot(slot, lock),
            typed_word="CONFIRM",
        )

    def _do_secure_boot(self, slot, lock):
        def work():
            try:
                self._require_apdu().secure_boot(slot, lock)
            except SecureBootError as e:
                # Irreversible on real hardware: never let a refusal look like
                # success, and never bury the reason under a stack trace.
                raise UserError(i18n.t("err_secure_write", reason=str(e)))
            return slot

        def done(slot):
            self._done(i18n.t("msg_secure_set", slot=slot))
            self.log(i18n.t("hint_bootkey"))

        self._worker(work, done, i18n.t("msg_secure_writing"))

    # ----------------------------------------------------------- misc ops

    def wink(self):
        def work():
            if self.kind != "ctap":
                # Was err_no_apdu before, which told CCID users they were on
                # the FIDO HID channel - the exact opposite of the truth.
                raise UserError(i18n.t("err_no_ctap"))
            self.transport.wink()
            return True

        def done(_):
            self._done(i18n.t("msg_wink_sent"))

        self._worker(work, done, i18n.t("msg_winking"))

    def test_presence(self):
        """Ask the device to confirm user presence and time how long it took.

        A board with a real button on the configured GPIO will sit there and
        send KEEPALIVE until it is pressed. One without will answer straight
        away, and that instant answer is the clearest evidence that presence is
        not being enforced.
        """
        def work():
            if self.kind != "ctap":
                raise UserError(i18n.t("err_no_ctap"))
            try:
                return self.transport.selection(
                    timeout=30000, on_keepalive=self._on_keepalive)
            except ctap.CTAPError as exc:
                raise UserError(i18n.t("msg_presence_failed", err=exc))

        def done(elapsed):
            if elapsed < 1.0:
                self._done(i18n.t("msg_presence_instant") % elapsed)
                self.log(i18n.t("msg_presence_instant") % elapsed)
            else:
                self._done(i18n.t("msg_presence_ok") % elapsed)
                self.log("presence confirmed in %.1fs" % elapsed)

        self._worker(work, done, i18n.t("msg_testing_presence"))

    def _uv_pin(self) -> str:
        """The PIN typed into the box, or a UserError naming the problem."""
        ids = self.ids_of("device")
        box = ids.get("inp_pin")
        pin = (box.text if box is not None else "") or ""
        pin = pin.strip()
        if not pin:
            raise UserError(i18n.t("uv_pin_required"))
        return pin

    def _uv_refresh_state(self):
        """Re-read getInfo and show the options this feature is about."""
        info = self._ctap_info or {}
        summary = ctapcfg.summarise(info) if info else {}
        if not summary:
            self.uv_state_text = i18n.t("uv_state_unknown")
            return
        lines = []
        for key, label in (("alwaysUv", "uv_always_uv"),
                           ("makeCredUvNotRqd", "uv_make_cred"),
                           ("clientPin", "uv_client_pin")):
            value = summary.get(key)
            if value is True:
                state = i18n.t("uv_on")
            elif value is False:
                state = i18n.t("uv_off")
            else:
                state = i18n.t("uv_not_reported")
            lines.append(f"{i18n.t(label)}: {state}")
        if not ctapcfg.config_supported(info):
            lines.append(i18n.t("uv_unsupported"))
        self.uv_state_text = "\n".join(lines)

    def toggle_always_uv(self):
        """Flip alwaysUv - the switch between "PIN every time" and "press the button"."""
        if self.kind != "ctap":
            self.status_text = i18n.t("err_no_ctap")
            return
        info = self._ctap_info or {}
        if not ctapcfg.config_supported(info):
            self.status_text = i18n.t("uv_unsupported")
            return

        try:
            pin = self._uv_pin()
        except UserError as exc:
            self.status_text = str(exc)
            return

        transport = self.transport

        def work():
            # The whole handshake happens in the worker: it is several USB
            # round trips plus a scalar multiplication, none of which belongs
            # on the UI thread.
            cfg = ctapcfg.UvConfig(transport)
            cfg.obtain_token(pin)
            cfg.toggle_always_uv()
            return True

        def ok(_):
            self.busy = False
            self.status_text = i18n.t("uv_toggled")
            self.log("alwaysUv: toggled")
            self._ctap_info = None
            self._uv_refresh_state()

        self._worker(work, ok, i18n.t("uv_working"))

    def ask_set_min_pin(self):
        """Confirm before raising the minimum PIN length - it cannot be undone."""
        if self.kind != "ctap":
            self.status_text = i18n.t("err_no_ctap")
            return
        try:
            pin = self._uv_pin()
        except UserError as exc:
            self.status_text = str(exc)
            return

        def on_yes(value):
            try:
                length = int(str(value).strip())
            except (TypeError, ValueError):
                self.status_text = i18n.t("uv_bad_length")
                return
            self._set_min_pin(pin, length)

        self._ask_confirm(i18n.t("uv_set_min_title"),
                          i18n.t("uv_set_min_body"),
                          i18n.t("uv_set_min_go"),
                          on_yes, typed_word="CONFIRM",
                          entry=True, entry_hint=i18n.t("uv_set_min_hint"))

    def _set_min_pin(self, pin: str, length: int):
        transport = self.transport

        def work():
            cfg = ctapcfg.UvConfig(transport)
            cfg.obtain_token(pin)
            cfg.set_min_pin_length(length)
            return True

        def ok(_):
            self.busy = False
            self.status_text = i18n.t("uv_min_set") % length
            self.log(f"minPINLength: {length}")
            self._ctap_info = None
            self._uv_refresh_state()

        self._worker(work, ok, i18n.t("uv_working"))

    def reboot(self, bootsel: bool):
        def work():
            self._require_apdu().reboot(bootsel)
            return True

        def done(_):
            self._done(i18n.t("msg_reboot_sent"))
            self.disconnect(silent=True)

        self._worker(work, done, i18n.t("msg_rebooting"))

    def disconnect(self, silent: bool = False):
        try:
            if self.pk:
                self.pk.close()
            if self.transport:
                self.transport.close()
        except Exception as e:
            self.log(i18n.t("msg_closed_error", err=e))
        self.pk = None
        self.transport = None
        self.kind = None
        self.connected = False
        self._sync_channel()
        self._dev = None
        self._secure = None
        self._phy = None
        # firmware page state
        self._fw_data = None
        self._fw_dev = None
        self._fw_kind = None
        self.device_text = i18n.t("not_connected")
        self._render_secure_text()
        if not silent:
            self.status_text = i18n.t("msg_disconnected")
            self.go("scan")

    # ------------------------------------------------------------ selftest

    def selftest(self):
        def work():
            from picokeyapp import selftest
            return selftest.run()

        def done(report):
            self._done(i18n.t("msg_selftest_done"))
            self.log(report)
            self.go("log")

        self._worker(work, done, i18n.t("msg_selftest_running"))


def main():
    PicoKeyApp().run()


if __name__ == "__main__":
    main()
