# PicoKey Manager for Android

[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Platform](https://img.shields.io/badge/Platform-Android%208.0%2B-green.svg)](https://www.android.com/)
[![Hardware testing](https://img.shields.io/badge/Hardware%20testing-none%20yet-critical.svg)](#verification-status)
[![Authored by](https://img.shields.io/badge/code%20%26%20docs-AI%20generated-8A2BE2.svg)](#ai-generated-code)

[简体中文](README.md) | English

An Android app that talks to a **development board** (one running the Pico HSM /
Pico FIDO / Pico OpenPGP firmware) over a USB OTG cable. Plug the key into your phone and you can read
device information, edit the PHY configuration (USB VID/PID, LED pin and
brightness, enabled USB interfaces), blink the LED, reboot the device, or drop
it into flashing mode to load new firmware.

Supported chips: **RP2040, RP2350, ESP32-S2, ESP32-S3** — see
[Supported boards](#supported-boards).

**Download**: a prebuilt APK is on the [Releases](../../releases) page — grab the
latest one. Older versions stay on the same page so you can roll back; see
[CHANGELOG.md](CHANGELOG.md) for what changed in each.

**Updates install over the old one — no uninstall needed.** Every build is signed
with the same key.

There is also a **web flashing tool**, `picokey-commissioner.html`, deployed
through GitHub Pages — just open it in Chrome on your phone (WebUSB requires
HTTPS, which Pages provides for free):

```
https://ksksmnejs.github.io/PicoKey-Manager-Android/
```

It is deployed automatically by `.github/workflows/static.yml`; nothing to do.

**What it does**: exactly one thing — flashes firmware onto an ESP32-S2 / S3 that
is in download mode (using the esptool ROM protocol, no tools to install).

**What it cannot do**: no VID/PID editing, no secure boot / secure lock, and no
reading a running device. Chrome has blocked browser access to the smart-card
(CCID) interface since version 67 (CVE-2018-6125), and CCID is exactly what
PicoKey firmware uses while running — so once the firmware is up, the browser
cannot see the board at all. Use the Android app for those (it talks to the
Android USB Host API, which has no such restriction).


---

## AI-generated code

**The code in this repository was written by AI and is not the work of the
upstream firmware authors.** If something misbehaves, suspect this app first —
not your board and not the firmware.

**This documentation was written by AI too, and may contain errors.** Technical
details here — USB IDs, chip differences, curve compatibility, Secure Boot
support — were compiled from public sources and were not verified item by item.
Where this file and the upstream firmware docs disagree, **upstream wins**.

Spot something wrong? Please open an issue. For anything safety-relevant
(writing PHY config, secure boot, flashing firmware) rely on the official
firmware documentation and your board's own manual, not on this file alone.

---

## Verification status

The protocol layer has automated self-test coverage, but **none of this code has
ever run against a real board**:

- Self-tests and simulated links all pass, but they exercise a **mock device**,
  not real hardware responses.
- USB permission prompts, OTG power delivery and vendor-specific HID interface
  handling are all untested on real phones.
- The actual effect of writing PHY config has never been verified.

**So read first, confirm the values, and only then consider writing.**

---

## Supported boards

PicoKeys firmware runs on four chips. The protocol layer is identical across
them; they differ in **how you flash them, how you enter flashing mode, and the
security features**.

| Chip | Typical boards | Flashing mechanism | Secure Boot / Lock |
| --- | --- | --- | --- |
| **RP2040** | Raspberry Pi Pico / Pico W | UF2 (becomes a drive in flashing mode) | ❌ none |
| **RP2350** | Pico 2, Waveshare RP2350-One/Zero/Tiny | UF2 (becomes a drive in flashing mode) | ✅ full |
| **ESP32-S2** | ESP32-S2 dev boards | esptool / DFU | ⚠️ uncertain |
| **ESP32-S3** | ESP32-S3 SuperMini, DevKitC | esptool / DFU | ⚠️ uncertain |

### RP2040 and RP2350 are not equally secure

- The RP2350 has an OTP region holding the master key that encrypts every stored
  key; with Secure Boot / Secure Lock it resists having the flash read out.
- **The RP2040 has none of this.** Its flash can be read directly — lose the
  board and the private keys on it are gone.

If security is the point, use an RP2350 or an ESP32-S3, not an RP2040.

### Two ESP32 quirks

**The device name changes in download mode.** There the board reports itself as
**"USB JTAG/serial debug unit"**, which is not the firmware's CCID interface and
not answer any command. If you see that name in the log, the board is stuck in
download mode — **unplug it, press nothing, plug it back in**.

**Secure Boot support is uncertain.** Upstream claims ESP32-S3 supports it; the
community fork (LibreKeys) marks it `No (// TODO)`. The two disagree. Press
**Read secure boot status** first, and if it comes back empty or nonsensical,
**do not force a write** — blown OTP fuses are physically irreversible.

### Factory VID/PID: you may not need to configure anything

Since January 2026 firmware ships with Raspberry Pi's officially assigned USB IDs:

| Firmware | VID:PID |
| --- | --- |
| Pico HSM | `2E8A:10FD` |
| Pico FIDO | `2E8A:10FE` |
| Pico OpenPGP | `2E8A:10FF` |

Older firmware used the placeholder `FEFF:FCFD`; that is the case where you do
have to change it. **If your goal is simply "a working FIDO2 key" and the VID/PID
is already one of the above, there is nothing to configure.** Changing it is
mainly about impersonating a YubiKey (for certain sites, or so Yubico
Authenticator can manage the device).

---

## Features

- **Device scan** — lists every usable channel:
  - `CCID` — full feature set: device info, PHY, secure boot, reboot
  - `rescue` (vendor `0xFF`) — fallback when the firmware is not up
  - `FIDO HID` — WINK, `authenticatorGetInfo`
- **PHY read/write** — USB VID/PID, product name, LED GPIO and brightness, USB
  interface switches, enabled curves
- **Secure boot** — read status, set the boot key slot, permanent lock
- **Device information** — platform, product, firmware version, flash usage
- **Maintenance** — reboot, enter flashing mode, WINK
- **Firmware flashing** — pick a firmware file with the system file manager and
  write it, see [Flashing firmware](#flashing-firmware)
- **Bilingual UI** — 简体中文 / English switchable at the top; the choice is remembered
- **Protocol self-test** — runs the stack against a fake USB pipe, no hardware needed

---

## Usage

1. Connect the board with an **OTG adapter**. **Hold no buttons while powering
   up** — on some boards that goes straight into flashing mode, where it does not
   appear as a firmware device and the app cannot talk to it.
2. Open the app → **Scan USB devices**. Every available channel appears.
3. Tap one to connect. Android shows a USB authorization dialog — **you must
   allow it** (asked only once; if denied, re-enable it in system settings).
4. On the device screen: refresh info / read PHY / write PHY / WINK / enter
   flashing mode.

If the device is not detected, run **protocol self-test** first — it needs no
hardware. All green means the app is fine and the problem is the cable, the power
supply, or the OTG adapter.

### Recommended order for a first run

1. **Read only, do not write** — if you can read device info, the link works
2. When editing VID/PID, leave other fields blank: they inherit the device's
   current values, so board-specific settings like LED GPIO are not wiped
3. **Enable at least P-256** among the curves (ES256, the most widely compatible
   WebAuthn default) and **leave secp256k1 off** — upstream warns some older
   Android devices do not support it and the device becomes undetectable
4. **Secure boot goes last**, and only when: passkeys are registered and proven in
   daily use, a backup exists, you are on stock upstream firmware, and you accept
   that it is irreversible

---

## Flashing firmware

The app has a **Flash firmware** page (button at the bottom of the scan screen)
covering two mechanically unrelated paths:

| Board | Underlying mechanism | What this app does |
| --- | --- | --- |
| RP2040 / RP2350 | In flashing mode the flash is exposed as a drive; copying a `.uf2` onto it is the whole job | Hands the UF2 to the system file manager, you save it to the `RPI-RP2` / `RP2350` drive |
| ESP32-S2 / S3 | esptool's ROM serial protocol over USB Serial/JTAG — no UF2 bootloader | Implements that protocol directly; no external tool needed |

Tap **Pick firmware file** and the app hands the choice to your **system file
manager** (Android's Storage Access Framework) so you can select a `.uf2` or
`.bin`.

The system file manager sees your whole storage — internal storage, SD card,
USB OTG drives and cloud providers alike. The app itself never walks the
directory tree, so it needs no storage permission at all.

Once loaded the app identifies the file type and shows its size; the target chip
is reported only when it is actually a **UF2** or **ESP image**. If it turns out
to be a ZIP, a gzip or a web page, the app says so plainly — that means you do
not have the firmware itself.

You supply the firmware file yourself (for example, from the releases of the
upstream open-source repo `polhenarejos/pico-fido`). This app makes no network
requests and bundles no firmware.

⚠️ **Neither flashing path has been verified on real hardware.** On your first
run, identify the file without flashing and read the log at each step.

---

## Known limitations

- Requires Android 8.0 (API 26) or newer, a device with USB host support, and an
  OTG adapter.
- No hot-plug monitoring. After unplugging, go back to the scan screen and
  reconnect.
- Secure channel / DKEK features are unavailable (the crypto library they need is
  not bundled); everything else works.
- **The RP2040 has no OTP protection** — its flash can be read directly. Use an
  RP2350 or ESP32-S3 if you need to resist physical extraction.
- The three firmwares (HSM / FIDO / OpenPGP) **cannot coexist**; switching
  requires flashing Pico Nuke to wipe first. Dedicate one board per purpose
  rather than switching back and forth.
- **"User presence" (the physical press) only works if a button is actually
  soldered to the board.** Most Pico boards ship with nothing but BOOTSEL, no
  user button. With no button fitted — or with a "Confirm button GPIO" that does
  not match the wiring — registering a passkey succeeds on the PIN alone and
  never asks for a touch. Use **"Test user presence (button)"** on the device
  screen to measure it: an instant answer means it never waited for you, an
  answer that only arrives after a pause means presence is genuinely enforced.
- The signing key `tools/debug.keystore.b64` is public in this repo, so every
  automated build signs identically and updates install cleanly. The trade-off:
  anyone could sign an APK with the same package name using it. A debug key is
  not a security boundary by design (that is how Android works).

  **The next point only matters if you build this app yourself** — ordinary
  users can ignore it: to use your own key instead, store it base64-encoded as
  the repository secret `ANDROID_KEYSTORE_BASE64`; it takes priority and the
  committed one is ignored.

---

## Troubleshooting

- **Device found but connection fails** — most likely the USB permission dialog
  was denied. Android asks only once; re-enable it in system settings, or
  reinstall the app.
- **"USB JTAG/serial debug unit" in the log (ESP32)** — the board is in download
  mode, with the firmware not running. Unplug, press nothing, plug back in.
- **Secure boot reads back empty on an ESP32** — the feature is probably not
  implemented on that board. Do not force a write; OTP fuses are irreversible.

---

## License

Upstream `pypicokey` is AGPL-3.0-or-later, and the files under `picokeyapp/pk/`
carry the same license (see `LICENSE`); the Android port and UI are released
under AGPL-3.0-or-later as well.

The bundled font `assets/fonts/NotoSansSC-Regular-subset.ttf` comes from
[Noto Sans SC](https://fonts.google.com/noto/specs/NotoSansSC) and is licensed
under the SIL Open Font License 1.1 (embedding and redistribution allowed), which
is separate from this project's AGPL terms.
