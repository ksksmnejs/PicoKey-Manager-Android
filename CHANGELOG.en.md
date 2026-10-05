# Changelog

Release notes (the body of the Releases page) are **generated from this file**
by GitHub Actions. Write them here; there is no need to touch the workflow.

Format: one second-level heading per version, and the heading must contain the
version number (with or without a `v` prefix, with or without a date). The
workflow matches it against `version` in `buildozer.spec`.

```markdown
## [vX.Y.Z] - YYYY-MM-DD

### Added
- something

### Fixed
- something
```

This file is the **single source of truth for the version number and the release
notes**. To publish:

1. Add a section for the new version here (and in `CHANGELOG.en.md`).
2. Actions → **Build Android APK** → Run workflow, leave the rest at defaults.

The workflow then: reads the version from this file → writes it into
`buildozer.spec` → derives the release tag → extracts this version's section as
the Releases page body → commits the bump back after a successful build.

Optional inputs when running the workflow:

| Input | Meaning |
| --- | --- |
| `bump` | `auto` (default, newest version here) / `patch` / `minor` / `major` / `none` |
| `overwrite` | **On** by default. If the tag exists it is replaced in place (leaving it unticked fails instead); untick to protect a published version |
| `draft` / `prerelease` | Publish as a draft / mark as pre-release |

If the build fails the job stops early and no version number is consumed.

---

## [v0.3.2] - 2026-10-05

### Added
- Two more self-checks: the bundled font must be able to draw every glyph the interface can show, and field rows must size themselves to their text instead of using a fixed height that clips a wrapped English label.

### Fixed
- When secure boot is refused by the firmware (6A86 / 6A82 / 6D00), the message now also explains that this usually means the firmware does not accept the command rather than that a parameter was wrong, so an irreversible action is not retried blindly.
- Symbols the bundled font cannot draw (some arrows, ticks, crosses and warning marks) were replaced with forms that render; they previously appeared as empty boxes on the phone.

### Changed
- The bundled CJK font was re-subset to the characters the interface actually uses: 6890 glyphs down to 850, 2.12 MB down to 0.20 MB, cutting the assets shipped inside the APK by roughly 90%.

## [v0.3.1] - 2026-10-04

### Added
- Direct UF2 write: an RP2040 / RP2350 in BOOTSEL mode is a USB mass-storage
  device, so the image is now written over Bulk-Only Transport instead of
  relying on the phone mounting that little drive. When the phone did mount it,
  the simpler plain file copy is used instead
- The web page can write a UF2 the same way. A browser may protect mass storage
  and refuse to claim the interface; that is then stated plainly and the Android
  app is suggested, rather than surfacing as an opaque error
- The board reboots on the final block and never replies to it; that now counts
  as success instead of being reported as a failure

### Fixed
- The secure boot / secure lock screen described INS 1D while the code actually
  sends INS 1C with P1=02. On an irreversible operation that mismatch is a real
  hazard, so the text now matches what is sent

## [v0.3.0] - 2026-10-02

The `uv-config` branch is merged into the main line; the two version sequences
are now one.

### Added

- **User-verification policy (authenticatorConfig, CTAP 0x0D)** — a new section
  on the device screen. Enter the device's FIDO2 PIN to:
  - **Toggle alwaysUv**: the switch between "PIN every time" and "just press the
    button". With alwaysUv on, every registration requires user verification,
    the platform satisfies it with the PIN and the physical button never takes
    part; once off, makeCredUvNotRqd can be true and non-resident credentials
    may be created with a button press alone
  - **Set the minimum PIN length**: can only be raised, never revoked (going back
    requires an authenticator reset, which deletes every credential)
- Current alwaysUv / makeCredUvNotRqd / clientPin state, read from getInfo
- Cryptography implemented here (P-256 ECDH, AES-256-CBC, HMAC-SHA-256) — no
  `cryptography` dependency
- **Persistent log**: every line is written to a file and flushed immediately, so
  it survives a crash; uncaught exceptions (including on worker threads) are
  written too. The previous run is kept as `.1`
- "Erase whole flash before writing" is now an option when flashing

### Fixed

- **The chip was never reset after flashing.** The FLASH_END argument is
  backwards (0 reboots, 1 stays in the bootloader) and the code always sent 1, so a
  freshly flashed board sat in download mode: no LED (the LED is driven by
  firmware) and a single USB interface — indistinguishable from a failed write.
  Now it reboots by default; with several files, only after the last one
- Crashed after removing a row from the multi-file list: the callback captured a
  row index that went out of range once the rows were renumbered
- The self-test now reports its environment first, so a failure in a built app
  can be told apart from one in source

### Notes

- Only PIN/UV auth protocol 1; FIDO HID channel only (buttons are disabled on
  CCID); not offered on the web page (CTAP runs over HID, which browsers block)

---

## [v0.2.3] - 2026-09-27

### Added

- **Multi-image flashing with per-file offsets**: an ESP32-S3 needs its bootloader,
  partition table and firmware at three different addresses. Files can now be added
  one by one with their own offset and written in a single run, with offsets
  filled in automatically from the file names
- **Full chip erase (ESP32)**: the recovery step when the firmware will not start —
  re-flashing alone leaves whatever stopped it booting still in flash

### Fixed

- Flashing and erasing read the previous command's overdue reply ("got op 0D,
  wanted D0"): the ROM banner was not cleared after sync, `flash()` and
  `erase_flash()` had drifted apart, and a timeout was treated as "never ran"
- The self-test aborted on its first failure, so one run could only reveal one
  problem; failures are now collected and listed together
- "ERASE_FLASH went out 2 times" with no clue why: the guard lives in
  `flasher.py`, so a missing file now says so instead of looking like a test bug
- Overlapping text: scan status, device info and channel buttons used fixed
  heights that cropped long strings; heights now follow the text
- Signature-mismatch warnings read like a build failure: they are notes now, and
  the APK is re-read after re-signing to confirm it actually took effect
- App and web page disagreed about the same board: both now use identical
  handshake checks (direction, opcode, length, and two consecutive successes),
  and scanning performs a real handshake before listing a device
- Secure-boot confirmation only appeared in the log: a confirmation dialog now
  precedes the write, naming the slot and whether the lock is permanent
- No guidance when only the rescue channel is found: recovery steps are shown,
  with a note that the ESP32 ROM download mode cannot be bricked
- Every build had a different signature: the key was PKCS12 while Gradle reads
  debug keys as JKS, and silently regenerated one when it could not read ours

### Changed

- The channel hint now cites upstream: firmware 7.4 and later can only change
  hardware configuration over rescue / PCSC

## [v0.2.2] - 2026-09-27

### Fixed

- Short CCID frames raised "not enough values to unpack": length is checked
  before parsing, with a readable error
- A response without SW bytes no longer invents a status word from stray bytes
- Extra bytes at the end of a CCID frame corrupted the next exchange: trimmed
  to `dwLength`
- The WINK error said the opposite of the truth: on the CCID channel it claimed
  "this is the FIDO HID channel"
- ESP32 flashing "response mismatch": clear and resync on an overdue reply, then
  retry once; if it still fails, both opcodes are reported
- Expected failures no longer print a stack trace: channel mismatches show one line
- The app hung while the device waited for a touch: KEEPALIVE restarted the timer
  on every read, so it never timed out. One deadline now covers the whole exchange,
  and CTAPHID_CANCEL is sent on timeout
- CTAPHID_ERROR reported only `0xBF`, dropping the one byte that explains it
- Response frames were not checked against the channel ID
- INIT did not verify the echoed nonce, so another device's CID could be adopted
- No indication while waiting for a touch: now shows "touch the button on the board"
- CCID frame checks relied on `assert`, which Python removes under `-O`

### Changed

- Status words carry a readable explanation, e.g. `SW:6A86 — incorrect P1 or P2`
- "Cannot open device" now lists what to check: permission prompt, another app
  holding the device, how to revoke the grant

## [v0.2.1] - 2026-09-26

### Fixed

- No firmware files could be picked: switched to the system file manager (SAF);
  the built-in browser was limited by scoped storage
- The web tool became an ESP32-S2/S3 flasher, and the CCID configuration it could
  never use (browsers block CCID) was removed
- Release assets are APK-only: the page is served by Pages, two copies drift apart,
  and WebUSB silently fails over `file://`
- "Failed to read the chosen file": reads through a file descriptor instead of a
  Java byte array, and shows the actual reason
- No way to tell whether user presence (the physical button) works: a "test user
  presence" button now sends CTAP_SELECTION and times the reply
- Device info did not show UP state: a "User presence (UP)" row was added
- The confirm-button GPIO field had no explanation: added — most Pico boards ship
  with only BOOTSEL
- No way to confirm the signature actually applied: the APK certificate is read
  back and compared after the build
- The log area went blank: updating a Kivy property from a worker thread corrupts
  the label's texture; log lines are queued and appended on the main thread
- Reading secure boot raised IndexError on an empty response: reports "not
  reported" instead
- An empty log was indistinguishable from a broken one: empty now says so

### Changed

- Removed fetching firmware from GitHub or a URL, and dropped the `INTERNET`
  permission

## [v0.2.0] - 2026-09-26

### Added

- **Firmware page**: UF2 (RP2040/RP2350) detection and the ESP32 ROM serial
  download protocol, with automatic format and chip detection
- `CHANGELOG.md`; release notes are now generated
- The version can be advanced by the workflow — no need to edit `buildozer.spec`
- Fetch official firmware from GitHub, grouped by chip, newest stable only
- Builds use a pinned signing key, so upgrades install over the previous version
- Concurrency control: re-running the workflow cancels the in-flight job
- Documentation covering the differences between RP2040 / RP2350 / ESP32-S2 / S3

### Fixed

- The status bar covered the top of the screen
- Long English button labels were clipped (button height follows wrapped text)
- Tapping "scan" on the firmware page crashed the app

### Changed

- Firmware page reordered into "1. Pick the board / 2. Pick the firmware / 3. Write"
- Dropped the specific button gesture for download mode (it differs per board)
- The UI no longer calls the board a PicoKey
- Releases refused to overwrite an existing tag by default

## [v0.1.0] - 2026-09-25

First release.

- USB OTG connection, three-channel scan (CCID / rescue / FIDO HID)
- Device information, PHY configuration read/write, secure boot
- Reboot and flashing mode, WINK
- Protocol self-test that needs no hardware
- Bilingual UI with a bundled CJK font
