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

## [v0.2.3] - 2026-09-27

### Fixed

- **Text overlapping**: the scan-page status, the device summary and the channel
  buttons all used fixed heights, so long strings (the "found a serial device but
  it did not answer the handshake" hint, for one) were clipped and the wrapped
  remainder was drawn straight over the widgets below. Heights now follow the text

- **The signature-conflict warning read like a failed build**: when a mismatch was
  found the wording was indistinguishable from a real failure, even though the next
  step re-signs and fixes it. Those messages are now notices saying plainly that it
  is corrected below and is not a failed build. On top of that the APK is read back
  once more after re-signing to confirm it took effect - otherwise a silently failed
  re-sign would publish an APK that does not install. The keystore is also
  re-checked immediately before Gradle runs, with its fingerprint printed, so it is
  possible to tell which step replaced it

- **The app and the web tool disagreed about the same board**: the two are separate
  implementations and used different rules - the app accepted any frame whose first
  byte was 0x01, while an ESP32-S3 prints to USB Serial/JTAG whether or not its
  firmware is running, so a live firmware was taken for a ready bootloader and the
  app said "done" exactly where the web tool said "sync failed".
  Both sides now use the same check (direction, opcode, length, and two consecutive
  successes), and the scan performs a real handshake before offering a device

- **The secure-boot confirmation only existed in the log**: the only gate before
  burning OTP/eFuse was a checkbox on a crowded screen, and the warning was printed
  to the log *after* the write - too late, and invisible unless you went looking.
  Tapping the button now opens a dialog naming the slot and whether it locks, and
  the write only runs after CONFIRM is typed

- **No explanation when only the rescue channel was found**: firmware that fails to
  start exposes just the rescue interface (and usually a dark LED), which looks like
  a dead board. The scan page now spells out the recovery steps and says plainly
  that the ESP32 ROM download mode cannot be bricked

- **The APK was not signed with our key (every build got a new signature)**: the debug
  key in the repo was a PKCS12 container (keytool's default since JDK 9), but Gradle
  reads the debug keystore as JKS - when it cannot load the file it silently deletes it
  and generates a fresh one, so every build came out with a different signature and
  phones reported a "signature conflict". The key is now normalised to JKS when
  installed (a container change only - **the certificate and its fingerprint are
  unchanged**, so nobody has to uninstall), and on top of that: if the finished APK
  turns out to carry a foreign signature, it is re-signed with apksigner instead of
  being published as something that will not install

- **Secure boot / secure lock could never be enabled (wrong instruction)**: the app sent
  `INS 1C P1=02` with a two-byte body, but in the rescue applet's table `1C` means "write
  object N" and **P1 is the object number** - `P1=01` is the PHY config, which is why the
  LED settings did take effect, while `P1=02` asks the device to write an object that does
  not exist, hence 6A86. Reading the state with `1E P1=03` failed for the same reason:
  there is no object 3. The real command is **`INS 1D`**, with the bootkey slot in P1 and
  the lock flag in P2 and **no data**. Corrected

- **New "Diagnose: list readable objects"**: scans P1 with the read-only `INS 1E` and lists
  which objects actually exist (`P1=01` is the PHY, `P1=02` the flash). A read has no side
  effect, so the device can tell you whether it supports secure boot instead of us guessing.
  `1C`/`1D` are never used to probe - those write, and `1D` burns the eFuse

- **The app crashed on launch**: main.py imported `SecureBootError` from `picokeyapp.pk`
  (the package `__init__.py`), which is a separate file that has to be uploaded alongside
  it. Uploading main.py without that file raises ImportError at module load, so the app
  exits before a single widget exists - it just closes, with nothing to go on. The import
  now goes straight to PicoKey.py where the class is defined, with a local fallback
  definition, so the app starts no matter which subset of files is in sync

- **A startup failure no longer looks like a crash**: build() now catches exceptions and
  shows an error screen carrying the full traceback instead of letting the process exit
  before any window appears. Any future startup problem is readable on screen

- **"Could not read the signing certificate from the APK" was the checker's own bug**:
  apksigner prints `SHA-1 digest` but the script only matched `SHA1`, so a successful
  apksigner run still yielded nothing; and an APK carrying only a v2/v3 signature has no
  META-INF certificate for the fallback to read. Three readers are now tried in order
  (apksigner, then keytool -jarfile, then unpacking the v1 certificate with python3),
  both spellings match, and the log says which one worked. When none does, the message
  states plainly that this is a limitation of the check, not evidence of bad signing

- **A wrong-channel tap could only be caught after the fact**: PHY, secure boot and reboot
  need the CCID channel, WINK and the presence test need FIDO HID, yet every button stayed
  tappable. Tapping the wrong one reported "needs CCID, you are on HID" with a stack trace
  behind it, which reads like a crash. Buttons that cannot work on the current channel are
  now greyed out, and the page says which ones work and that switching happens on the scan
  page

- Firmware flashing failures (FirmwareError), CTAP errors, a refused secure-boot write and
  bad numeric input no longer print a stack trace — their messages already say what to do

- **The "confirm button does nothing" verdict was misleading**: the test answers instantly and
  the old message flatly blamed user presence for not being enabled. Two different things are
  actually going on: with a PIN, the firmware skips the button on purpose (by design, no PHY
  change can force it), while this test carries no PIN, so an instant answer really does mean
  the button GPIO is wrong. Both are now stated separately, along with "BOOT is usually GPIO0"
  and "a reboot is required after writing"

- **The LED settings carried no hint, so a wrong value was undiagnosable**: the driver has to
  match the hardware, and choosing PICO for an addressable LED leaves it dark entirely (a plain
  GPIO cannot produce the 800 kHz timing). A hint was added, including a reminder to enter the
  real pin number rather than Arduino's virtual RGB_BUILTIN value of 97

- **A refused secure-boot write was reported as success**: the write ignored the returned status
  word entirely, so a board answering 6A86 was still reported as done. For an irreversible
  OTP/eFuse burn that is the worst possible answer — it invites blind retries and hides that
  nothing happened. The status word now names the cause (6A86 unsupported parameters / 6A82 not
  implemented / 6982 not verified / 6D00 unsupported INS) and says plainly that nothing was
  written, without a stack trace

- **The secure-boot instruction was wrong (introduced in the previous build)**: it had been
  changed from `1C P1=02` to `0x1D`, based on a documentation mirror rather than source.
  Checked against upstream pypicokey (`picokey/PicoKey.py`), `0x1D` does not exist there at
  all — secure boot is `1C P1=02` with a two-byte body `[slot, lock flag]`. The 6A86 seen
  earlier was therefore misread as "the object does not exist"; the device genuinely refuses,
  for a reason that is still open. Restored to upstream's form, and the self-test now pins the
  whole command table statically so it cannot be "fixed" from memory again

### Added

- **Erase whole flash (ESP32)**: when the firmware will not start, re-flashing it is
  not enough — whatever stopped it booting is still in flash, so the board comes
  back up in the same state. A recovery section on the firmware page now offers a
  full-chip erase, and the web tool gained the same as section 4. Both ask first

- **The secure lock consequence is now stated**: upstream documents that enabling it is not
  merely "signed firmware only" — it also invalidates every key except the official Pico Key
  one, after which only officially signed firmware is recognised and compiling or flashing
  your own builds becomes impossible. That consequence was never mentioned before; it is now
  in the confirmation dialog


- **The channel hint now cites upstream**: not being able to change the PHY over the FIDO HID channel is not an app limitation — upstream PicoForge documents that only firmware 7.0/7.2 has the legacy FIDO-only configuration path, while 7.4 and later (including your 8.0) require rescue / PCSC mode.

## [v0.2.2] - 2026-09-27

### Fixed

- **Short CCID frames reported "not enough values to unpack"**: the length is
  checked before parsing, so you now get `truncated CCID response: got N byte(s),
  need at least 10`
- **A response with no SW bytes no longer invents a status word**: too-short
  frames raise, instead of reading SW1/SW2 out of whatever was in the buffer
- **Stray bytes past the end of a CCID frame poisoned the next exchange**: the
  buffer is trimmed to dwLength
- **WINK's error message said the opposite of the truth**: tapping WINK on the
  CCID channel claimed you were on the FIDO HID one. It now says which channel
  WINK needs and which one you are on
- **ESP32 flashing "unexpected response"**: a late reply to the previous command
  now triggers one drain-and-retry; if it still mismatches, both the received
  and the expected op are reported
- **Expected failures no longer print a stack trace**: explainable errors such as
  a wrong channel show one line, not a dozen frames

### Changed

- Status words carry a readable explanation, e.g. `SW:6A86 — incorrect P1/P2`
- "Cannot open the device" now includes what to check (permission dialog,
  another app holding it, how to revoke the grant)

- **The app hung whenever the device was waiting for a touch**: every CTAPHID
  KEEPALIVE restarted the read timeout, so a device sending them regularly never
  timed out. The whole exchange now shares one deadline, and running out of time
  also sends CTAPHID_CANCEL so the authenticator stops waiting for a touch that
  will never come
- **CTAPHID_ERROR only said "unexpected response command 0xBF"**, discarding the
  one byte that explains the problem. Real codes are now decoded, e.g.
  `CTAPHID error 0x06 (CHANNEL_BUSY)`
- **Response frames were not checked for their channel**: a frame from another
  device on the bus, or left over from an earlier session, was accepted as the
  answer to the current command. Both INIT and continuation packets now check CID
- **INIT did not verify the echoed nonce**, so a channel allocated by a different
  device could be adopted and every later command would fail
- **Nothing was shown while waiting for a touch**: KEEPALIVE status was dropped.
  The UI now says "Touch the button on the board"
- **CCID frame checks relied on `assert`**: Python strips asserts under `-O`, so
  after packaging the sequence-number check (and others) would silently stop
  working and an out-of-order response could be read as valid. Now explicit

## [v0.2.1] - 2026-09-26

### Fixed

- **Could not find firmware files**: now uses the Android system file manager
  (Storage Access Framework). The app's own directory browser was limited by
  scoped storage and listed only a few third-party app folders, so firmware
  stored anywhere else was invisible
- **Web tool is now an ESP32-S2 / S3 firmware flasher**: implements the esptool
  ROM protocol (SLIP framing + FLASH_BEGIN/DATA/END) with no flasher stub uploaded.
  The old CCID configuration features are gone - browsers block CCID, so they
  could never have worked
- The page now states the CCID restriction up front; secure boot / secure lock are
  marked unavailable with a pointer to the Android app; both READMEs spell out what
  the page can and cannot do
- Release assets are APK-only now; `picokey-commissioner.html` is no longer attached.
  Pages serves the web tool, two copies drift apart, and opening the downloaded file
  over `file://` makes WebUSB fail silently
- Fixed "could not read the selected file": reads via a file descriptor now,
  no longer relying on Java byte arrays; failures show the actual reason

- **No way to tell whether user presence (the physical press) is actually
  enforced**: the device screen gains **"Test user presence (button)"**, which
  sends CTAP_SELECTION and times it. An instant answer means the device never
  waited for a press; an answer that arrives after a pause means it genuinely is
- **The UP state was invisible**: added a "User presence (UP)" line reading
  `options.up` from getInfo. When the device does not report it, the text points
  at the test button instead of showing a meaningless "not reported"
- **The "Confirm button GPIO" field had no explanation**: it now says that most
  Pico boards ship with nothing but BOOTSEL, and that with no button soldered —
  or a GPIO that does not match the wiring — a PIN alone is enough and no touch
  is requested
- **Nothing was shown while waiting for a press** (the presence test reuses
  this): the CTAPHID KEEPALIVE callback now drives "Touch the button on the
  board"

- **No way to confirm the signing key was actually used**: the build now reads
  the certificate back out of the finished APK and compares it with the
  installed key. A mismatch warns that Gradle used a different key — so every
  build gets a different signature and phones report a signature conflict —
  instead of leaving you to discover it at install time

- **The log area went blank**: half of the `log()` calls happen on a background
  worker thread, but they assign to a Kivy property. Updating it off-thread
  corrupts the Label's texture — the symptom is not a crash but a black
  rectangle where the log should be. Lines are now queued and appended from
  the main thread
- **Reading secure boot raised IndexError**: an unsupported device answers with
  an empty body, yet the code indexed `resp[0..2]` unconditionally. It now
  reports "not reported" with a reason instead of throwing a traceback
- **An empty log was indistinguishable from a broken one**: a hint line is
  shown while there is nothing logged yet

### Changed

- **Removed firmware fetching from GitHub / URL** - the `INTERNET` permission is
  gone and the app makes no network requests at all; firmware is now picked from
  local storage with the system file manager

## [v0.2.0] - 2026-09-26

### Added

- **Flash firmware page** - UF2 sniffing (RP2040/RP2350) plus the ESP32 ROM
  serial download protocol; firmware can come from a local file or an https
  URL, and the format and target chip are detected on load
- Docs now cover the differences between RP2040 / RP2350 / ESP32-S2 / S3
- Added `CHANGELOG.md`; release notes are now generated from it
- Version can be advanced automatically: add a new CHANGELOG section and
  `buildozer.spec` is updated for you
- **Official firmware from GitHub**: new entry on the firmware page that lists
  release assets from the upstream open-source `polhenarejos/pico-fido` repo,
  grouped by chip with only the newest stable image per board, and downloads
  the one you pick (needs the `INTERNET` permission)
- The board is no longer called "PicoKey" - it is a "board" / "development board"
- Builds use a fixed signing key (`tools/debug.keystore.b64`), so updating the
  APK installs over the old one instead of demanding an uninstall; override it
  with the repository secret `ANDROID_KEYSTORE_BASE64`
- Added concurrency control: pressing Run workflow again cancels the in-progress
  run instead of piling up a queue
- Docs and UI no longer describe button gestures for entering download mode
  (they differ per board)

### Fixed

- Status bar covering the top row (the real system status-bar height is now
  read and applied as a top inset)
- Long English button labels being clipped (button height now follows the
  wrapped text height)
- Crash when tapping **Scan** on the firmware page (an exception in the success
  callback now shows an error instead of killing the app)

### Changed

- Firmware page restructured into "1. Pick the board / 2. Pick the firmware /
  3. Write"
- Removed the concrete button gestures for entering flashing mode - they differ
  per board, so hardcoding them misleads. The UI now just says to consult the
  board's own documentation
- Publishing now refuses to overwrite an existing tag by default, preserving
  earlier versions

## [v0.1.0] - 2026-09-25

First release.

- USB OTG connection, three-channel scan (CCID / rescue / FIDO HID)
- Device information, PHY configuration read/write, secure boot
- Reboot and flashing mode, WINK
- Protocol self-test that needs no hardware
- Bilingual UI with a bundled CJK font
