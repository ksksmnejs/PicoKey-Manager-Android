# Changelog (UV config branch)

This belongs to the `uv-config` branch alone and is deliberately separate from
the main `CHANGELOG.md`.

They cannot share one file: the main CI reads the version from `CHANGELOG.md`
and this branch's CI reads it from here, so a shared file would have each
branch overwrite the other's version on every build.

This branch therefore starts at **0.3.0** (main was at 0.2.3) so the tags never
collide.

Format is the same as main:

```markdown
## [vX.Y.Z] - YYYY-MM-DD

### Added
- something
```

---

## [v0.3.0] - 2026-10-02

### Added

- **User verification policy (authenticatorConfig, CTAP 0x0D)** — a new section
  on the device page which, once the device's FIDO2 PIN is entered, can:
  - **Toggle alwaysUv** — the switch between "PIN every time" and "just press the
    button". With alwaysUv on, every registration needs user verification and the
    platform satisfies it with the PIN, so the physical button is never consulted.
    Turning it off is what allows makeCredUvNotRqd to become true, after which a
    non-discoverable credential can be created on a button press alone
  - **Set the minimum PIN length** — it can only increase. Lowering it again needs
    a full authenticator reset, which deletes every credential
- Shows the current alwaysUv / makeCredUvNotRqd / clientPin state, read from
  getInfo at connect time
- All crypto is implemented here (P-256 ECDH, AES-256-CBC, HMAC-SHA-256) with
  **no cryptography dependency** — adding it would make every CI build compile a
  Rust toolchain, raising both build time and failure rate

### Notes

- Only PIN/UV auth protocol 1 is supported. Getting protocol 2's key schedule
  wrong fails in a way that is indistinguishable from a wrong PIN, which is not
  acceptable without hardware to verify against
- FIDO HID channel only; both buttons are greyed out on CCID
- The **web page does not get this feature**: CTAP runs over HID (class 0x03) and
  Chrome's protected-interface list blocks HID, so the page cannot reach the FIDO
  channel at all
