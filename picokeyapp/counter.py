"""
Signature counter (signCount) sampling for resident FIDO2 credentials.

Why a "read" needs a real assertion
-----------------------------------
CTAP2 deliberately has no command to ask an authenticator for its current
signature counter. The counter only ever appears in the authenticatorData of
an authenticatorGetAssertion response (bytes 33..36, big endian). So the only
honest way to report it is to run one assertion and read the number out of the
reply. That has two consequences the UI states plainly:

  * the counter advances by one for the credential that answered;
  * the device may ask for a PIN and, on some firmware, a physical touch.

This module never hides that. It also keeps a local history keyed by the
credential ID, because a single number means nothing: a counter *going
backwards* between two samples is the signal that matters (firmware state
rolled back, flash restored from a snapshot, or a cloned key). A server
remembers the last counter it saw and rejects a smaller one, which is exactly
the failure mode this screen was added to diagnose.

Nothing here writes to the authenticator. The only device-side effect is the
counter increment that any genuine assertion would cause anyway.
"""

from __future__ import annotations

import hashlib
import json
import os
import struct
import time

from . import cbor_mini, ctapcfg
from .ctap import CTAP2_OK
from .uvcrypto import protocol1_authenticate

CTAP2_GET_ASSERTION = 0x02
# CTAP2.1 pinUvAuthToken permissions: 0x01=mc 0x02=ga 0x04=cm
# 0x08=be 0x10=lbw 0x20=acfg. Asking for the wrong bit is the usual reason
# getAssertion comes back with PIN_AUTH_INVALID / unauthorized permission.
PERMISSION_GA = 0x02
PROTOCOL_ONE = 1

# A stable, meaningless clientDataHash. We are not authenticating to a relying
# party here, only asking the authenticator to produce authenticatorData; any
# 32 bytes work, and a fixed one keeps the request reproducible in the log.
_CLIENT_DATA_HASH = hashlib.sha256(
    b"picokey-manager/sign-counter-sample/v1").digest()


class CounterError(Exception):
    """An expected failure: wrong channel, wrong PIN, no matching credential."""


def sign_count_from_authdata(auth_data) -> int:
    """Extract the 4-byte signature counter from authenticatorData.

    Layout: 32 bytes rpIdHash | 1 byte flags | 4 bytes signCount | ...
    Extensions/attested data follow and are irrelevant here.
    """
    raw = bytes(auth_data or b"")
    if len(raw) < 37:
        raise CounterError(
            "authenticatorData is too short (%d bytes, need 37)" % len(raw))
    return struct.unpack(">I", raw[33:37])[0]


def _ordered(pairs) -> dict:
    """The firmware rejects CBOR maps whose keys are not in ascending order."""
    return dict(sorted(pairs, key=lambda kv: kv[0]))


class CounterReader:
    """One getAssertion against a FIDO HID transport."""

    def __init__(self, transport):
        self.hid = transport
        self._uv = ctapcfg.UvConfig(transport)

    def sample(self, rp_id: str, pin: str, cred_id: bytes = None,
               on_keepalive=None) -> dict:
        """Return the credential that answered and its current signCount.

        `cred_id` is optional. Without it the authenticator picks the first
        discoverable credential for `rp_id`, which is enough to see the counter
        and avoids needing credential-management permission as well.
        """
        rp_id = (rp_id or "").strip()
        if not rp_id:
            raise CounterError("an RP ID is required")
        if not pin:
            raise CounterError("a PIN is required")

        try:
            token = self._uv.obtain_token(pin, PERMISSION_GA)
        except ctapcfg.ConfigError as exc:
            # A wrong PIN must read as a refusal, not as an unhandled crash.
            raise CounterError(str(exc)) from exc

        req = [
            (1, rp_id),
            (2, _CLIENT_DATA_HASH),
        ]
        if cred_id:
            req.append((3, [{"type": "public-key", "id": bytes(cred_id)}]))
        # up=false asks for a silent assertion (no button press). Some firmware
        # still sends KEEPALIVE(UPNEEDED); the caller surfaces that as a hint.
        req.append((5, {"up": False, "uv": True}))
        req.append((6, protocol1_authenticate(token, _CLIENT_DATA_HASH)))
        req.append((7, PROTOCOL_ONE))

        try:
            status, data = self.hid.cbor(
                CTAP2_GET_ASSERTION, cbor_mini.dumps(_ordered(req)),
                timeout=30000, on_keepalive=on_keepalive)
        except Exception as exc:
            raise CounterError(str(exc)) from exc
        if status != CTAP2_OK:
            raise CounterError("getAssertion refused: %s (0x%02X)" %
                               (ctapcfg.status_text(status), status))
        try:
            resp = cbor_mini.loads(data)
        except cbor_mini.CBORError as exc:
            raise CounterError("getAssertion returned unreadable CBOR: %s" % exc)
        if not isinstance(resp, dict):
            raise CounterError("getAssertion did not return a CBOR map")

        auth_data = resp.get(2)
        count = sign_count_from_authdata(auth_data)
        cred = resp.get(1) or {}
        cid = cred.get("id") if isinstance(cred, dict) else None
        user = resp.get(4) or {}
        return {
            "rp_id": rp_id,
            "cred_id": bytes(cid).hex() if isinstance(cid, (bytes, bytearray)) else "",
            "sign_count": count,
            "user_name": (user.get("name") if isinstance(user, dict) else "") or "",
            "number_of_credentials": resp.get(5),
        }


class CounterStore:
    """Local sample history, so a rollback can be detected across two runs."""

    def __init__(self, path: str = None):
        # path=None is an in-memory store, used by the self-test where there
        # may be no writable directory at all.
        self.path = path
        self._data = {}
        self._load()

    def _load(self):
        if not self.path:
            return
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                obj = json.load(fh)
            if isinstance(obj, dict):
                self._data = obj.get("credentials", {}) if isinstance(
                    obj.get("credentials"), dict) else obj
        except Exception:
            self._data = {}

    def _save(self):
        if not self.path:
            return
        try:
            folder = os.path.dirname(self.path)
            if folder:
                os.makedirs(folder, exist_ok=True)
            with open(self.path, "w", encoding="utf-8") as fh:
                json.dump({"version": 1, "credentials": self._data}, fh,
                          ensure_ascii=False, indent=2)
        except Exception:
            # Losing history is annoying, not fatal: the live sample still
            # reports the current counter.
            pass

    def record(self, entry: dict) -> dict:
        """Store one sample and describe how it compares with the last one."""
        key = entry.get("cred_id") or ("rp:" + entry.get("rp_id", ""))
        now = int(entry["sign_count"])
        prev = self._data.get(key, {})
        last = prev.get("last")
        high = prev.get("max", 0) or 0
        samples = list(prev.get("samples") or [])

        regression = isinstance(last, int) and last > 0 and now <= last
        unused = now == 0 and (not isinstance(last, int) or last == 0)
        delta = now - last if isinstance(last, int) else None

        samples.append({"at": int(time.time()), "n": now})
        self._data[key] = {
            "rp_id": entry.get("rp_id", ""),
            "user_name": entry.get("user_name", ""),
            "last": now,
            "max": max(high, now),
            "samples": samples[-20:],
        }
        self._save()

        out = dict(entry)
        out.update({
            "key": key,
            "previous": last,
            "max": max(high, now),
            "delta": delta,
            "regression": regression,
            "counter_unused": unused,
            "sample_count": len(samples),
        })
        return out

    def summary(self) -> list:
        """All tracked credentials, newest sample first."""
        rows = []
        for key, item in self._data.items():
            if not isinstance(item, dict):
                continue
            rows.append({
                "key": key,
                "rp_id": item.get("rp_id", ""),
                "user_name": item.get("user_name", ""),
                "last": item.get("last"),
                "max": item.get("max"),
                "samples": item.get("samples") or [],
            })
        rows.sort(key=lambda r: (r["samples"][-1]["at"] if r["samples"] else 0),
                  reverse=True)
        return rows

    def clear(self):
        self._data = {}
        self._save()
