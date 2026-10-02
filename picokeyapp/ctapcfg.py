"""authenticatorConfig (CTAP 0x0D) - alwaysUv and the PIN policy.

This is the piece that turns "why does my board never ask me to press the
button" into something you can act on. The chain is:

    alwaysUv = true  ->  makeCredUvNotRqd MUST be false  ->  every registration
                         needs user verification  ->  the platform satisfies
                         that with the PIN  ->  the button is never consulted
    alwaysUv = false ->  makeCredUvNotRqd may be true  ->  a non-discoverable
                         credential can be created on user presence alone

so toggling alwaysUv is not cosmetic: it is the switch between "PIN every time"
and "press the button".

Everything here needs a pinUvAuthToken carrying the authenticatorCfg
permission, which means a PIN. There is no way around that and it is the right
design - these are device-wide policy changes.

Requires the FIDO HID channel. None of this is reachable over CCID.
"""

from . import uvcrypto as U
from .cbor_mini import dumps, loads

# authenticatorClientPIN (0x06)
CMD_CLIENT_PIN = 0x06
PIN_SUB_GET_KEY_AGREEMENT = 0x02
PIN_SUB_GET_TOKEN_USING_PIN = 0x09     # ...WithPermissions

PIN_PARAM_PROTOCOL = 0x01
PIN_PARAM_SUBCOMMAND = 0x02
PIN_PARAM_KEY_AGREEMENT = 0x03
PIN_PARAM_PIN_HASH_ENC = 0x06
PIN_PARAM_PERMISSIONS = 0x07

PIN_RESP_KEY_AGREEMENT = 0x01
PIN_RESP_PIN_TOKEN = 0x02

# authenticatorConfig (0x0D)
CMD_CONFIG = 0x0D
CFG_SUB_TOGGLE_ALWAYS_UV = 0x02
CFG_SUB_SET_MIN_PIN_LENGTH = 0x03

CFG_PARAM_SUBCOMMAND = 0x01
CFG_PARAM_SUBCOMMAND_PARAMS = 0x02
CFG_PARAM_PROTOCOL = 0x03
CFG_PARAM_AUTH_PARAM = 0x04

# Token permissions (CTAP 2.1). We only ever ask for the one we need.
PERM_AUTHENTICATOR_CFG = 0x20

PROTOCOL_ONE = 1

# COSE_Key labels for an EC2 key on P-256.
COSE_KTY = 1
COSE_ALG = 3
COSE_CRV = -1
COSE_X = -2
COSE_Y = -3
COSE_KTY_EC2 = 2
COSE_ALG_ECDH_ES_HKDF256 = -25
COSE_CRV_P256 = 1

# CTAP2 status codes worth naming.
CTAP2_OK = 0x00


class ConfigError(Exception):
    """A config operation could not be completed, with a reason."""


# Human-readable status codes. Without this the user sees "0x33" and has
# nothing to act on; with it they see "the PIN was blocked".
STATUS_TEXT = {
    0x01: "invalid command",
    0x02: "invalid parameter",
    0x03: "invalid length",
    0x04: "invalid seq",
    0x05: "timeout",
    0x06: "channel busy",
    0x0A: "lock required",
    0x0B: "invalid channel",
    0x11: "CBOR unexpected type",
    0x12: "invalid CBOR",
    0x14: "missing parameter",
    0x15: "limit exceeded",
    0x16: "fingerprint database full",
    0x21: "operation denied",
    0x22: "key store full",
    0x23: "no operations",
    0x24: "no option to continue",
    0x25: "unsupported option",
    0x26: "unsupported algorithm",
    0x27: "operation pending",
    0x28: "invalid CBOR for user parameter",
    0x2A: "unsupported PIN/UV auth protocol",
    0x2B: "PIN/UV auth token required",
    0x2C: "PIN/UV auth param required",
    0x2D: "PIN/UV auth protocol not supported",
    0x2E: "PIN not set",
    0x2F: "PIN blocked",
    0x30: "PIN invalid",
    0x31: "PIN auth invalid",
    0x32: "PIN auth blocked",
    0x33: "PIN auth blocked - power cycle the authenticator",
    0x34: "PIN policy violation",
    0x35: "PIN token expired",
    0x36: "PIN/UV auth token required",
    0x37: "request too large",
    0x38: "action timeout",
    0x39: "user presence required",
    0x3A: "user verification blocked",
    0x3B: "integrity failure",
    0x3C: "invalid subcommand",
    0x3D: "user verification invalid",
    0x3E: "unauthorized permission",
    0x7F: "unspecified error",
}


def status_text(code: int) -> str:
    return STATUS_TEXT.get(code, "unknown status")


# ------------------------------------------------------------------ COSE keys

def encode_platform_pubkey(point) -> dict:
    """Our ephemeral public key as a COSE_Key map.

    Returned as a map, not as encoded bytes: it is nested inside the
    authenticatorClientPIN request, and pre-encoding it would make it a CBOR
    byte string wrapping a CBOR map - which the authenticator rejects.

    `alg` is ECDH-ES+HKDF-256 (-25) rather than ES256 (-7): this key is for key
    agreement, not signing, and the authenticator checks the label.
    """
    x, y = point
    return {
        COSE_KTY: COSE_KTY_EC2,
        COSE_ALG: COSE_ALG_ECDH_ES_HKDF256,
        COSE_CRV: COSE_CRV_P256,
        COSE_X: x.to_bytes(32, "big"),
        COSE_Y: y.to_bytes(32, "big"),
    }


def decode_device_pubkey(cose: dict):
    """Pull (x, y) out of the authenticator's COSE_Key, validating as we go.

    The point is checked to be on P-256 before it is used. Feeding an
    attacker-supplied off-curve point into ECDH is a textbook way to leak the
    private scalar, and this value arrives over USB.
    """
    if not isinstance(cose, dict):
        raise ConfigError("keyAgreement was not a CBOR map")
    if cose.get(COSE_KTY) != COSE_KTY_EC2:
        raise ConfigError("keyAgreement is not an EC2 key")
    if cose.get(COSE_CRV) != COSE_CRV_P256:
        raise ConfigError("keyAgreement is not on P-256")
    xb, yb = cose.get(COSE_X), cose.get(COSE_Y)
    if not isinstance(xb, (bytes, bytearray)) or len(xb) != 32:
        raise ConfigError("keyAgreement x is not 32 bytes")
    if not isinstance(yb, (bytes, bytearray)) or len(yb) != 32:
        raise ConfigError("keyAgreement y is not 32 bytes")
    return U.p256_point_from_bytes(int.from_bytes(xb, "big"),
                                   int.from_bytes(yb, "big"))


# ------------------------------------------------------------------ the flow

class UvConfig:
    """Obtain a PIN/UV auth token and use it for authenticatorConfig.

    One instance covers one session: the ECDH key is ephemeral and the token
    belongs to the connection it was fetched over.
    """

    def __init__(self, transport):
        self._t = transport
        self._secret = None
        self._token = None

    # -- step 1: key agreement -------------------------------------------

    def _get_key_agreement(self):
        req = dumps({PIN_PARAM_PROTOCOL: PROTOCOL_ONE,
                     PIN_PARAM_SUBCOMMAND: PIN_SUB_GET_KEY_AGREEMENT})
        status, data = self._t.cbor(CMD_CLIENT_PIN, req, timeout=5000)
        if status != CTAP2_OK:
            raise ConfigError(f"getKeyAgreement failed: {status_text(status)} "
                              f"(0x{status:02X})")
        resp = loads(data)
        if not isinstance(resp, dict) or PIN_RESP_KEY_AGREEMENT not in resp:
            raise ConfigError("getKeyAgreement returned no key")
        return decode_device_pubkey(resp[PIN_RESP_KEY_AGREEMENT])

    # -- step 2: exchange the PIN for a token ----------------------------

    def obtain_token(self, pin: str, permissions: int = PERM_AUTHENTICATOR_CFG):
        """Return a decrypted pinUvAuthToken, or raise with a reason.

        The shared secret is derived here and kept for later: the token comes
        back encrypted under it, and subsequent commands are authenticated
        under it too.
        """
        if not pin:
            raise ConfigError("a PIN is required")
        peer = self._get_key_agreement()

        priv, pub = U.p256_keypair()
        secret = U.protocol1_shared_secret(U.p256_ecdh(priv, peer))
        pin_hash_enc = U.protocol1_encrypt(secret, U.pin_hash(pin))

        req = dumps({
            PIN_PARAM_PROTOCOL: PROTOCOL_ONE,
            PIN_PARAM_SUBCOMMAND: PIN_SUB_GET_TOKEN_USING_PIN,
            PIN_PARAM_KEY_AGREEMENT: encode_platform_pubkey(pub),
            PIN_PARAM_PIN_HASH_ENC: pin_hash_enc,
            PIN_PARAM_PERMISSIONS: permissions,
        })
        status, data = self._t.cbor(CMD_CLIENT_PIN, req, timeout=10000)
        if status != CTAP2_OK:
            raise ConfigError(self._pin_error(status))
        resp = loads(data)
        if not isinstance(resp, dict) or PIN_RESP_PIN_TOKEN not in resp:
            raise ConfigError("no pinUvAuthToken in the response")

        enc = resp[PIN_RESP_PIN_TOKEN]
        if not isinstance(enc, (bytes, bytearray)) or len(enc) % 16:
            raise ConfigError("pinUvAuthToken is not a whole number of blocks")
        self._secret = secret
        self._token = U.protocol1_decrypt(secret, bytes(enc))
        return self._token

    def _pin_error(self, status: int) -> str:
        base = status_text(status)
        if status == 0x2E:
            return base + " — set a PIN on the authenticator first"
        if status == 0x2F:
            return base + " — too many wrong attempts; the authenticator needs a reset"
        if status == 0x31 or status == 0x35:
            return base + " — the PIN is wrong, or the session expired"
        if status == 0x33:
            return base + " — unplug the authenticator and plug it back in"
        return f"{base} (0x{status:02X})"

    # -- step 3: the config command itself -------------------------------

    def _config(self, subcommand: int, params=None) -> None:
        if self._token is None or self._secret is None:
            raise ConfigError("no PIN/UV auth token — call obtain_token() first")

        if params is None:
            body = bytes([subcommand])
            payload = b""
        else:
            payload = dumps(params)
            body = bytes([subcommand]) + payload

        auth_param = U.protocol1_authenticate(self._token,
                                              bytes([CMD_CONFIG]) + body)
        req = {
            CFG_PARAM_SUBCOMMAND: subcommand,
            CFG_PARAM_PROTOCOL: PROTOCOL_ONE,
            CFG_PARAM_AUTH_PARAM: auth_param,
        }
        if params is not None:
            req[CFG_PARAM_SUBCOMMAND_PARAMS] = params
        status, _ = self._t.cbor(CMD_CONFIG, dumps(req), timeout=10000)
        if status != CTAP2_OK:
            raise ConfigError(f"config failed: {status_text(status)} "
                              f"(0x{status:02X})")

    def toggle_always_uv(self) -> None:
        """Flip alwaysUv. Run it twice to get back where you started."""
        self._config(CFG_SUB_TOGGLE_ALWAYS_UV)

    def set_min_pin_length(self, new_length: int) -> None:
        """Raise the minimum PIN length. This cannot be undone.

        CTAP only allows the value to increase; lowering it again means a full
        authenticator reset, which wipes every credential. That is why the UI
        asks twice before getting here.
        """
        if not 4 <= new_length <= 63:
            raise ConfigError("the minimum PIN length must be between 4 and 63")
        self._config(CFG_SUB_SET_MIN_PIN_LENGTH, {0x01: int(new_length)})


def config_supported(info: dict) -> bool:
    """Whether this authenticator accepts authenticatorConfig at all.

    Guarded on `authnrCfg` rather than on the CTAP version string: an
    authenticator can speak 2.1 and still not implement the config command.
    """
    opts = info.get("options") or {}
    return bool(opts.get("authnrCfg"))


def summarise(info: dict) -> dict:
    """The handful of getInfo options this feature is about."""
    opts = info.get("options") or {}
    return {
        "alwaysUv": opts.get("alwaysUv"),
        "makeCredUvNotRqd": opts.get("makeCredUvNotRqd"),
        "clientPin": opts.get("clientPin"),
        "authnrCfg": opts.get("authnrCfg"),
        "setMinPINLength": opts.get("setMinPINLength"),
        "protocols": info.get("pinUvAuthProtocols") or [],
        "minPINLength": info.get("minPINLength"),
    }
