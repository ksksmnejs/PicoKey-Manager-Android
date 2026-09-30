"""
Android port of the pypicokey core (AGPL-3.0-or-later, (c) 2025 Pol Henarejos).

Only the pure-Python layers are kept; everything that touched PC/SC (pyscard)
or libusb (pyusb) is replaced by the transports in picokeyapp.ccid /
picokeyapp.ctap, which talk to the Android USB Host API through pyjnius.
"""

from ._version import __version__
from .PicoKey import PicoKey, Platform, Product, ConnectionType, SecureBootError
from .APDU import APDUResponse
from .SWCodes import SWCodes
from .PhyData import PhyData, PhyCurve, PhyUsbItf, PhyLedDriver, PhyOpt
from .core.exceptions import PicoKeyError, PicoKeyNotFoundError, PicoKeyInvalidStateError

try:
    from .SecureChannel import SecureChannel
except Exception:
    SecureChannel = None

__all__ = [
    "__version__", "PicoKey", "Platform", "Product", "ConnectionType",
    "APDUResponse", "SWCodes", "PhyData", "PhyCurve", "PhyUsbItf",
    "PhyLedDriver", "PhyOpt", "SecureChannel",
    "PicoKeyError", "PicoKeyNotFoundError", "PicoKeyInvalidStateError",
    "SecureBootError",
]
