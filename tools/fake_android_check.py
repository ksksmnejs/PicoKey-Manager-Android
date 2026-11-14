"""
Desktop smoke test for the Android-only USB layer (picokeyapp/usbhost.py).

It installs a fake `jnius` module that mimics the Android USB Host API closely
enough (including the "bytearray is filled in place" semantics of bulk IN
transfers) to exercise the whole chain:

    enumerate_devices -> Connection.claim/IN/OUT -> CCIDTransport -> PicoKey
    ...and the same for the FIDO HID path (CTAPHIDTransport).

This does NOT prove that the real Android API behaves the same way - it proves
our frame handling, endpoint selection and state machine are consistent.

Run:  python3 tools/fake_android_check.py
"""

import os
import sys
import struct
import subprocess

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# --------------------------------------------------------------- fake Android

class FakeEndpoint:
    def __init__(self, address, type_, maxp=64, interval=1):
        self._address = address
        self._type = type_
        self._maxp = maxp
        self._interval = interval

    def getAddress(self):
        return self._address

    def getDirection(self):
        return 0x80 if self._address & 0x80 else 0

    def getType(self):
        return self._type

    def getMaxPacketSize(self):
        return self._maxp

    def getInterval(self):
        return self._interval

    def getEndpointNumber(self):
        return self._address & 0x0F


class FakeInterface:
    def __init__(self, iid, cls, subclass, protocol, endpoints):
        self._iid = iid
        self._cls = cls
        self._sub = subclass
        self._proto = protocol
        self._eps = endpoints

    def getId(self):
        return self._iid

    def getInterfaceClass(self):
        return self._cls

    def getInterfaceSubclass(self):
        return self._sub

    def getInterfaceProtocol(self):
        return self._proto

    def getEndpointCount(self):
        return len(self._eps)

    def getEndpoint(self, i):
        return self._eps[i]


class FakeUsbDevice:
    def __init__(self, vid, pid, interfaces, manufacturer="Pol Henarejos",
                 product="PicoKey"):
        self._vid, self._pid = vid, pid
        self._intfs = interfaces
        self._manufacturer, self._product = manufacturer, product
        self.backend = None                      # set by the test

    def getDeviceId(self):
        return 1001

    def getVendorId(self):
        return self._vid

    def getProductId(self):
        return self._pid

    def getManufacturerName(self):
        return self._manufacturer

    def getProductName(self):
        return self._product

    def getSerialNumber(self):
        return "000000000000"

    def getInterfaceCount(self):
        return len(self._intfs)

    def getInterface(self, i):
        return self._intfs[i]


class FakeConnection:
    def __init__(self, device):
        self._device = device
        self._claimed = set()
        self.out = []
        self._rx = bytearray()

    def claimInterface(self, intf, force):
        if not force:
            return False
        self._claimed.add(intf.getId())
        return True

    def releaseInterface(self, intf):
        self._claimed.discard(intf.getId())

    def close(self):
        self._claimed.clear()

    # Java semantics: OUT -> return byte count, IN -> fill `buffer` in place
    def bulkTransfer(self, ep, buffer, length, timeout):
        addr = ep.getAddress()
        if addr & 0x80:                                  # IN
            if not self._rx:                             # lazy: serve last reply
                pass
            data = bytes(self._rx[:length])
            del self._rx[:len(data)]                     # served in 64B chunks
            for i, b in enumerate(data):                 # pyjnius copies back
                buffer[i] = b
            return len(data)
        packet = bytes(buffer[:length])
        self.out.append(packet)
        # a device answers when a complete request has arrived; CTAPHID CONT
        # packets yield no reply of their own
        reply = self._device.backend(packet)
        if reply:
            self._rx += bytearray(reply)
        return length

    def controlTransfer(self, request_type, request, value, index, buffer, length, timeout):
        desc = bytes([0x06, 0xD0, 0xF1]) + b"\x09\x01\xA1\x01" + b"\x00" * 8
        for i, b in enumerate(desc[:length]):
            buffer[i] = b
        return min(len(desc), length)


class _KeySet:
    def __init__(self, names):
        self._names = names

    def toArray(self):
        return list(self._names)


class FakeDeviceList:
    def __init__(self, devices):
        self._map = {f"/dev/bus/usb/001/{i + 1:03d}": d for i, d in enumerate(devices)}

    def keySet(self):
        return _KeySet(self._map.keys())

    def get(self, name):
        return self._map.get(name)


class FakeActivity:
    def getSystemService(self, name):
        assert name == "usb", name
        return _MANAGER

    def getPackageName(self):
        return "org.picokey.picokeymanager"

    def registerReceiver(self, *a, **kw):
        return None

    def unregisterReceiver(self, *a):
        return None


class FakeUsbManager:
    def __init__(self, devices):
        self._devices = devices
        self._connections = {}

    def getDeviceList(self):
        return FakeDeviceList(self._devices)

    def hasPermission(self, dev):
        return True                                  # pre-granted for the test

    def openDevice(self, dev):
        conn = FakeConnection(dev)
        self._connections[dev] = conn
        return conn


class _PythonActivity:
    mActivity = FakeActivity()


_FAKE_CLASSES = {
    "org.kivy.android.PythonActivity": _PythonActivity,
    "android.content.Context": type("Context", (), {"USB_SERVICE": "usb"}),
    "android.hardware.usb.UsbManager": type(
        "UsbManager", (), {"EXTRA_PERMISSION_GRANTED": "permission"}),
    "android.os.Build": type("Build", (), {"VERSION": type("V", (), {"SDK_INT": 34})}),
}


def _install_fake_jnius():
    class PythonJavaClass:
        def __init__(self, *a, **kw):
            pass

    def java_method(*a, **kw):
        def deco(fn):
            return fn
        return deco

    def autoclass(name):
        if name not in _FAKE_CLASSES:
            raise AssertionError("unexpected autoclass: " + name)
        return _FAKE_CLASSES[name]

    module = type(sys)("jnius")
    module.autoclass = autoclass
    module.PythonJavaClass = PythonJavaClass
    module.java_method = java_method
    module.cast = lambda *a, **kw: a[0] if a else None
    sys.modules["jnius"] = module


# ------------------------------------------------------------------- the test

def build_device():
    from picokeyapp.selftest import FakePicoKey, FakeFidoKey

    ccid = FakeInterface(0, 0x0B, 0x00, 0x00,
                         [FakeEndpoint(0x81, 2), FakeEndpoint(0x01, 2)])
    rescue = FakeInterface(1, 0xFF, 0x00, 0x00,
                           [FakeEndpoint(0x82, 2), FakeEndpoint(0x02, 2)])
    hid = FakeInterface(2, 0x03, 0x00, 0x00,
                        [FakeEndpoint(0x83, 3), FakeEndpoint(0x03, 3)])

    dev = FakeUsbDevice(0xFEFF, 0xFCFD, [ccid, rescue, hid])
    pico, fido = FakePicoKey(), FakeFidoKey()

    def backend(frame):
        # route by frame layout: CCID has bSlot at [4] (0x80 clear), CTAPHID
        # marks the INIT packet with 0x80 at [4]
        if frame[0] in (0x62, 0x63, 0x6F):
            return pico(frame)
        return fido(frame)

    dev.backend = backend
    return dev, pico, fido


def main():
    # A KV body that binds to a missing app.<name> aborts build() on Android.
    # Catch it here first; the USB simulation below never parses real KV.
    _tools = os.path.dirname(os.path.abspath(__file__))
    subprocess.check_call(
        [sys.executable, os.path.join(_tools, "check_kv_bindings.py")])

    _install_fake_jnius()
    dev, pico, fido = build_device()
    global _MANAGER
    _MANAGER = FakeUsbManager([dev])

    from picokeyapp import usbhost, ccid, ctap, detect
    from picokeyapp.pk import PicoKey

    assert usbhost.is_android(), "fake jnius was not picked up"

    devices = usbhost.enumerate_devices()
    print("devices:", devices)
    assert len(devices) == 1
    d = devices[0]
    assert (d.vid, d.pid) == (0xFEFF, 0xFCFD)
    assert len(d.interfaces) == 3
    assert d.interfaces[0].class_name == "CCID/Smartcard"
    assert d.interfaces[1].class_name == "Vendor-specific"
    assert d.interfaces[2].class_name == "HID"

    channels = detect.scan()
    print("channels:", channels)
    kinds = sorted(c.kind for c in channels)
    assert kinds == ["ccid", "fido", "rescue"], kinds

    # --- CCID channel -----------------------------------------------
    kind, transport = detect.connect(channels[0])
    assert kind == "apdu", kind
    pk = PicoKey(transport)
    print("ccid summary:", pk.summary())
    assert pk.summary()["platform"] == "RP2350"
    assert pk.flash_info()["total"] == 4096
    transport.close()

    # --- rescue channel (same device, vendor interface) --------------
    rescue_chan = [c for c in channels if c.kind == "rescue"][0]
    kind, transport = detect.connect(rescue_chan)
    pk2 = PicoKey(transport)
    assert pk2.summary()["product"] == "FIDO"
    print("rescue summary:", pk2.summary())
    transport.close()

    # --- FIDO HID channel --------------------------------------------
    fido_chan = [c for c in channels if c.kind == "fido"][0]
    kind, transport = detect.connect(fido_chan)
    assert kind == "ctap", kind
    init = transport.init()
    assert init["cid"] == 0x12345678, init
    assert transport.wink() and fido.winked
    info = ctap.describe(transport.get_info())
    assert info["versions"] == ["U2F_V2", "FIDO_2_0"], info
    print("fido init:", init)
    print("fido info:", info)
    transport.close()

    print("\nfake-Android 集成检查全部通过。")


_MANAGER = None

if __name__ == "__main__":
    main()
