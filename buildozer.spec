[app]
title = PicoKey Manager
package.name = picokeymanager
package.domain = org.picokey

source.dir = .
# ttf is required: the bundled CJK font (assets/fonts/) has to end up
# inside the APK or every Chinese label renders as a tofu box.
source.include_exts = py,png,jpg,kv,atlas,txt,md,xml,ttf
source.exclude_dirs = tests,docs,.github,tools,build,bin,.buildozer,__pycache__

# Bump this before every release you want to keep. The workflow derives the
# release tag from it (v0.2.0 here), and it refuses to overwrite an existing
# tag unless you explicitly ask - so raising this number is what actually
# preserves earlier versions in Releases.
version = 0.2.3

# python3 + kivy pull in pyjnius by themselves; cryptography/pycvc are NOT
# listed on purpose (they would need a Rust toolchain for the modern
# cryptography wheels) - the app degrades gracefully without them.
requirements = python3,kivy,pyjnius

orientation = portrait
fullscreen = 0

# ---------------------------------------------------------------- android

# DO NOT use `android.features` here.
# buildozer translates android.features into p4a's `--feature` argument
# (buildozer/targets/android.py), and current python-for-android (>= 2024)
# removed `--feature`, so the build dies with:
#   toolchain.py: error: unrecognized arguments: --feature android.hardware.usb.host
# This is true for BOTH buildozer 1.5.0 and 1.6.0, so it cannot be fixed by
# pinning another buildozer version - the setting itself has to go.
#
# The same declaration is injected straight into <manifest> instead, which is
# what p4a supports today via --extra-manifest-xml.
android.extra_manifest_xml = ./src/android/usb_host_feature.xml

android.api = 35
android.minapi = 26

# arm64 only: one arch roughly halves the build time and every current phone
# (including the Snapdragon 8+ Gen1 in a OnePlus Ace 2) is arm64-v8a. Add
# armeabi-v7a back here only if you need a 32-bit device.
android.archs = arm64-v8a

# USB host needs no runtime permission, so this stays empty on purpose.
# Firmware is picked with the system file manager (SAF), which needs no
# permission either - the app makes no network requests at all.
android.permissions =

android.allow_backup = True

# make `adb logcat | grep python` readable while debugging on the phone
android.logcat_filters = *:S python:D

[buildozer]
log_level = 2
warn_on_root = 1
