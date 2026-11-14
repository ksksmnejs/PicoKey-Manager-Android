# -*- coding: utf-8 -*-
"""Rebuild the bundled CJK font subset after UI strings change.

The APK ships a subset of Noto Sans CJK SC, not the full 10 MB font. It is cut
to the exact characters that appear in main.py and picokeyapp/i18n.py, which is
why a new string containing a character that was never used before renders as a
tofu box on the phone. The self-test (`_check_font_coverage`) catches that, but
catching it is not the same as fixing it - this script is the fix.

Run it from the project root whenever Chinese copy is added:

    python3 tools/build_font_subset.py

It needs fontTools and a local Noto Sans CJK Regular TTC. On a machine without
that font, set NOTO_CJK_TTC to another OTF/CFF CJK font; on Android the freshly
generated file is simply committed/ uploaded with the rest of the sources.

The output keeps the same filename and the same CFF/OTTO structure as before,
so Kivy's font registration and the APK packaging do not change.
"""

from __future__ import annotations

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "assets", "fonts", "NotoSansSC-Regular-subset.ttf")

DEFAULT_TTC = "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc"
TTC = os.environ.get("NOTO_CJK_TTC", DEFAULT_TTC)
FONT_NUMBER = int(os.environ.get("NOTO_CJK_FACE", "2"))  # 2 = SC


def characters() -> str:
    text = []
    for rel in ("main.py", "picokeyapp/i18n.py"):
        path = os.path.join(ROOT, rel)
        with open(path, encoding="utf-8") as fh:
            text.append(fh.read())
    # Printable ASCII, plus the punctuation the UI may use outside of those
    # two files (spinners, log lines, numbers, hex dumps).
    text.append("".join(chr(c) for c in range(32, 127)))
    text.append("　，。！？：；（）【】「」《》·…—－￥％＋")
    return "".join(text)


def main():
    from fontTools import subset
    from fontTools.ttLib import TTFont

    if not os.path.exists(TTC):
        raise SystemExit(
            "CJK source font not found: %s\nSet NOTO_CJK_TTC to a Noto Sans "
            "CJK (or another CFF/OTF) font on this machine." % TTC)

    font = TTFont(TTC, fontNumber=FONT_NUMBER)
    opts = subset.Options()
    opts.layout_features = ["*"]
    opts.name_IDs = ["*"]
    opts.name_legacy = True
    opts.name_languages = ["*"]
    opts.notdef_outline = True
    opts.recalc_bounds = True
    opts.drop_tables += ["DSIG"]

    sub = subset.Subsetter(options=opts)
    sub.populate(text=characters())
    sub.subset(font)
    font.save(OUT)

    # Verify here as well: the self-test only runs in the app.
    check = TTFont(OUT)
    cmap = check.getBestCmap()
    missing = sorted({c for c in characters()
                      if ord(c) > 0x2000 and ord(c) not in cmap})
    size = os.path.getsize(OUT)
    print("wrote %s (%d bytes, %d codepoints, sfnt=%s)" %
          (OUT, size, len(cmap), check.sfntVersion))
    if missing:
        raise SystemExit("still missing glyphs: " + "".join(missing))
    if size >= 900_000:
        raise SystemExit("subset is too large to ship: %d bytes" % size)
    print("font coverage: OK")


if __name__ == "__main__":
    sys.exit(main())
