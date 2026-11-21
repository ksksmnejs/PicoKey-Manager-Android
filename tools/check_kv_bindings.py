"""Static check: every ``app.<name>`` used in a KV body must exist on PicoKeyApp.

Why this exists
---------------
``Builder.load_string()`` resolves ``app.foo`` by calling ``getattr`` on the
running App instance *while the KV body is being parsed*. A single missing
attribute raises ``BuilderException`` and aborts ``build()`` - on Android that
looks exactly like "the APK crashes on launch". It is easy to miss because
template expansion tests and the Python self-tests never parse real KV.

This check needs no Kivy, no GL context and no Android: it reads main.py with
``ast`` and compares the names used in KV strings against the App's own
members. It walks plain literals, f-strings (KV_RULES interpolates the
palette) and ``+``-concatenated fragments - looking only at ast.Constant
silently skipped every binding inside those two, which is exactly how one
can reach an APK unchecked. Run it after any UI/KV edit:

    python3 tools/check_kv_bindings.py

It is also called at the start of tools/fake_android_check.py.
"""

import ast
import os
import re
import sys

# Attributes inherited from kivy.app.App (and a few ObjectProperty-like ones
# supplied by the framework) that are legal in KV but not declared in our class.
APP_INHERITED = {
    "user_data_dir", "name", "title", "icon", "kv_directory", "kv_file",
    "root", "build_config", "build_settings", "on_start", "on_stop",
    "on_pause", "on_resume", "get_application_config", "load_config",
    "load_kv", "run", "stop", "open_settings", "create_settings",
    "close_settings", "on_config_change",
}

APP_REF = re.compile(r"\bapp\.([A-Za-z_][A-Za-z0-9_]*)")


def _literal_text(node):
    """Best-effort text of a string-valued expression.

    A KV body is not always one plain literal: KV_RULES is an f-string, and
    the generated fragments (curve grid, USB interface toggles) are assembled
    with ``+``. ast.walk() visits the small constants too, but an f-string
    splits its text across several nodes, so a bare ast.Constant scan finds
    nothing there.
    """
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        parts = []
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                parts.append(value.value)
            elif isinstance(value, ast.FormattedValue):
                parts.append(_literal_text(value.value) or "")
        return "".join(parts)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return (_literal_text(node.left) or "") + (_literal_text(node.right) or "")
    return None


def _app_members(tree):
    cls = next((n for n in tree.body
                if isinstance(n, ast.ClassDef) and n.name == "PicoKeyApp"), None)
    if cls is None:
        raise RuntimeError("PicoKeyApp class not found in main.py")
    names = set()
    for item in cls.body:
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
            names.add(item.name)
            # Only __init__ runs before Builder.load_string(). An assignment
            # buried in a button handler creates the attribute far too late,
            # and counting it here would hide exactly the bug this check is
            # for: a KV binding with no class-level declaration at all.
            if item.name == "__init__":
                for node in ast.walk(item):
                    if (isinstance(node, ast.Attribute)
                            and isinstance(node.value, ast.Name)
                            and node.value.id == "self"
                            and isinstance(node.ctx, ast.Store)):
                        names.add(node.attr)
        elif isinstance(item, ast.Assign):
            for target in item.targets:
                if isinstance(target, ast.Name):
                    names.add(target.id)
        elif isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
            names.add(item.target.id)
    return names


def check_file(path):
    with open(path, encoding="utf-8") as fh:
        tree = ast.parse(fh.read(), filename=path)
    known = _app_members(tree) | APP_INHERITED

    used = {}
    for node in ast.walk(tree):
        text = _literal_text(node)
        if not text:
            continue
        for match in APP_REF.finditer(text):
            used.setdefault(match.group(1), []).append(node.lineno)
    missing = {name: lines for name, lines in used.items()
               if name not in known}

    print("KV bindings: %d app.* references, %d App members, %d missing"
          % (len(used), len(known), len(missing)))
    for name, lines in sorted(missing.items(), key=lambda kv: kv[1][0]):
        print("  MISSING app.%s (main.py line %d)" % (name, lines[0]))
    if missing:
        raise SystemExit(1)
    print("KV bindings: OK")
    return 0


if __name__ == "__main__":
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sys.exit(check_file(os.path.join(root, "main.py")))
