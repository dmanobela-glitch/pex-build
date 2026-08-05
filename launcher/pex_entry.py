"""pex_entry — thin frozen-exe entry that makes launcher/pex_launch.py bullet-proof on Windows, WITHOUT changing the
launcher (Cludia leads PEX; this is the build wrapper's job). Adopted from engine 2035 + one addition for onefile bug 3.

Guards two Windows-frozen hazards that would kill the app SILENTLY:
  1. `pex_launch._log` non-ASCII under cp1252 stdout → UnicodeEncodeError. → force UTF-8.
  2. `--windows-console-mode=disable` (GUI-subsystem) exe → sys.stdout/stderr can be None → print() raises. → real sinks.
Plus (Cludia 2026-08-05, frozen bug 3): a Nuitka ONEFILE sets sys.executable to a /tmp extraction dir, so the launcher
can't find the sibling python relative to it. We know the true install dir here (the launched exe's own path), so export
it as PEX_APP_DIR — the launcher prefers it (authoritative), with its argv[0] search as backup.
"""
from __future__ import annotations
import io
import os
import sys

os.environ.setdefault("PYTHONUTF8", "1")
os.environ.setdefault("PYTHONIOENCODING", "utf-8")

# Ensure stdout/stderr exist and are UTF-8 (frozen windowless → None; console → cp1252).
for _name in ("stdout", "stderr"):
    _s = getattr(sys, _name, None)
    if _s is None:
        try:
            setattr(sys, _name, open(os.devnull, "w", encoding="utf-8"))
        except Exception:
            pass
    else:
        try:
            _s.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            try:
                setattr(sys, _name, io.TextIOWrapper(_s.buffer, encoding="utf-8", errors="replace"))
            except Exception:
                pass

# __B4L_ONEFILE_APPDIR__ point the launcher at the real install dir (where the sibling python lives) — onefile's
# sys.executable is a temp dir, so we resolve it from the launched-exe path here at bootstrap.
try:
    _appdir = os.path.dirname(os.path.realpath(sys.argv[0])) if (sys.argv and sys.argv[0]) else None
    if _appdir and os.path.isdir(_appdir):
        os.environ.setdefault("PEX_APP_DIR", _appdir)
except Exception:
    pass

import pex_launch  # noqa: E402  (the launcher, unchanged)

if __name__ == "__main__":
    pex_launch.main()
