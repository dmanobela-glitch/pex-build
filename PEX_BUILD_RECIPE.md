# PEX one-click build recipe (handoff to Cludia, 2026-08-05) — everything that works, + every gotcha we hit

Your `launcher/pex_launch.py` is the source of truth. This is the packaging around it. Attached: `pex-build.yml` (the GH
Actions workflow) + `pex_entry.py` (the frozen wrapper). Adopt + extend.

## The package (what a user unzips)
`pex-win.zip` → `pex/` folder containing:
- `pex.exe` — Nuitka **--onefile** frozen `pex_entry.py` (which imports your `pex_launch` unchanged).
- the **embeddable CPython** flat beside it: Windows `pythonw.exe`/`python.exe`/`python3xx.dll`/`Lib/`/`DLLs/`; Linux `bin/python3` + `lib/`.
- `cryptography` + `pywebview` pip-installed INTO that embeddable python.
Linux twin: `pex-linux.zip` → `pex/` with `pex` + `bin/python3`.

## Nuitka invocation (both OSes, host-native — NO cross-compile)
```
python -m nuitka --onefile --assume-yes-for-downloads [--windows-console-mode=disable] \
  --company-name=Bull4Life --product-name=PEX --product-version=1.0.0 --file-version=1.0.0.0 \
  --include-module=pex_launch \
  --output-dir=nbuild --output-filename=<pex.exe|pex> \
  launcher/pex_entry.py
```
- **`--onefile` is REQUIRED** (not `--standalone`): sys.executable then == the real `pex.exe` path (beside the sibling
  python) and there's no Nuitka `python3xx.dll` to clash with the embeddable one in the same folder.
- `--windows-console-mode=disable` only on Windows (no console flash). NO UPX (AV false-positive trigger).
- Metadata (`--company-name` etc.) = why AV treats it as software not an anonymous packed exe (mirrors the miner).
- `--output-dir=nbuild` keeps the binary OUT of the CWD — else the Linux binary named `pex` collides with `mkdir pex`.

## `pex_entry.py` (attached) — the frozen wrapper around your launcher
Forces UTF-8 + gives real stdout/stderr BEFORE importing `pex_launch`, so a `--windows-console-mode=disable` exe can't
die on `print()` (None stdout / cp1252). Your `pex_launch` is imported verbatim; `pex_entry.main()` → `pex_launch.main()`.

## THE THREE GOTCHAS WE HIT (don't repeat)
1. **Nuitka packs 3730 files → dropped symlinks/exec-bits** (an earlier baked approach). Bake dirs as tarballs, or (now)
   just cp the embeddable python — but see #3.
2. **Frozen interpreter has only what the launcher imports** → the node tree's `secrets`/`ssl` aren't in it. NEVER verify
   the fetched tree in the frozen interpreter. Your `_tree_fp` (subprocess via the SIBLING python) is the fix — keep it.
3. **`zip` FLATTENS symlinks into real files.** A top-level `python3` symlink → a real ELF at `pex/python3` whose rpath
   `$ORIGIN/../lib` points to `pex/../lib` (wrong) → "cannot load libpython". FIX: ship `bin/python3` ONLY (rpath resolves
   to `pex/lib`); your `_find_python` finds it. Windows `pythonw.exe` is top-level with DLLs beside it → fine.

## BUILD-TIME GATE (add this — it's what would've caught bug1/bug2 in CI, not on Master)
After packaging, RUN the sibling python you ship:
```
pex/python.exe -c "import secrets,hashlib,ssl,cryptography; print('OK', cryptography.__version__)"   # win
pex/bin/python3 -c "import secrets,hashlib,ssl,cryptography; print('OK', cryptography.__version__)"   # linux
```
Plus your planned **frozen smoke-test** (run the actual `pex.exe` headless against the box, assert it reaches the tip) is
the real gate — strictly better than my logic-only self-check. That closes the frozen≠full-python gap for good.

## Hosting (your `pex_ops` does this now)
`/var/www/compute-download/`: `pex-win.zip` + `pex-linux.zip` + `.fp` (the live fp). LEAVE `Bull4LifeNode.exe` (mine).
Caddy serves `compute.bull4life.com/download/*`. Your auto-publish timer keeps `/download/pex-node.tar.gz` current.

## Embeddable CPython source
python-build-standalone (indygreg) `install_only` builds, pinned e.g. `20241016 / cpython-3.12.7`:
win `...-x86_64-pc-windows-msvc-install_only.tar.gz`, linux `...-x86_64-unknown-linux-gnu-install_only.tar.gz` → extracts
to `python/`; pip-install cryptography+certifi+pywebview into it.
