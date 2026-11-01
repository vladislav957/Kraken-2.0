#!/usr/bin/env bash
#
# build.sh — produce a standalone `kraken` binary that runs WITHOUT Python.
#
#   ./packaging/build.sh
#
# Output:  dist/kraken   — one self-contained executable for THIS OS + CPU.
# Copy it anywhere and run it; the target machine needs no Python, no pip,
# no Tk, nothing. (Build it once per OS/architecture you want to ship to.)
#
# To BUILD you need: a Python 3.10+ that can `import tkinter` (so the GUI gets
# bundled), plus one-time internet access to fetch PyInstaller. The resulting
# binary needs none of that.
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$(pwd)"

CANDIDATES="python3 python3.14 python3.13 python3.12 python3.11 python3.10"
has()      { command -v "$1" >/dev/null 2>&1; }
has_tk()   { "$1" -c "import tkinter" >/dev/null 2>&1; }
has_venv() { "$1" -c "import ensurepip" >/dev/null 2>&1; }   # needed to create a venv

# Prefer a Python with BOTH Tkinter (for the GUI) and a working venv; then one
# with Tkinter only; then any Python 3 at all.
pick_python() {
    for c in $CANDIDATES; do
        if has "$c" && has_tk "$c" && has_venv "$c"; then echo "$c"; return 0; fi
    done
    for c in $CANDIDATES; do
        if has "$c" && has_tk "$c"; then echo "$c"; return 0; fi
    done
    for c in $CANDIDATES; do
        if has "$c"; then echo "$c"; return 0; fi
    done
    return 1
}

PY="$(pick_python)" || { echo "No suitable Python 3 found to build with." >&2; exit 1; }
echo "[*] Building with $PY ($("$PY" --version 2>&1))"
if "$PY" -c "import tkinter" >/dev/null 2>&1; then
    echo "[*] Tkinter present — the desktop GUI will be bundled."
else
    echo "[!] Tkinter NOT found in $PY — the CLI will work but the bundled GUI will not."
fi

# Make sure we can actually create a venv before trying (Debian/Ubuntu split
# this into a separate pythonX.Y-venv package).
if ! has_venv "$PY"; then
    VER="$("$PY" -c 'import sys;print(f"python3.{sys.version_info.minor}")')"
    echo "[!] $PY can't create virtualenvs (ensurepip/venv missing)." >&2
    echo "    Install it, then re-run this script:" >&2
    echo >&2
    echo "        sudo apt install ${VER}-venv        # Debian/Ubuntu" >&2
    echo "        # (Fedora/RHEL: python3 -m ensurepip is usually built in)" >&2
    echo >&2
    exit 1
fi

VENV="${KRAKEN_BUILD_VENV:-.build-venv}"
if [ ! -x "$VENV/bin/pyinstaller" ]; then
    echo "[*] Creating one-time build environment in $VENV/ ..."
    rm -rf "$VENV"                       # drop any half-made venv from a prior failed run
    "$PY" -m venv "$VENV"
    "$VENV/bin/python" -m pip install --upgrade pip >/dev/null
    "$VENV/bin/python" -m pip install "pyinstaller>=6.0"
fi

echo "[*] Running PyInstaller ..."
"$VENV/bin/pyinstaller" --noconfirm --clean packaging/kraken.spec

echo
echo "[+] Done: $ROOT/dist/kraken"
"$ROOT/dist/kraken" --version
cat <<EOF

Try it:
  ./dist/kraken --help        # list commands
  ./dist/kraken exposure      # audit this host's exposure
  ./dist/kraken gui           # open the desktop app

Install system-wide (optional):
  sudo install -m 0755 dist/kraken /usr/local/bin/kraken
  kraken --help
EOF
