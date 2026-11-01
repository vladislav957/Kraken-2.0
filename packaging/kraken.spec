# -*- mode: python ; coding: utf-8 -*-
#
# PyInstaller spec — bundle the whole Kraken Audit toolkit into ONE
# self-contained `kraken` executable that runs without any system Python.
#
# Build with:  ./packaging/build.sh   (which installs PyInstaller in a venv
# and runs `pyinstaller packaging/kraken.spec`). Output lands in ./dist/kraken.
#
# The single entry point is kraken_cli.py; it dispatches to every auditor and,
# with no arguments, opens the Tkinter desktop app. All the audit modules are
# listed as hidden imports so the frozen binary carries the complete toolkit.

import os

ROOT = os.path.abspath(os.path.join(SPECPATH, ".."))

a = Analysis(
    [os.path.join(ROOT, "kraken_cli.py")],
    pathex=[ROOT],
    binaries=[],
    datas=[],
    hiddenimports=[
        "kraken_app",
        "kraken_core",
        "audit_common",
        "node_audit",
        "lightning_audit",
        "miner_audit",
        "exposure_audit",
        "kraken_report",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure)

# One-file build: binaries + datas go straight into EXE (no COLLECT).
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="kraken",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    runtime_tmpdir=None,
    console=True,            # a terminal app that can also open the GUI window
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
