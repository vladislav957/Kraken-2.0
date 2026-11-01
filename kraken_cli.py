#!/usr/bin/env python3
"""
kraken_cli.py — one entry point for every Kraken auditor.

This is what the standalone, no-Python-required binary runs. It dispatches to
the same defensive, read-only auditors you can also run as individual scripts:

    kraken                       # no args -> launch the desktop app (GUI)
    kraken gui                   # launch the desktop app explicitly
    kraken node     [options]    # Bitcoin Core config / perms / sockets
    kraken lightning[options]    # lnd / Core Lightning
    kraken miner    [options]    # one ASIC/GPU miner (read-only CGMiner API)
    kraken exposure [options]    # what of THIS host is reachable off-box
    kraken report   [options]    # several audits -> one Markdown/JSON report

    kraken <cmd> --help          # options for that auditor
    kraken --version

Everything here is the same scope as the rest of the toolkit: it inspects
local config/permissions/sockets, or makes a single read-only query to one
host you name. It never scans networks, brute-forces, or attacks anything.
"""

from __future__ import annotations

import sys

__version__ = "1.0.0"

# Importing the module behind each subcommand up front keeps things simple and
# also makes PyInstaller pull them (and, transitively, kraken_core /
# audit_common) into the frozen binary.
import node_audit
import lightning_audit
import miner_audit
import exposure_audit
import kraken_report

# Subcommand -> (callable taking argv-list -> int, one-line help).
_COMMANDS = {
    "node":      (node_audit.main,      "Audit a Bitcoin Core node (bitcoin.conf, perms, sockets)."),
    "lightning": (lightning_audit.main, "Audit a Lightning node (lnd / Core Lightning)."),
    "ln":        (lightning_audit.main, "Alias for 'lightning'."),
    "miner":     (miner_audit.main,     "Audit one miner you own (read-only CGMiner API)."),
    "exposure":  (exposure_audit.main,  "List what of THIS host is reachable off-box."),
    "report":    (kraken_report.main,   "Run several audits into one Markdown/JSON report."),
}

_GUI_ALIASES = {"gui", "app", "desktop"}


def _launch_gui() -> int:
    """Open the Tkinter desktop app. Bundled binaries ship Tk; a bare
    `python3 kraken_cli.py gui` needs Tk installed."""
    try:
        import kraken_app
    except SystemExit as exc:       # kraken_app raises SystemExit when Tk is absent
        print(str(exc), file=sys.stderr)
        return 2
    kraken_app.main()
    return 0


def _usage() -> str:
    lines = [
        "kraken — defensive, read-only auditors for Bitcoin / Lightning infra you own.",
        "",
        "Usage:",
        "  kraken                 launch the desktop app (GUI)",
        "  kraken <command> ...   run one auditor",
        "  kraken <command> -h    options for that command",
        "",
        "Commands:",
        "  gui                    launch the desktop app explicitly",
    ]
    seen = set()
    for name, (_, desc) in _COMMANDS.items():
        if desc.startswith("Alias"):
            continue
        if name in seen:
            continue
        seen.add(name)
        lines.append(f"  {name:<22} {desc}")
    lines += [
        "",
        "Scope: inspects local config/permissions/sockets, or one read-only query to",
        "one host you name. Never scans networks, brute-forces, or attacks anything.",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)

    # No arguments -> open the GUI (so a double-clicked binary "just opens").
    if not argv:
        return _launch_gui()

    cmd = argv[0]

    if cmd in ("-h", "--help", "help"):
        print(_usage())
        return 0
    if cmd in ("-V", "--version", "version"):
        print(f"kraken {__version__}")
        return 0
    if cmd in _GUI_ALIASES:
        return _launch_gui()

    entry = _COMMANDS.get(cmd)
    if entry is None:
        print(f"kraken: unknown command {cmd!r}\n", file=sys.stderr)
        print(_usage(), file=sys.stderr)
        return 2

    func, _ = entry
    return func(argv[1:])


if __name__ == "__main__":
    raise SystemExit(main())
