#!/usr/bin/env python3
"""
kraken_report.py — run several audits and write ONE combined report.

A thin CLI over kraken_core: audit whichever of your nodes/miner you pass, then
emit a single Markdown (and/or JSON) report with an overall Security Score.
Same defensive, read-only checks — just gathered into one document.

    # one report covering a node, an lnd instance and a miner you own
    python3 kraken_report.py \
        --node ~/.bitcoin/bitcoin.conf \
        --lnd  ~/.lnd/lnd.conf --ln-dir ~/.lnd \
        --miner 192.168.1.50 \
        --output report.md --json report.json

With no --output/--json it prints the Markdown to stdout. Exits non-zero if any
section has a CRITICAL/HIGH finding (handy for cron/CI).
"""

from __future__ import annotations

import argparse
import json
import sys

import kraken_core as core
import audit_common as ac


def main(argv=None):
    p = argparse.ArgumentParser(
        description="Run several audits and write one combined report.")
    p.add_argument("--node", metavar="CONF", help="Bitcoin Core bitcoin.conf.")
    p.add_argument("--lnd", metavar="CONF", help="lnd.conf to audit as lnd.")
    p.add_argument("--cln", metavar="CONF", help="CLN config to audit as cln.")
    p.add_argument("--ln-dir", metavar="DIR", help="Lightning home (~/.lnd / ~/.lightning).")
    p.add_argument("--miner", metavar="HOST", help="One miner host you own (no ranges).")
    p.add_argument("--api-port", type=int, default=4028)
    p.add_argument("--no-sockets", action="store_true", help="Skip local socket checks.")
    p.add_argument("--output", metavar="FILE", help="Write the Markdown report here.")
    p.add_argument("--json", metavar="FILE", help="Write the JSON report here.")
    args = p.parse_args(argv)

    sockets = not args.no_sockets
    results = []

    if args.node:
        results.append(core.audit_node(args.node, check_sockets=sockets))
    if args.lnd:
        results.append(core.audit_lightning("lnd", args.lnd, args.ln_dir, check_sockets=sockets))
    if args.cln:
        results.append(core.audit_lightning("cln", args.cln, args.ln_dir, check_sockets=sockets))
    if args.miner:
        try:
            results.append(core.audit_miner(args.miner, args.api_port))
        except ac.TargetError as exc:
            p.error(str(exc))

    if not results:
        p.error("Nothing to audit — pass at least one of --node / --lnd / --cln / --miner.")

    md = core.report_markdown(results)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(md)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(core.report_dict(results), fh, indent=2, ensure_ascii=False)
    if not args.output and not args.json:
        print(md)
    else:
        sc = core.overall(results)
        print(f"[+] {sc.label} · score {sc.score}/100 ({sc.grade}) · "
              f"{sum(sc.totals.values())} findings"
              + (f" → {args.output}" if args.output else "")
              + (f", {args.json}" if args.json else ""))

    return 1 if any(r.exit_code for r in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
