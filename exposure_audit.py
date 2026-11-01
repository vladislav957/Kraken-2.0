#!/usr/bin/env python3
"""
exposure_audit.py — local network-exposure auditor.

DEFENSIVE and READ-ONLY. It answers one question about THIS machine: "which of
my own services are reachable off-box?" It lists the local listening sockets
(via ss / netstat) and flags every one bound to a non-loopback interface —
nothing more. It does NOT scan the network, probe other hosts, or discover
devices; it only looks at the machine it runs on.

    python3 exposure_audit.py
    python3 exposure_audit.py --json --output exposure.md
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import asdict

from audit_common import (
    CRITICAL, HIGH, MEDIUM, LOW, INFO, OK,
    Finding, local_listeners, is_public_bind,
    render_markdown, render_terminal, sort_findings, worst_exit_code,
)

# port -> (what it is, severity if reachable off-box)
KNOWN = {
    8332: ("Bitcoin RPC", HIGH), 18332: ("Bitcoin RPC", HIGH),
    38332: ("Bitcoin RPC", HIGH), 18443: ("Bitcoin RPC", HIGH),
    8333: ("Bitcoin P2P", INFO), 18333: ("Bitcoin P2P", INFO),
    38333: ("Bitcoin P2P", INFO), 18444: ("Bitcoin P2P", INFO),
    10009: ("lnd gRPC", HIGH), 8080: ("REST / HTTP", MEDIUM),
    8443: ("REST / HTTPS", MEDIUM), 9735: ("Lightning P2P", INFO),
    9736: ("Lightning gRPC", HIGH), 3010: ("clnrest", MEDIUM),
    4028: ("CGMiner API", MEDIUM),
    22: ("SSH", HIGH), 23: ("Telnet", CRITICAL),
    3000: ("Grafana", MEDIUM), 9090: ("Prometheus", MEDIUM),
    80: ("HTTP", LOW), 443: ("HTTPS", LOW),
    3306: ("MySQL", HIGH), 5432: ("PostgreSQL", HIGH),
    6379: ("Redis", CRITICAL), 11211: ("Memcached", CRITICAL),
    27017: ("MongoDB", HIGH), 9200: ("Elasticsearch", HIGH),
    5900: ("VNC", HIGH), 3389: ("RDP", HIGH),
}


def check_exposure(listeners=None) -> list[Finding]:
    err = None
    if listeners is None:
        listeners, err = local_listeners()
    if err:
        return [Finding(INFO, "sockets-unavailable",
                        "Could not inspect local sockets", err,
                        "Install iproute2 (ss) to enable the exposure check.")]

    public, local = [], 0
    for host, port in listeners:
        (public.append((host, port)) if is_public_bind(host) else None)
        if not is_public_bind(host):
            local += 1

    findings: list[Finding] = []
    for host, port in sorted(set(public)):
        role, sev = KNOWN.get(port, ("unrecognised service", MEDIUM))
        findings.append(Finding(
            sev, "exposed-port",
            f"Port {port} ({role}) is listening on {host} — reachable off-box",
            "This service is bound to a non-loopback interface, so it may be "
            "reachable from your LAN or the internet (depending on the "
            "firewall). Control interfaces and databases should almost never be "
            "exposed.",
            f"Bind it to 127.0.0.1, or firewall the port (e.g. `sudo ufw deny "
            f"{port}/tcp`). Expose only what genuinely must be public (e.g. a "
            "P2P port).",
        ))

    if not public:
        findings.append(Finding(
            OK, "no-exposure", "No service is reachable off this host",
            "Every listening socket is bound to localhost. Nothing is exposed "
            "to the network from this machine.",
        ))
    if local:
        findings.append(Finding(
            INFO, "local-only", f"{local} service(s) bound to localhost only",
            "These listen on loopback and are not reachable from the network.",
        ))
    return findings


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Local network-exposure auditor — what of YOUR OWN machine "
                    "is reachable off-box. It never scans other hosts.")
    ap.add_argument("--output", help="Write a Markdown report to this file.")
    ap.add_argument("--json", action="store_true", help="Emit findings as JSON.")
    args = ap.parse_args(argv)

    findings = check_exposure()
    if args.json:
        print(json.dumps([asdict(f) for f in sort_findings(findings)],
                         indent=2, ensure_ascii=False))
    else:
        print(render_terminal(findings))
    if args.output:
        meta = [("Host", f"`{os.uname().nodename}`")] if hasattr(os, "uname") else []
        try:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(render_markdown(
                    findings, "Network Exposure Audit", meta,
                    "Inspected only this machine's own listening sockets. No "
                    "other host was scanned or contacted."))
        except OSError as exc:
            print(f"[!] Could not write report: {exc}", file=sys.stderr)
    return worst_exit_code(findings)


if __name__ == "__main__":
    raise SystemExit(main())
