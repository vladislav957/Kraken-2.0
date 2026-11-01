#!/usr/bin/env python3
"""
miner_audit.py — Exposure check for a SINGLE ASIC/GPU miner you own.

DEFENSIVE, non-intrusive, and deliberately single-target. By design it cannot
sweep a network: the target is parsed with a guard that rejects CIDRs, ranges
and lists. It also never attempts to authenticate — it does not send
credentials of any kind.

What it does (all against ONE host you name):
  * Checks whether the CGMiner/bmminer JSON API (default 4028) is reachable and
    reads ONLY the public, read-only `version` the device already serves to
    monitoring dashboards. It sends NO control commands.
  * Checks whether the web admin (80/443) is reachable (a bare TCP connect).
  * Reports exposure and reminds you to verify default passwords are changed —
    advice only; it does not test any password.

    python3 miner_audit.py --target 192.168.1.50
    python3 miner_audit.py --target 192.168.1.50 --api-port 4028 --output report.md
"""

from __future__ import annotations

import argparse
import json
import socket
import sys
from dataclasses import asdict

from audit_common import (
    HIGH, MEDIUM, LOW, INFO, OK,
    Finding, TargetError, parse_single_target, is_loopback,
    render_markdown, render_terminal, sort_findings, worst_exit_code,
)


# --------------------------------------------------------------------------- #
# Low-level, read-only probes (single host)
# --------------------------------------------------------------------------- #

def tcp_open(host: str, port: int, timeout: float = 4.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def cgminer_version(host: str, port: int,
                    timeout: float = 4.0) -> tuple[str | None, dict | None]:
    """Read the CGMiner API `version` — a read-only call that monitoring tools
    make routinely. The API is unauthenticated by design; we only read."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.sendall(json.dumps({"command": "version"}).encode())
            s.settimeout(timeout)
            chunks = []
            while True:
                try:
                    data = s.recv(4096)
                except socket.timeout:
                    break
                if not data:
                    break
                chunks.append(data)
                if b"\x00" in data:           # cgminer terminates with NUL
                    break
    except OSError:
        return None, None
    raw = b"".join(chunks).replace(b"\x00", b"").decode("utf-8", "replace").strip()
    if not raw:
        return None, None
    try:
        return raw, json.loads(raw)
    except json.JSONDecodeError:
        return raw, None


def _extract_identity(parsed: dict | None) -> dict[str, str]:
    out: dict[str, str] = {}
    if not isinstance(parsed, dict):
        return out
    for key in ("VERSION", "STATS", "SUMMARY"):
        block = parsed.get(key)
        if isinstance(block, list) and block and isinstance(block[0], dict):
            for k, v in block[0].items():
                if k.lower() in ("type", "model", "cgminer", "bmminer",
                                 "api", "miner", "firmware", "prod"):
                    out[k] = str(v)
    status = parsed.get("STATUS")
    if isinstance(status, list) and status and isinstance(status[0], dict):
        d = status[0].get("Description")
        if d:
            out["Description"] = str(d)
    return out


# --------------------------------------------------------------------------- #
# Checks
# --------------------------------------------------------------------------- #

def check_api(host: str, port: int) -> list[Finding]:
    findings: list[Finding] = []
    raw, parsed = cgminer_version(host, port)
    if raw is None:
        findings.append(Finding(
            OK, "miner-api-unreachable",
            f"CGMiner API not reachable on {host}:{port}",
            "No response from the miner's JSON API from this host — fine if the "
            "API is firewalled to your management network (or host/port differ).",
            "If you expected it reachable, confirm host/port; otherwise this is "
            "the desired state for an unexposed device.",
        ))
        return findings

    sev = INFO if is_loopback(host) else MEDIUM
    findings.append(Finding(
        sev, "miner-api-reachable",
        f"CGMiner API reachable and unauthenticated on {host}:{port}",
        "The miner's JSON API answered. This API has no authentication: anyone "
        "who can reach the port can read device/pool data, and depending on the "
        "firmware's `api-allow` privileges may be able to issue control "
        "commands. A routable address means it is not confined to localhost.",
        f"Restrict the API to your management host/VLAN: set `api-allow` to a "
        f"specific privileged IP and turn `api-network` off, or firewall "
        f"TCP/{port} so only your admin box can reach it.",
    ))

    ident = _extract_identity(parsed)
    if ident:
        pretty = ", ".join(f"{k}={v}" for k, v in ident.items())
        findings.append(Finding(
            INFO, "miner-identity",
            "Miner identity (from the public version response)",
            f"Reported by the device: {pretty}. Use this to confirm you are "
            "auditing the right unit and to check firmware currency.",
            "Keep firmware updated from the vendor; outdated miner firmware is a "
            "common source of known vulnerabilities.",
        ))
    return findings


def check_web(host: str) -> list[Finding]:
    http, https = tcp_open(host, 80), tcp_open(host, 443)
    if not (http or https):
        return []
    ports = ", ".join(p for p, ok in (("80", http), ("443", https)) if ok)
    sev = INFO if is_loopback(host) else LOW
    return [Finding(
        sev, "miner-web-reachable",
        f"Miner web admin reachable on {host} (port(s) {ports})",
        "The device's web management panel answers a TCP connection. Many ASIC "
        "miners ship with well-known default admin credentials.",
        "Make sure the admin password was changed from the factory default, "
        "serve the panel only on your management VLAN, and put it behind a VPN "
        "rather than exposing it. (This tool does not test the password — verify "
        "it yourself.)",
    )]


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Single-target, non-intrusive exposure check for a miner you own.",
        epilog="Audits ONE host; refuses ranges/CIDRs/lists; never sends credentials.",
    )
    parser.add_argument("--target", required=True,
                        help="ONE miner host or host:port you own (no ranges/CIDRs).")
    parser.add_argument("--api-port", type=int, default=4028,
                        help="CGMiner API port (default 4028).")
    parser.add_argument("--no-web", action="store_true",
                        help="Skip the web-admin reachability check.")
    parser.add_argument("--output", help="Write a Markdown report to this file.")
    parser.add_argument("--json", action="store_true", help="Emit findings as JSON.")
    args = parser.parse_args(argv)

    try:
        host, port = parse_single_target(args.target, default_port=args.api_port)
    except TargetError as exc:
        parser.error(str(exc))

    findings: list[Finding] = []
    findings += check_api(host, port)
    if not args.no_web:
        findings += check_web(host)

    if args.json:
        print(json.dumps([asdict(f) for f in sort_findings(findings)],
                         indent=2, ensure_ascii=False))
    else:
        print(render_terminal(findings))

    if args.output:
        meta = [("Target", f"`{host}:{port}`")]
        try:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(render_markdown(
                    findings, "Miner Security Audit", meta,
                    "Single-target, non-intrusive audit: read-only API query and "
                    "TCP reachability only. No ranges were scanned, no control "
                    "commands were sent, and no credentials were tested."))
            if not args.json:
                print(f"\n[+] Markdown report written to {args.output}")
        except OSError as exc:
            print(f"[!] Could not write report: {exc}", file=sys.stderr)

    return worst_exit_code(findings)


if __name__ == "__main__":
    raise SystemExit(main())
