#!/usr/bin/env python3
"""
node_audit.py — Local security auditor for Bitcoin Core nodes.

DEFENSIVE and READ-ONLY. It does NOT scan remote hosts, connect to the
network, or test credentials. It inspects, on the machine it runs on:

  1. bitcoin.conf  — RPC exposure mistakes
  2. that file's permissions — secrets readable by other users
  3. local listening sockets — is the RPC port exposed off-box?

...and reports each issue with a severity and a concrete fix.

    python3 node_audit.py                       # auto-detect bitcoin.conf
    python3 node_audit.py --conf ~/.bitcoin/bitcoin.conf --output report.md
    python3 node_audit.py --json
    python3 node_audit.py --no-sockets
"""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
from dataclasses import asdict

from audit_common import (
    CRITICAL, HIGH, MEDIUM, LOW, INFO, OK,
    Finding, host_from_bind, is_loopback, is_wildcard, is_public_bind,
    local_listeners, password_entropy_bits, render_markdown, render_terminal,
    sort_findings, worst_exit_code,
)

RPC_PORTS = {8332, 18332, 38332, 18443}
P2P_PORTS = {8333, 18333, 38333, 18444}

NETWORK_SECTIONS = {"main", "test", "signet", "regtest"}


# --------------------------------------------------------------------------- #
# bitcoin.conf parsing
# --------------------------------------------------------------------------- #

def parse_conf(path: str) -> dict[str, list[str]]:
    values: dict[str, list[str]] = {}
    section = None
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#") or line.startswith(";"):
                continue
            m = re.match(r"^\[([A-Za-z0-9_]+)\]$", line)
            if m:
                section = m.group(1).lower()
                continue
            if "=" not in line:
                continue
            key, _, val = line.partition("=")
            key = key.strip()
            val = val.split("#", 1)[0].strip()
            values.setdefault(key, []).append(val)
            if section in NETWORK_SECTIONS:
                values.setdefault(f"{section}.{key}", []).append(val)
    return values


def _first(values: dict[str, list[str]], key: str) -> str | None:
    got = values.get(key)
    return got[0] if got else None


def _all(values: dict[str, list[str]], key: str) -> list[str]:
    out = list(values.get(key, []))
    for net in NETWORK_SECTIONS:
        out.extend(values.get(f"{net}.{key}", []))
    return out


# --------------------------------------------------------------------------- #
# Checks
# --------------------------------------------------------------------------- #

def check_config(values: dict[str, list[str]]) -> list[Finding]:
    findings: list[Finding] = []

    server = _first(values, "server")
    rpcpasswords = _all(values, "rpcpassword")
    rpcusers = _all(values, "rpcuser")
    rpcauths = _all(values, "rpcauth")
    rpcallowips = _all(values, "rpcallowip")
    rpcbinds = _all(values, "rpcbind")

    rpc_enabled = server == "1" or bool(rpcauths or rpcpasswords or rpcbinds)

    if rpcpasswords:
        findings.append(Finding(
            HIGH, "rpc-plaintext-password",
            "RPC password stored in plaintext (rpcpassword)",
            "bitcoin.conf contains a plaintext `rpcpassword`. Anyone who can "
            "read the file (backups, other users, a leaked config) gets full "
            "RPC control of the node.",
            "Prefer cookie auth (the default — simply remove rpcuser/rpcpassword) "
            "or `rpcauth` (a salted HMAC, generated with the share/rpcauth/"
            "rpcauth.py helper). The plaintext secret then never touches the "
            "config file.",
        ))
        for pw in rpcpasswords:
            bits = password_entropy_bits(pw)
            if bits < 80:
                findings.append(Finding(
                    HIGH if bits < 60 else MEDIUM, "rpc-weak-password",
                    f"Weak RPC password (~{bits:.0f} bits of entropy)",
                    f"The rpcpassword is {len(pw)} characters with an estimated "
                    f"{bits:.0f} bits of entropy. Low-entropy secrets fall to a "
                    "dictionary or brute-force attempt if the RPC port is ever "
                    "reachable.",
                    "Use a random secret of >=128 bits, e.g. "
                    "`python3 -c \"import secrets; print(secrets.token_urlsafe(32))\"`, "
                    "or switch to cookie auth / rpcauth.",
                ))
    elif rpcauths:
        findings.append(Finding(
            OK, "rpc-auth-hashed",
            "RPC uses rpcauth (salted hash)",
            "Authentication is configured via `rpcauth`, so no plaintext "
            "password is stored in the config. Good.",
        ))
    elif rpc_enabled:
        findings.append(Finding(
            OK, "rpc-cookie-auth",
            "RPC appears to use cookie authentication",
            "No rpcuser/rpcpassword/rpcauth is set while the RPC server is "
            "enabled, so Bitcoin Core falls back to its `.cookie` file auth — "
            "the recommended default for local use.",
            "Keep the datadir (and the .cookie file) readable only by the "
            "bitcoind user: `chmod 700` on the datadir.",
        ))

    if rpcusers and not rpcpasswords and not rpcauths:
        findings.append(Finding(
            LOW, "rpc-user-without-secret",
            "rpcuser set without rpcpassword/rpcauth",
            "An `rpcuser` is defined but no matching secret — this combination "
            "does not establish password auth and is likely a leftover.",
            "Remove the dangling rpcuser, or complete the setup with rpcauth.",
        ))

    for cidr in rpcallowips:
        c = cidr.strip()
        if c in ("0.0.0.0/0", "::/0", "0.0.0.0", "::"):
            findings.append(Finding(
                CRITICAL, "rpc-allowip-world",
                f"RPC allowed from the entire internet (rpcallowip={c})",
                "`rpcallowip` permits every source address. Combined with a "
                "public rpcbind this exposes full node control to anyone who "
                "can reach the port.",
                "Restrict rpcallowip to specific hosts/subnets you control "
                "(e.g. 127.0.0.1 or 10.0.0.0/24). Never use 0.0.0.0/0.",
            ))
        elif re.search(r"/(0|[1-7])$", c):
            findings.append(Finding(
                HIGH, "rpc-allowip-broad",
                f"RPC allowed from a very broad range (rpcallowip={c})",
                "This CIDR covers a huge address space — far more hosts than a "
                "node normally needs to trust with RPC.",
                "Narrow it to the exact admin host(s) or a small private subnet.",
            ))

    broad_allow = any(
        c.strip() in ("0.0.0.0/0", "::/0", "0.0.0.0", "::") or
        re.search(r"/(0|[1-7])$", c.strip())
        for c in rpcallowips
    )
    for b in rpcbinds:
        host = host_from_bind(b)
        if not is_loopback(host) and not is_wildcard(host):
            findings.append(Finding(
                CRITICAL if broad_allow else HIGH, "rpc-bind-public",
                f"RPC bound to a non-loopback interface (rpcbind={b})",
                "The RPC server is listening on an interface other than "
                "localhost, so it is reachable off-box. RPC is a full-control "
                "interface and should almost never be exposed.",
                "Bind RPC to 127.0.0.1 only. For remote admin use an SSH tunnel "
                "or WireGuard, not a public bind.",
            ))
        elif is_wildcard(host):
            findings.append(Finding(
                CRITICAL if broad_allow else HIGH, "rpc-bind-wildcard",
                f"RPC bound to all interfaces (rpcbind={b})",
                "`rpcbind` is set to a wildcard address, exposing RPC on every "
                "interface including public ones.",
                "Set rpcbind=127.0.0.1 and tunnel in for remote access.",
            ))

    if server == "1":
        findings.append(Finding(
            INFO, "rpc-server-on",
            "RPC server is enabled (server=1)",
            "The JSON-RPC server is on. That is normal for a node you "
            "administer; just make sure it is bound to localhost and "
            "authenticated (see the checks above).",
        ))

    if not findings:
        findings.append(Finding(
            OK, "config-clean",
            "No RPC exposure issues found in config",
            "The parsed configuration did not reveal plaintext secrets, broad "
            "rpcallowip ranges, or public RPC binds.",
        ))
    return findings


def check_permissions(path: str, values: dict[str, list[str]]) -> list[Finding]:
    findings: list[Finding] = []
    try:
        st = os.stat(path)
    except OSError:
        return findings
    has_secret = bool(_all(values, "rpcpassword") or _all(values, "rpcauth"))
    perms = stat.S_IMODE(st.st_mode)
    if perms & 0o077 and has_secret:
        findings.append(Finding(
            HIGH, "conf-perms-secret",
            f"bitcoin.conf is group/other readable ({oct(perms)})",
            "The config holds RPC credentials yet is readable beyond its owner. "
            "Any local user can lift the secret.",
            f"chmod 600 {path}  (and ensure it is owned by the bitcoind user).",
        ))
    elif perms & 0o077:
        findings.append(Finding(
            LOW, "conf-perms",
            f"bitcoin.conf is group/other readable ({oct(perms)})",
            "No plaintext secret was found, but tightening permissions is good "
            "hygiene since the file reveals your node topology.",
            f"chmod 640 {path} (or 600).",
        ))
    return findings


def check_sockets() -> list[Finding]:
    findings: list[Finding] = []
    listeners, err = local_listeners()
    if err:
        findings.append(Finding(
            INFO, "sockets-unavailable",
            "Could not inspect local sockets",
            err, "Install iproute2 (ss), or run with --no-sockets to silence this.",
        ))
        return findings

    exposed = False
    for host, port in listeners:
        if port in RPC_PORTS and is_public_bind(host):
            exposed = True
            findings.append(Finding(
                CRITICAL, "socket-rpc-public",
                f"RPC port {port} is listening on {host} (off-box reachable)",
                "A Bitcoin RPC port is bound to a non-loopback address. If a "
                "firewall is not blocking it, the full-control RPC interface is "
                "reachable from other machines.",
                f"Bind RPC to 127.0.0.1 and/or block the port: `sudo ufw deny {port}/tcp`.",
            ))
        elif port in P2P_PORTS and is_public_bind(host):
            findings.append(Finding(
                INFO, "socket-p2p-public",
                f"P2P port {port} is listening on {host}",
                "The peer-to-peer port is public. This is normal and expected "
                "for a reachable node — it is how you serve blocks to peers.",
                "No action needed unless you intended the node to stay private "
                "(then set listen=0 or firewall the P2P port).",
            ))
    if not exposed and not findings:
        findings.append(Finding(
            OK, "sockets-clean",
            "No RPC port exposed on a public interface",
            "No Bitcoin RPC port was found listening on a non-loopback address.",
        ))
    return findings


# --------------------------------------------------------------------------- #
# Config discovery / main
# --------------------------------------------------------------------------- #

def default_conf_paths() -> list[str]:
    home = os.path.expanduser("~")
    candidates = [
        os.path.join(home, ".bitcoin", "bitcoin.conf"),
        os.path.join(home, "Library", "Application Support", "Bitcoin", "bitcoin.conf"),
        os.path.join(os.environ.get("APPDATA", ""), "Bitcoin", "bitcoin.conf"),
        "/etc/bitcoin/bitcoin.conf",
    ]
    return [p for p in candidates if p and os.path.isfile(p)]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Local, read-only security auditor for a Bitcoin Core node "
                    "you own or are authorized to audit.",
    )
    parser.add_argument("--conf", help="Path to bitcoin.conf (auto-detected if omitted).")
    parser.add_argument("--output", help="Write a Markdown report to this file.")
    parser.add_argument("--json", action="store_true", help="Emit findings as JSON.")
    parser.add_argument("--no-sockets", action="store_true",
                        help="Skip the local listening-socket check.")
    args = parser.parse_args(argv)

    findings: list[Finding] = []

    conf_path = args.conf
    if not conf_path:
        found = default_conf_paths()
        conf_path = found[0] if found else None

    if conf_path and os.path.isfile(conf_path):
        try:
            values = parse_conf(conf_path)
            findings += check_config(values)
            findings += check_permissions(conf_path, values)
        except OSError as exc:
            findings.append(Finding(INFO, "conf-read-error",
                                    "Could not read bitcoin.conf",
                                    f"{conf_path}: {exc}"))
    else:
        findings.append(Finding(
            INFO, "conf-not-found", "No bitcoin.conf found",
            "No config was given with --conf and none was found in the usual "
            "locations. The config-based checks were skipped.",
            "Pass --conf /path/to/bitcoin.conf to audit a specific node.",
        ))

    if not args.no_sockets:
        findings += check_sockets()

    if args.json:
        print(json.dumps([asdict(f) for f in sort_findings(findings)],
                         indent=2, ensure_ascii=False))
    else:
        print(render_terminal(findings))

    if args.output:
        meta = [("Config", f"`{conf_path or 'not found'}`")]
        if hasattr(os, "uname"):
            meta.append(("Host", f"`{os.uname().nodename}`"))
        try:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(render_markdown(
                    findings, "Bitcoin Node Security Audit", meta,
                    "This audit only inspected local configuration and local "
                    "listening sockets. No network scanning, authentication "
                    "attempts, or remote connections were performed."))
            if not args.json:
                print(f"\n[+] Markdown report written to {args.output}")
        except OSError as exc:
            print(f"[!] Could not write report: {exc}", file=sys.stderr)

    return worst_exit_code(findings)


if __name__ == "__main__":
    raise SystemExit(main())
