#!/usr/bin/env python3
"""
node_audit.py — Local security auditor for Bitcoin Core nodes.

This is a DEFENSIVE, READ-ONLY tool. It is the opposite of an attack tool:

  * It does NOT scan remote hosts.
  * It does NOT connect to the network or send any traffic.
  * It does NOT brute-force or guess credentials.

It inspects, on the machine it runs on:
  1. your bitcoin.conf  (configuration mistakes that expose the RPC interface)
  2. the file permissions of that config (secrets readable by other users)
  3. the local listening sockets (is the RPC port exposed to the world?)

...and prints a report of what is weak and exactly how to fix it.

Run it on a node you own or are explicitly authorized to audit. Because it
only reads local files and local sockets, it cannot be pointed at a third
party — which is the whole point.

Usage:
    python3 node_audit.py                         # auto-detect bitcoin.conf
    python3 node_audit.py --conf /path/to/bitcoin.conf
    python3 node_audit.py --output report.md      # also write a Markdown report
    python3 node_audit.py --json                   # machine-readable output
    python3 node_audit.py --no-sockets             # skip local socket check
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import shutil
import stat
import subprocess
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone

# --------------------------------------------------------------------------- #
# Severity model
# --------------------------------------------------------------------------- #

CRITICAL = "CRITICAL"
HIGH = "HIGH"
MEDIUM = "MEDIUM"
LOW = "LOW"
INFO = "INFO"
OK = "OK"

SEVERITY_ORDER = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4, OK: 5}
SEVERITY_LABEL = {
    CRITICAL: "🔴 CRITICAL",
    HIGH: "🟠 HIGH",
    MEDIUM: "🟡 MEDIUM",
    LOW: "🔵 LOW",
    INFO: "⚪ INFO",
    OK: "🟢 OK",
}

# Default RPC / P2P ports for mainnet, testnet, signet, regtest.
RPC_PORTS = {8332, 18332, 38332, 18443}
P2P_PORTS = {8333, 18333, 38333, 18444}

LOOPBACK_PREFIXES = ("127.", "::1", "[::1]")
WILDCARD_ADDRS = {"0.0.0.0", "*", "::", "[::]", ""}


@dataclass
class Finding:
    severity: str
    check: str          # short id, e.g. "rpc-allowip-world"
    title: str
    detail: str
    remediation: str = ""


# --------------------------------------------------------------------------- #
# bitcoin.conf parsing
# --------------------------------------------------------------------------- #

# bitcoin.conf is `key=value`, one per line, `#` comments, with optional
# network sections like [main] / [test] / [signet] / [regtest]. Some keys
# (rpcallowip, rpcauth, rpcbind, bind, connect) may legitimately repeat, so we
# keep every occurrence.
NETWORK_SECTIONS = {"main", "test", "signet", "regtest"}


def parse_conf(path: str) -> dict[str, list[str]]:
    """Parse bitcoin.conf into {key: [values...]}.

    Section-qualified keys are stored as "<section>.<key>" in addition to the
    bare key, so `[test] rpcallowip=...` is visible but distinguishable.
    """
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
            val = val.split("#", 1)[0].strip()  # trailing inline comment
            values.setdefault(key, []).append(val)
            if section in NETWORK_SECTIONS:
                values.setdefault(f"{section}.{key}", []).append(val)
    return values


def _first(values: dict[str, list[str]], key: str) -> str | None:
    got = values.get(key)
    return got[0] if got else None


def _all(values: dict[str, list[str]], key: str) -> list[str]:
    """All occurrences of a key across the global scope and any network
    section (so `rpcallowip` and `test.rpcallowip` are both returned)."""
    out = list(values.get(key, []))
    for net in NETWORK_SECTIONS:
        out.extend(values.get(f"{net}.{key}", []))
    return out


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def is_loopback(addr: str) -> bool:
    addr = addr.strip()
    return addr.startswith(LOOPBACK_PREFIXES)


def is_wildcard(addr: str) -> bool:
    return addr.strip() in WILDCARD_ADDRS


def password_entropy_bits(pw: str) -> float:
    """Rough Shannon upper bound: len * log2(charset size)."""
    if not pw:
        return 0.0
    charset = 0
    if re.search(r"[a-z]", pw):
        charset += 26
    if re.search(r"[A-Z]", pw):
        charset += 26
    if re.search(r"[0-9]", pw):
        charset += 10
    if re.search(r"[^A-Za-z0-9]", pw):
        charset += 33
    charset = max(charset, 1)
    return len(pw) * math.log2(charset)


def host_from_bind(value: str) -> str:
    """Extract the host portion of an rpcbind/bind value like '0.0.0.0:8332',
    '[::]:8333', '127.0.0.1' or 'example.lan'."""
    v = value.strip()
    if v.startswith("["):  # bracketed IPv6, maybe with :port
        end = v.find("]")
        if end != -1:
            return v[: end + 1]
    # If there's exactly one ':' treat the left side as host:port.
    if v.count(":") == 1:
        return v.rsplit(":", 1)[0]
    return v


# --------------------------------------------------------------------------- #
# Config checks
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

    # --- Authentication method -------------------------------------------- #
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
            "",
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

    # --- rpcallowip: who may reach the RPC -------------------------------- #
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

    # --- rpcbind: which interface the RPC listens on ---------------------- #
    broad_allow = any(
        c.strip() in ("0.0.0.0/0", "::/0", "0.0.0.0", "::") or
        re.search(r"/(0|[1-7])$", c.strip())
        for c in rpcallowips
    )
    for b in rpcbinds:
        host = host_from_bind(b)
        if not is_loopback(host) and not is_wildcard(host):
            sev = CRITICAL if broad_allow else HIGH
            findings.append(Finding(
                sev, "rpc-bind-public",
                f"RPC bound to a non-loopback interface (rpcbind={b})",
                "The RPC server is listening on an interface other than "
                "localhost, so it is reachable off-box. RPC is a full-control "
                "interface and should almost never be exposed.",
                "Bind RPC to 127.0.0.1 only. If you need remote admin, reach it "
                "over an SSH tunnel or WireGuard, not a public bind.",
            ))
        elif is_wildcard(host):
            findings.append(Finding(
                CRITICAL if broad_allow else HIGH, "rpc-bind-wildcard",
                f"RPC bound to all interfaces (rpcbind={b})",
                "`rpcbind` is set to a wildcard address, exposing RPC on every "
                "interface including public ones.",
                "Set rpcbind=127.0.0.1 and tunnel in for remote access.",
            ))

    # --- RPC enabled awareness -------------------------------------------- #
    if server == "1":
        findings.append(Finding(
            INFO, "rpc-server-on",
            "RPC server is enabled (server=1)",
            "The JSON-RPC server is on. That is normal for a node you "
            "administer; just make sure it is bound to localhost and "
            "authenticated (see the checks above).",
            "",
        ))

    if not findings:
        findings.append(Finding(
            OK, "config-clean",
            "No RPC exposure issues found in config",
            "The parsed configuration did not reveal plaintext secrets, broad "
            "rpcallowip ranges, or public RPC binds.",
            "",
        ))
    return findings


# --------------------------------------------------------------------------- #
# File permission check
# --------------------------------------------------------------------------- #

def check_permissions(path: str, values: dict[str, list[str]]) -> list[Finding]:
    findings: list[Finding] = []
    try:
        st = os.stat(path)
    except OSError:
        return findings
    mode = st.st_mode
    has_secret = bool(_all(values, "rpcpassword") or _all(values, "rpcauth"))
    group_other = stat.S_IMODE(mode) & 0o077
    if group_other and has_secret:
        findings.append(Finding(
            HIGH, "conf-perms-secret",
            f"bitcoin.conf is group/other readable ({oct(stat.S_IMODE(mode))})",
            "The config holds RPC credentials yet is readable beyond its owner. "
            "Any local user can lift the secret.",
            f"chmod 600 {path}  (and ensure it is owned by the bitcoind user).",
        ))
    elif group_other:
        findings.append(Finding(
            LOW, "conf-perms",
            f"bitcoin.conf is group/other readable ({oct(stat.S_IMODE(mode))})",
            "No plaintext secret was found, but tightening permissions is good "
            "hygiene since the file reveals your node topology.",
            f"chmod 640 {path} (or 600).",
        ))
    return findings


# --------------------------------------------------------------------------- #
# Local socket check (read-only: inspects THIS machine's listening sockets)
# --------------------------------------------------------------------------- #

def _parse_listen_addr(addr: str) -> tuple[str, int | None]:
    """'0.0.0.0:8332' -> ('0.0.0.0', 8332); '[::]:8333' -> ('[::]', 8333)."""
    a = addr.strip()
    if a.startswith("["):
        end = a.find("]")
        host = a[: end + 1]
        rest = a[end + 1:]
        port = rest[1:] if rest.startswith(":") else ""
    else:
        host, _, port = a.rpartition(":")
        if not host:  # no ':' at all
            host, port = a, ""
    try:
        return host, int(port)
    except ValueError:
        return host, None


def check_sockets() -> list[Finding]:
    findings: list[Finding] = []
    tool = None
    if shutil.which("ss"):
        cmd = ["ss", "-H", "-tlnp"]
        tool = "ss"
    elif shutil.which("netstat"):
        cmd = ["netstat", "-tlnp"]
        tool = "netstat"
    else:
        findings.append(Finding(
            INFO, "sockets-unavailable",
            "Could not inspect local sockets (no ss/netstat)",
            "Neither `ss` nor `netstat` is available, so the local listening "
            "socket check was skipped.",
            "Install iproute2 (ss) to enable this check, or run with "
            "--no-sockets to silence this note.",
        ))
        return findings

    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=10).stdout
    except (subprocess.SubprocessError, OSError) as exc:
        findings.append(Finding(
            INFO, "sockets-error",
            "Local socket inspection failed",
            f"Running `{' '.join(cmd)}` failed: {exc}",
            "",
        ))
        return findings

    seen_exposed = False
    for line in out.splitlines():
        parts = line.split()
        if not parts:
            continue
        # Find the local-address token (contains a ':'); differs by tool/version.
        local = None
        if tool == "ss":
            # ss -H columns: State Recv-Q Send-Q Local Peer [Process]
            local = parts[3] if len(parts) >= 4 else None
        else:
            # netstat: Proto Recv-Q Send-Q Local Foreign State [PID/Program]
            local = parts[3] if len(parts) >= 4 else None
        if not local or ":" not in local:
            continue
        host, port = _parse_listen_addr(local)
        if port is None:
            continue
        public = is_wildcard(host) or (not is_loopback(host))
        if port in RPC_PORTS and public:
            seen_exposed = True
            findings.append(Finding(
                CRITICAL, "socket-rpc-public",
                f"RPC port {port} is listening on {host} (off-box reachable)",
                "A Bitcoin RPC port is bound to a non-loopback address. If a "
                "firewall is not blocking it, the full-control RPC interface is "
                "reachable from other machines.",
                "Bind RPC to 127.0.0.1 (rpcbind=127.0.0.1) and/or block the "
                "port at the firewall: `sudo ufw deny {}/tcp`.".format(port),
            ))
        elif port in P2P_PORTS and public:
            findings.append(Finding(
                INFO, "socket-p2p-public",
                f"P2P port {port} is listening on {host}",
                "The peer-to-peer port is public. This is normal and expected "
                "for a reachable node — it is how you serve blocks to peers.",
                "No action needed unless you intended the node to stay private "
                "(then set listen=0 or firewall the P2P port).",
            ))

    if not seen_exposed and not findings:
        findings.append(Finding(
            OK, "sockets-clean",
            "No RPC port exposed on a public interface",
            "No Bitcoin RPC port was found listening on a non-loopback address.",
            "",
        ))
    return findings


# --------------------------------------------------------------------------- #
# Config discovery
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


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #

def render_markdown(findings: list[Finding], conf_path: str | None) -> str:
    findings = sorted(findings, key=lambda f: SEVERITY_ORDER[f.severity])
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines = [
        "# Bitcoin Node Security Audit",
        "",
        f"- Generated: {now}",
        f"- Config: `{conf_path or 'not found'}`",
        f"- Host: `{os.uname().nodename if hasattr(os, 'uname') else 'n/a'}`",
        "",
        "## Summary",
        "",
        "| Severity | Count |",
        "| --- | --- |",
    ]
    for sev in (CRITICAL, HIGH, MEDIUM, LOW, INFO, OK):
        if counts.get(sev):
            lines.append(f"| {SEVERITY_LABEL[sev]} | {counts[sev]} |")
    lines += ["", "## Findings", ""]
    for f in findings:
        lines.append(f"### {SEVERITY_LABEL[f.severity]} — {f.title}")
        lines.append(f"*check: `{f.check}`*")
        lines.append("")
        lines.append(f.detail)
        if f.remediation:
            lines.append("")
            lines.append(f"**Fix:** {f.remediation}")
        lines.append("")
    lines += [
        "---",
        "*This audit only inspected local configuration and local listening "
        "sockets. It performed no network scanning, no authentication attempts, "
        "and no remote connections.*",
    ]
    return "\n".join(lines)


def render_terminal(findings: list[Finding]) -> str:
    findings = sorted(findings, key=lambda f: SEVERITY_ORDER[f.severity])
    out = []
    for f in findings:
        out.append(f"[{SEVERITY_LABEL[f.severity]}] {f.title}")
        out.append(f"    {f.detail}")
        if f.remediation:
            out.append(f"    Fix: {f.remediation}")
        out.append("")
    worst = min((SEVERITY_ORDER[f.severity] for f in findings), default=5)
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    summary = "  ".join(
        f"{SEVERITY_LABEL[s]}:{counts[s]}"
        for s in (CRITICAL, HIGH, MEDIUM, LOW, INFO, OK) if counts.get(s)
    )
    out.append("Summary: " + summary)
    return "\n".join(out)


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #

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
            findings.append(Finding(
                INFO, "conf-read-error",
                "Could not read bitcoin.conf",
                f"{conf_path}: {exc}", "",
            ))
    else:
        findings.append(Finding(
            INFO, "conf-not-found",
            "No bitcoin.conf found",
            "No config was given with --conf and none was found in the usual "
            "locations. The config-based checks were skipped.",
            "Pass --conf /path/to/bitcoin.conf to audit a specific node.",
        ))

    if not args.no_sockets:
        findings += check_sockets()

    if args.json:
        print(json.dumps([asdict(f) for f in
                          sorted(findings, key=lambda f: SEVERITY_ORDER[f.severity])],
                         indent=2, ensure_ascii=False))
    else:
        print(render_terminal(findings))

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(render_markdown(findings, conf_path))
            if not args.json:
                print(f"\n[+] Markdown report written to {args.output}")
        except OSError as exc:
            print(f"[!] Could not write report: {exc}", file=sys.stderr)

    # Exit non-zero if anything CRITICAL or HIGH was found (useful in CI/cron).
    worst = min((SEVERITY_ORDER[f.severity] for f in findings), default=5)
    return 1 if worst <= SEVERITY_ORDER[HIGH] else 0


if __name__ == "__main__":
    raise SystemExit(main())
