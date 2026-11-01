"""
audit_common.py — shared primitives for the Kraken defensive audit suite.

These helpers are used by node_audit.py (Bitcoin Core), miner_audit.py
(ASIC/GPU miners) and lightning_audit.py (lnd/CLN). Everything here is for
DEFENSIVE, read-only checks of systems you own or are authorized to test.

Design rule enforced here: `parse_single_target` refuses ranges, CIDRs and
lists, so any tool built on it can only ever look at ONE host — it cannot be
turned into a mass scanner.
"""

from __future__ import annotations

import math
import re
import shutil
import subprocess
from dataclasses import dataclass
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


@dataclass
class Finding:
    severity: str
    check: str
    title: str
    detail: str
    remediation: str = ""


# --------------------------------------------------------------------------- #
# Address helpers
# --------------------------------------------------------------------------- #

LOOPBACK_PREFIXES = ("127.", "::1", "[::1]")
WILDCARD_ADDRS = {"0.0.0.0", "*", "::", "[::]", ""}


def is_loopback(addr: str) -> bool:
    return addr.strip().startswith(LOOPBACK_PREFIXES)


def is_wildcard(addr: str) -> bool:
    return addr.strip() in WILDCARD_ADDRS


def host_from_bind(value: str) -> str:
    """Host portion of 'ADDR[:port]', handling bracketed IPv6."""
    v = value.strip()
    if v.startswith("["):
        end = v.find("]")
        if end != -1:
            return v[: end + 1]
    if v.count(":") == 1:
        return v.rsplit(":", 1)[0]
    return v


def parse_listen_addr(addr: str) -> tuple[str, int | None]:
    """'0.0.0.0:8332' -> ('0.0.0.0', 8332); '[::]:8333' -> ('[::]', 8333)."""
    a = addr.strip()
    if a.startswith("["):
        end = a.find("]")
        host = a[: end + 1]
        rest = a[end + 1:]
        port = rest[1:] if rest.startswith(":") else ""
    else:
        host, _, port = a.rpartition(":")
        if not host:
            host, port = a, ""
    try:
        return host, int(port)
    except ValueError:
        return host, None


# --------------------------------------------------------------------------- #
# Single-target guard (keeps these tools un-weaponizable)
# --------------------------------------------------------------------------- #

class TargetError(ValueError):
    pass


def parse_single_target(value: str, default_port: int | None = None) -> tuple[str, int | None]:
    """Parse 'host' or 'host:port' into (host, port).

    Refuses anything that denotes more than one host — CIDR ('/'), ranges
    ('-' in the host, '*'), or lists (',' ' '). This is deliberate: the audit
    tools are for one machine you own, not for sweeping a network.
    """
    v = (value or "").strip()
    if not v:
        raise TargetError("empty target")
    if "/" in v or "," in v or " " in v or "*" in v:
        raise TargetError(
            f"'{value}' looks like a range/list/CIDR. These tools audit ONE "
            "host you own — pass a single address like 192.168.1.50 or "
            "miner.lan:4028."
        )
    host, port = host_from_bind(v), None
    # extract :port if present and host isn't bare IPv6
    if not v.startswith("[") and v.count(":") == 1:
        _, _, p = v.rpartition(":")
        try:
            port = int(p)
        except ValueError:
            raise TargetError(f"bad port in '{value}'")
    elif v.startswith("[") and "]:" in v:
        _, _, p = v.rpartition("]:")
        try:
            port = int(p)
        except ValueError:
            raise TargetError(f"bad port in '{value}'")
    # a bare IPv4 octet-range like 10.0.0.1-50 (dash in last octet)
    if re.search(r"-\d+\s*$", host) or re.search(r"\d+-\d+", host):
        raise TargetError(
            f"'{value}' looks like an IP range. One host at a time, please."
        )
    if port is None:
        port = default_port
    return host, port


# --------------------------------------------------------------------------- #
# Secrets / entropy
# --------------------------------------------------------------------------- #

def password_entropy_bits(pw: str) -> float:
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
    return len(pw) * math.log2(max(charset, 1))


# --------------------------------------------------------------------------- #
# Local listening sockets (read-only inspection of THIS machine)
# --------------------------------------------------------------------------- #

def local_listeners() -> tuple[list[tuple[str, int]], str | None]:
    """Return ([(host, port), ...], error_message_or_None) for TCP listeners
    on this machine, via `ss` then `netstat`."""
    if shutil.which("ss"):
        cmd = ["ss", "-H", "-tlnp"]
    elif shutil.which("netstat"):
        cmd = ["netstat", "-tlnp"]
    else:
        return [], "Neither `ss` nor `netstat` is available."
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=10).stdout
    except (subprocess.SubprocessError, OSError) as exc:
        return [], f"Running `{' '.join(cmd)}` failed: {exc}"

    listeners: list[tuple[str, int]] = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        local = parts[3]
        if ":" not in local:
            continue
        host, port = parse_listen_addr(local)
        if port is not None:
            listeners.append((host, port))
    return listeners, None


def is_public_bind(host: str) -> bool:
    """True if a listener on `host` is reachable from off-box."""
    return is_wildcard(host) or not is_loopback(host)


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #

def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 9))


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts


def worst_exit_code(findings: list[Finding]) -> int:
    """1 if any CRITICAL/HIGH finding is present, else 0 (handy for cron/CI)."""
    worst = min((SEVERITY_ORDER.get(f.severity, 9) for f in findings), default=9)
    return 1 if worst <= SEVERITY_ORDER[HIGH] else 0


def render_terminal(findings: list[Finding]) -> str:
    findings = sort_findings(findings)
    out: list[str] = []
    for f in findings:
        out.append(f"[{SEVERITY_LABEL.get(f.severity, f.severity)}] {f.title}")
        out.append(f"    {f.detail}")
        if f.remediation:
            out.append(f"    Fix: {f.remediation}")
        out.append("")
    counts = severity_counts(findings)
    summary = "  ".join(
        f"{SEVERITY_LABEL[s]}:{counts[s]}"
        for s in (CRITICAL, HIGH, MEDIUM, LOW, INFO, OK) if counts.get(s)
    )
    out.append("Summary: " + (summary or "no findings"))
    return "\n".join(out)


def render_markdown(findings: list[Finding], title: str,
                    meta: list[tuple[str, str]] | None = None,
                    footer_note: str = "") -> str:
    findings = sort_findings(findings)
    counts = severity_counts(findings)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines = [f"# {title}", "", f"- Generated: {now}"]
    for k, v in (meta or []):
        lines.append(f"- {k}: {v}")
    lines += ["", "## Summary", "", "| Severity | Count |", "| --- | --- |"]
    for sev in (CRITICAL, HIGH, MEDIUM, LOW, INFO, OK):
        if counts.get(sev):
            lines.append(f"| {SEVERITY_LABEL[sev]} | {counts[sev]} |")
    lines += ["", "## Findings", ""]
    for f in findings:
        lines.append(f"### {SEVERITY_LABEL.get(f.severity, f.severity)} — {f.title}")
        lines.append(f"*check: `{f.check}`*")
        lines.append("")
        lines.append(f.detail)
        if f.remediation:
            lines.append("")
            lines.append(f"**Fix:** {f.remediation}")
        lines.append("")
    if footer_note:
        lines += ["---", f"*{footer_note}*"]
    return "\n".join(lines)
