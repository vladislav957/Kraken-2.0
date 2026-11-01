"""
kraken_core.py — the audit engine (the "core").

A single, UI-agnostic API that runs the read-only auditors and returns
structured results. The CLI tools, the desktop app, or any other front-end all
call this; the audit logic itself lives in node_audit / lightning_audit /
miner_audit and is covered by the tests.

Nothing here scans networks, brute-forces, or attacks anything — it reuses the
same defensive, read-only checks.

    from kraken_core import audit_node, audit_lightning, audit_miner, overall
    res = audit_node("~/.bitcoin/bitcoin.conf")
    print(res.exit_code, res.summary)
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, asdict

import audit_common as ac
import node_audit
import lightning_audit
import miner_audit

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "OK"]
# How many points each finding subtracts from a perfect 100.
_WEIGHT = {"CRITICAL": 30, "HIGH": 15, "MEDIUM": 7, "LOW": 3, "INFO": 0, "OK": 0}


@dataclass
class AuditResult:
    tool: str
    meta: dict
    findings: list                      # list[audit_common.Finding]
    summary: dict = field(default_factory=dict)
    exit_code: int = 0

    def __post_init__(self):
        self.findings = ac.sort_findings(self.findings)
        self.summary = ac.severity_counts(self.findings)
        self.exit_code = ac.worst_exit_code(self.findings)

    @property
    def worst(self) -> str:
        for sev in SEVERITY_ORDER:
            if self.summary.get(sev):
                return sev
        return "OK"

    def to_dict(self) -> dict:
        return {
            "tool": self.tool, "meta": self.meta,
            "exit_code": self.exit_code, "summary": self.summary,
            "findings": [asdict(f) for f in self.findings],
        }


# --------------------------------------------------------------------------- #
# Audits
# --------------------------------------------------------------------------- #

def _expand(path):
    return os.path.expanduser(path.strip()) if path else path


def audit_node(conf: str | None = None, check_sockets: bool = True) -> AuditResult:
    conf = _expand(conf) or ""
    findings = []
    if not conf:
        found = node_audit.default_conf_paths()
        conf = found[0] if found else ""
    if conf and os.path.isfile(conf):
        values = node_audit.parse_conf(conf)
        findings += node_audit.check_config(values)
        findings += node_audit.check_permissions(conf, values)
    else:
        findings.append(ac.Finding(
            ac.INFO, "conf-not-found", "No bitcoin.conf found",
            "Point this at a bitcoin.conf you own.",
            "e.g. ~/.bitcoin/bitcoin.conf"))
    if check_sockets:
        findings += node_audit.check_sockets()
    return AuditResult("node", {"conf": conf or "(none)"}, findings)


def audit_lightning(impl: str = "auto", conf: str | None = None,
                    node_dir: str | None = None,
                    check_sockets: bool = True) -> AuditResult:
    impl, conf = lightning_audit.detect_impl_and_conf(_expand(conf) or None, impl)
    node_dir = _expand(node_dir) or None
    findings = []
    if conf and os.path.isfile(conf):
        values = lightning_audit.parse_kv(conf)
        findings += (lightning_audit.check_lnd(values, node_dir) if impl == "lnd"
                     else lightning_audit.check_cln(values, node_dir))
    else:
        findings.append(ac.Finding(
            ac.INFO, "conf-not-found", f"No {impl} config found",
            "Point this at your lnd.conf or CLN config.", ""))
    if check_sockets:
        findings += lightning_audit.check_sockets()
    return AuditResult("lightning", {"impl": impl, "conf": conf or "(none)"}, findings)


def audit_miner(target: str, api_port: int = 4028,
                check_web: bool = True) -> AuditResult:
    """Single-target only. Raises TargetError on a range/CIDR/list."""
    host, port = ac.parse_single_target(target, default_port=api_port)
    findings = miner_audit.check_api(host, port)
    if check_web:
        findings += miner_audit.check_web(host)
    return AuditResult("miner", {"target": f"{host}:{port}"}, findings)


# --------------------------------------------------------------------------- #
# Aggregate score (for a status widget)
# --------------------------------------------------------------------------- #

@dataclass
class Score:
    score: int           # 0..100
    grade: str           # A..F
    worst: str           # worst severity across results
    label: str           # human status
    totals: dict         # severity -> count


_STATUS = {
    "CRITICAL": "Critical exposure", "HIGH": "Needs hardening",
    "MEDIUM": "Minor issues", "LOW": "Minor issues",
    "INFO": "Looks good", "OK": "Hardened",
}


def overall(results) -> Score:
    """Aggregate a list of AuditResult into a single score/status."""
    totals = {s: 0 for s in SEVERITY_ORDER}
    penalty = 0
    have = False
    for r in results:
        if not r:
            continue
        have = True
        for sev, n in r.summary.items():
            totals[sev] = totals.get(sev, 0) + n
            penalty += _WEIGHT.get(sev, 0) * n
    if not have:
        return Score(100, "–", "OK", "No audit run yet", totals)
    score = max(0, 100 - penalty)
    worst = "OK"
    for sev in SEVERITY_ORDER:
        if totals.get(sev):
            worst = sev
            break
    grade = ("A" if score >= 90 else "B" if score >= 75 else
             "C" if score >= 60 else "D" if score >= 40 else "F")
    return Score(score, grade, worst, _STATUS.get(worst, "Reviewed"), totals)
