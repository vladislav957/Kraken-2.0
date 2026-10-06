#!/usr/bin/env python3
"""
lightning_audit.py — Local security auditor for Lightning nodes (lnd / CLN).

DEFENSIVE and READ-ONLY, like node_audit.py. It inspects local configuration,
credential-file permissions, and local listening sockets. It makes no network
connections and tests no credentials.

Checks:
  lnd  — rpclisten/restlisten exposure, no-macaroons, admin.macaroon file
         permissions, exposed gRPC(10009)/REST(8080) sockets.
  CLN  — grpc/clnrest exposure, lightning-rpc socket permissions.

    python3 lightning_audit.py --impl lnd  --conf ~/.lnd/lnd.conf --output report.md
    python3 lightning_audit.py --impl cln  --conf ~/.lightning/config
    python3 lightning_audit.py                      # auto-detect
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import re
import stat
import sys
from dataclasses import asdict

from audit_common import (
    CRITICAL, HIGH, MEDIUM, LOW, INFO, OK,
    Finding, host_from_bind, is_public_bind, is_loopback, local_listeners,
    render_markdown, render_terminal, sort_findings, worst_exit_code,
)

LND_GRPC_PORTS = {10009}
LND_REST_PORTS = {8080, 8443}
LN_P2P_PORTS = {9735, 9736}
CLN_GRPC_REST_PORTS = {9736, 3010}   # common grpc-port / clnrest defaults


# --------------------------------------------------------------------------- #
# Parsing (both lnd.conf and CLN config are key=value with # comments)
# --------------------------------------------------------------------------- #

def parse_kv(path: str) -> dict[str, list[str]]:
    values: dict[str, list[str]] = {}
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#") or line.startswith(";"):
                continue
            if line.startswith("[") and line.endswith("]"):
                continue   # lnd section header — keys are flat, ignore section
            if "=" not in line:
                continue
            key, _, val = line.partition("=")
            values.setdefault(key.strip().lower(), []).append(
                val.split("#", 1)[0].strip())
    return values


def _truthy(val: str | None) -> bool:
    return (val or "").strip().lower() in ("1", "true", "yes", "on")


def _perm_finding(path: str, label: str, world_sev: str) -> Finding | None:
    try:
        perms = stat.S_IMODE(os.stat(path).st_mode)
    except OSError:
        return None
    if perms & 0o077:
        return Finding(
            world_sev, "ln-file-perms",
            f"{label} is group/other accessible ({oct(perms)})",
            f"`{path}` controls your node but is readable/writable beyond its "
            "owner. Any local user who reads it can control the node and move "
            "funds.",
            f"chmod 600 {path} (CLN's lightning-rpc socket: ensure the dir is "
            "0700 and owner-only).",
        )
    return None


# --------------------------------------------------------------------------- #
# lnd
# --------------------------------------------------------------------------- #

def check_lnd(values: dict[str, list[str]], lnd_dir: str | None) -> list[Finding]:
    findings: list[Finding] = []

    for val in values.get("rpclisten", []):
        host = host_from_bind(val)
        if is_public_bind(host):
            findings.append(Finding(
                CRITICAL, "lnd-grpc-exposed",
                f"lnd gRPC exposed (rpclisten={val})",
                "lnd's gRPC is its full-control interface. Binding it to a "
                "non-loopback address exposes node control (subject to macaroon "
                "auth) to the network.",
                "Set rpclisten=127.0.0.1:10009 and reach it over an SSH tunnel "
                "or WireGuard. If remote access is required, scope it with TLS "
                "(tlsextraip) AND a restricted macaroon, never the admin one.",
            ))
    for val in values.get("restlisten", []):
        host = host_from_bind(val)
        if is_public_bind(host):
            findings.append(Finding(
                HIGH, "lnd-rest-exposed",
                f"lnd REST exposed (restlisten={val})",
                "The REST proxy is bound to a public interface, widening the "
                "attack surface of the control API.",
                "Bind restlisten to 127.0.0.1 and tunnel in, or disable REST if "
                "unused.",
            ))

    if any(_truthy(v) for v in values.get("no-macaroons", [])):
        findings.append(Finding(
            CRITICAL, "lnd-macaroons-disabled",
            "lnd authentication disabled (no-macaroons=true)",
            "Macaroon auth is off. Anything that can reach the gRPC/REST port "
            "has unauthenticated full control of the node and its funds.",
            "Remove no-macaroons and use macaroon auth. Keep admin.macaroon "
            "owner-only; hand out bakery-minted scoped macaroons to apps.",
        ))

    for val in values.get("tlsextraip", []) + values.get("tlsextradomain", []):
        findings.append(Finding(
            INFO, "lnd-tls-extra",
            f"lnd TLS cert covers an external endpoint ({val})",
            "You've added an external IP/domain to the TLS certificate, which "
            "implies remote access. That can be fine — just make sure only "
            "scoped macaroons leave the host, never admin.macaroon.",
            "Mint a restricted macaroon (lncli bakemacaroon) per client.",
        ))

    # admin.macaroon permissions
    search_dirs = [lnd_dir] if lnd_dir else [
        os.path.expanduser("~/.lnd"), "/etc/lnd"]
    seen = False
    for base in filter(None, search_dirs):
        for mac in glob.glob(os.path.join(base, "data", "chain", "*", "*", "admin.macaroon")):
            seen = True
            f = _perm_finding(mac, "admin.macaroon", HIGH)
            if f:
                findings.append(f)
    if seen and not any(f.check == "ln-file-perms" for f in findings):
        findings.append(Finding(
            OK, "lnd-macaroon-perms-ok",
            "admin.macaroon permissions look owner-only",
            "The admin macaroon(s) found are not group/other accessible.",
        ))

    if not findings:
        findings.append(Finding(
            OK, "lnd-clean",
            "No lnd exposure issues found in config",
            "rpclisten/restlisten are loopback, macaroons are enabled, and no "
            "exposed credential files were detected.",
        ))
    return findings


# --------------------------------------------------------------------------- #
# CLN
# --------------------------------------------------------------------------- #

def check_cln(values: dict[str, list[str]], ln_dir: str | None) -> list[Finding]:
    findings: list[Finding] = []

    # grpc-port exposure depends on bind-addr; flag if grpc enabled AND a public
    # bind-addr/addr exists.
    grpc_on = bool(values.get("grpc-port"))
    public_bind = any(is_public_bind(host_from_bind(v))
                      for v in values.get("bind-addr", []) + values.get("addr", []))
    if grpc_on and public_bind:
        findings.append(Finding(
            HIGH, "cln-grpc-exposed",
            "CLN gRPC may be exposed (grpc-port set with a public bind-addr)",
            "grpc-port is enabled and a public bind-addr/addr is configured, so "
            "the gRPC control interface may be reachable off-box.",
            "Bind gRPC to localhost and tunnel in; keep public addr for P2P "
            "(9735) only.",
        ))
    for val in values.get("clnrest-port", []) + values.get("rest-port", []):
        if public_bind:
            findings.append(Finding(
                HIGH, "cln-rest-exposed",
                f"CLN REST (clnrest) may be exposed (port {val} with public bind)",
                "The clnrest HTTP API is enabled alongside a public bind. Its "
                "rune-authenticated endpoints would be reachable off-box.",
                "Bind clnrest to 127.0.0.1 and require strong runes; tunnel for "
                "remote use.",
            ))

    # lightning-rpc unix socket permissions (anyone who can write it controls CLN)
    search_dirs = [ln_dir] if ln_dir else [os.path.expanduser("~/.lightning")]
    seen = False
    for base in filter(None, search_dirs):
        for sock in glob.glob(os.path.join(base, "**", "lightning-rpc"), recursive=True):
            seen = True
            f = _perm_finding(sock, "lightning-rpc socket", CRITICAL)
            if f:
                findings.append(f)
    if seen and not any(f.check == "ln-file-perms" for f in findings):
        findings.append(Finding(
            OK, "cln-socket-perms-ok",
            "lightning-rpc socket permissions look owner-only",
            "The control socket(s) found are not group/other accessible.",
        ))

    if not findings:
        findings.append(Finding(
            OK, "cln-clean",
            "No CLN exposure issues found in config",
            "No public gRPC/REST bind and no world-accessible control socket "
            "were detected.",
        ))
    return findings


# --------------------------------------------------------------------------- #
# Sockets
# --------------------------------------------------------------------------- #

def check_sockets() -> list[Finding]:
    findings: list[Finding] = []
    listeners, err = local_listeners()
    if err:
        return [Finding(INFO, "sockets-unavailable",
                        "Could not inspect local sockets", err,
                        "Install iproute2 (ss), or run with --no-sockets.")]
    flagged = False
    for host, port in listeners:
        if not is_public_bind(host):
            continue
        if port in LND_GRPC_PORTS:
            flagged = True
            findings.append(Finding(
                CRITICAL, "socket-ln-grpc",
                f"Lightning gRPC port {port} listening on {host}",
                "The lnd gRPC control port is bound off-loopback.",
                "Rebind to 127.0.0.1 and/or firewall the port.",
            ))
        elif port in LND_REST_PORTS or port in CLN_GRPC_REST_PORTS:
            flagged = True
            findings.append(Finding(
                HIGH, "socket-ln-rest",
                f"Lightning REST/gRPC port {port} listening on {host}",
                "A Lightning REST/gRPC control port is reachable off-box.",
                "Rebind to localhost and/or firewall the port.",
            ))
        elif port in LN_P2P_PORTS:
            findings.append(Finding(
                INFO, "socket-ln-p2p",
                f"Lightning P2P port {port} listening on {host}",
                "The Lightning peer port is public. Normal for a routing node.",
                "No action needed unless the node should stay private.",
            ))
    if not flagged and not findings:
        findings.append(Finding(
            OK, "sockets-clean",
            "No Lightning control port exposed on a public interface",
            "No lnd/CLN gRPC or REST control port was found listening off-box.",
        ))
    return findings


# --------------------------------------------------------------------------- #
# Discovery / main
# --------------------------------------------------------------------------- #

def detect_impl_and_conf(explicit_conf: str | None, impl: str) -> tuple[str, str | None]:
    if explicit_conf:
        if impl == "auto":
            impl = "cln" if "lightning" in explicit_conf.lower() else "lnd"
        return impl, explicit_conf
    candidates = {
        "lnd": [os.path.expanduser("~/.lnd/lnd.conf"), "/etc/lnd/lnd.conf"],
        "cln": [os.path.expanduser("~/.lightning/config"),
                os.path.expanduser("~/.lightning/bitcoin/config"),
                "/etc/lightning/config"],
    }
    order = [impl] if impl != "auto" else ["lnd", "cln"]
    for imp in order:
        for path in candidates[imp]:
            if os.path.isfile(path):
                return imp, path
    return (impl if impl != "auto" else "lnd"), None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Local, read-only security auditor for a Lightning node you "
                    "own (lnd or CLN).")
    parser.add_argument("--impl", choices=["lnd", "cln", "auto"], default="auto")
    parser.add_argument("--conf", help="Path to lnd.conf or CLN config.")
    parser.add_argument("--dir", help="Node home dir (~/.lnd or ~/.lightning) "
                                      "for macaroon/socket permission checks.")
    parser.add_argument("--output", help="Write a Markdown report to this file.")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--no-sockets", action="store_true")
    args = parser.parse_args(argv)

    impl, conf = detect_impl_and_conf(args.conf, args.impl)
    findings: list[Finding] = []

    if conf and os.path.isfile(conf):
        try:
            values = parse_kv(conf)
            findings += check_lnd(values, args.dir) if impl == "lnd" \
                else check_cln(values, args.dir)
        except OSError as exc:
            findings.append(Finding(INFO, "conf-read-error",
                                    f"Could not read {conf}", str(exc)))
    else:
        findings.append(Finding(
            INFO, "conf-not-found", f"No {impl} config found",
            "No config was given with --conf and none was auto-detected.",
            "Pass --impl lnd|cln and --conf /path/to/config."))

    if not args.no_sockets:
        findings += check_sockets()

    if args.json:
        print(json.dumps([asdict(f) for f in sort_findings(findings)],
                         indent=2, ensure_ascii=False))
    else:
        print(render_terminal(findings))

    if args.output:
        meta = [("Implementation", impl), ("Config", f"`{conf or 'not found'}`")]
        try:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(render_markdown(
                    findings, "Lightning Node Security Audit", meta,
                    "Local-only audit: configuration, credential-file "
                    "permissions, and local sockets. No network connections or "
                    "credential tests were performed."))
            if not args.json:
                print(f"\n[+] Markdown report written to {args.output}")
        except OSError as exc:
            print(f"[!] Could not write report: {exc}", file=sys.stderr)

    return worst_exit_code(findings)


if __name__ == "__main__":
    raise SystemExit(main())
