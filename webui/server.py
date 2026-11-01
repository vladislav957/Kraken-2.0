#!/usr/bin/env python3
"""
Kraken Audit — local web UI (the GUI shell over the auditors).

A tiny, dependency-free web app (Python standard library only) that wraps the
existing read-only auditors and shows their findings in a browser, with a
"Security Score" widget. It is the same defensive tooling, just with a GUI
instead of the terminal.

Safety:
  * Binds to 127.0.0.1 by default — the UI is for you, on your own machine.
  * It only ever calls the read-only auditors (config/permission/socket checks,
    and a single read-only miner query). It never scans, brute-forces, or
    attacks anything.

    python3 webui/server.py                 # http://127.0.0.1:8787
    python3 webui/server.py --port 9000
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

# Import the auditors from the repo root (this file lives in webui/).
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import audit_common as ac           # noqa: E402
import node_audit                   # noqa: E402
import lightning_audit              # noqa: E402
import miner_audit                  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))


# --------------------------------------------------------------------------- #
# Audit runners (reuse the existing modules; nothing new is scanned)
# --------------------------------------------------------------------------- #

def _response(findings, meta):
    findings = ac.sort_findings(findings)
    return {
        "ok": True,
        "meta": meta,
        "exit_code": ac.worst_exit_code(findings),
        "summary": ac.severity_counts(findings),
        "findings": [asdict(f) for f in findings],
    }


def run_node(params):
    conf = (params.get("conf") or [""])[0].strip()
    do_sockets = (params.get("sockets") or ["1"])[0] != "0"
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
            "Give the path to a bitcoin.conf you own.",
            "e.g. ~/.bitcoin/bitcoin.conf"))
    if do_sockets:
        findings += node_audit.check_sockets()
    return _response(findings, {"tool": "node", "conf": conf or "(none)"})


def run_lightning(params):
    impl = (params.get("impl") or ["auto"])[0]
    conf = (params.get("conf") or [""])[0].strip() or None
    node_dir = (params.get("dir") or [""])[0].strip() or None
    do_sockets = (params.get("sockets") or ["1"])[0] != "0"
    impl, conf = lightning_audit.detect_impl_and_conf(conf, impl)
    findings = []
    if conf and os.path.isfile(conf):
        values = lightning_audit.parse_kv(conf)
        findings += (lightning_audit.check_lnd(values, node_dir) if impl == "lnd"
                     else lightning_audit.check_cln(values, node_dir))
    else:
        findings.append(ac.Finding(
            ac.INFO, "conf-not-found", f"No {impl} config found",
            "Give the path to your lnd.conf or CLN config.", ""))
    if do_sockets:
        findings += lightning_audit.check_sockets()
    return _response(findings, {"tool": "lightning", "impl": impl,
                                "conf": conf or "(none)"})


def run_miner(params):
    target = (params.get("target") or [""])[0].strip()
    api_port = int((params.get("api_port") or ["4028"])[0] or 4028)
    do_web = (params.get("web") or ["1"])[0] != "0"
    if not target:
        return {"ok": False, "error": "Enter a single miner host you own."}
    try:
        host, port = ac.parse_single_target(target, default_port=api_port)
    except ac.TargetError as exc:
        return {"ok": False, "error": str(exc)}
    findings = miner_audit.check_api(host, port)
    if do_web:
        findings += miner_audit.check_web(host)
    return _response(findings, {"tool": "miner", "target": f"{host}:{port}"})


ROUTES = {"/api/node": run_node, "/api/lightning": run_lightning,
          "/api/miner": run_miner}


# --------------------------------------------------------------------------- #
# HTTP handler
# --------------------------------------------------------------------------- #

class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="application/json"):
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        if path in ("/", "/index.html"):
            try:
                with open(os.path.join(HERE, "index.html"), "rb") as fh:
                    self._send(200, fh.read(), "text/html; charset=utf-8")
            except OSError:
                self._send(500, json.dumps({"ok": False, "error": "index.html missing"}))
            return
        if path in ROUTES:
            try:
                result = ROUTES[path](parse_qs(parsed.query))
            except Exception as exc:                      # keep the UI alive
                result = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
            self._send(200, json.dumps(result, ensure_ascii=False))
            return
        self._send(404, json.dumps({"ok": False, "error": "not found"}))

    def log_message(self, *args):
        pass   # quiet


def main(argv=None):
    ap = argparse.ArgumentParser(description="Kraken Audit local web UI.")
    ap.add_argument("--host", default="127.0.0.1",
                    help="Bind address (default 127.0.0.1 — keep it local).")
    ap.add_argument("--port", type=int, default=8787)
    args = ap.parse_args(argv)

    if args.host not in ("127.0.0.1", "localhost", "::1"):
        print(f"[!] Warning: binding to {args.host} exposes the UI beyond this "
              "machine. Prefer 127.0.0.1.", file=sys.stderr)

    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    url = f"http://{args.host}:{args.port}"
    print(f"[+] Kraken Audit UI running at {url}  (Ctrl+C to stop)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n[+] stopped")
    finally:
        srv.server_close()


if __name__ == "__main__":
    main()
