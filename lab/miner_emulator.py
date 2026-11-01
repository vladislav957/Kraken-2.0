#!/usr/bin/env python3
"""
miner_emulator.py — a tiny, fake CGMiner-API server for the lab.

It speaks just enough of the CGMiner/bmminer JSON API (read-only `version` and
`summary`) to give miner_audit.py a safe, local target to point at. All data is
made up — there is no real miner, no real hashrate, nothing to attack. It
accepts read-only queries only and ignores everything else.

    python3 miner_emulator.py                 # listens on 127.0.0.1:4028
    python3 miner_emulator.py --host 0.0.0.0 --port 4028
"""

from __future__ import annotations

import argparse
import json
import socketserver

VERSION = {
    "STATUS": [{"STATUS": "S", "Code": 22, "Msg": "CGMiner versions",
                "Description": "cgminer 4.11.1 (lab emulator)"}],
    "VERSION": [{"CGMiner": "4.11.1", "API": "3.7",
                 "Type": "Antminer S19 (emulated)", "Prod": "lab-unit"}],
    "id": 1,
}

SUMMARY = {
    "STATUS": [{"STATUS": "S", "Code": 11, "Msg": "Summary",
                "Description": "cgminer 4.11.1 (lab emulator)"}],
    "SUMMARY": [{"Elapsed": 12345, "GHS 5s": "95000.00", "GHS av": "94500.00",
                 "Accepted": 1000, "Rejected": 3, "Model": "S19-emulated"}],
    "id": 1,
}


def response_for(command: str) -> dict:
    cmd = command.strip().lower()
    if cmd == "version":
        return VERSION
    if cmd == "summary":
        return SUMMARY
    return {
        "STATUS": [{"STATUS": "E", "Code": 14, "Msg": f"Invalid command '{command}'",
                    "Description": "cgminer 4.11.1 (lab emulator)"}],
        "id": 1,
    }


class Handler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        raw = self.request.recv(4096).decode("utf-8", "replace").strip()
        command = raw
        if raw.startswith("{"):
            try:
                command = json.loads(raw).get("command", "")
            except json.JSONDecodeError:
                command = ""
        body = json.dumps(response_for(command)).encode() + b"\x00"
        try:
            self.request.sendall(body)
        except OSError:
            pass


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main() -> int:
    p = argparse.ArgumentParser(description="Fake CGMiner API for the lab.")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=4028)
    args = p.parse_args()
    with Server((args.host, args.port), Handler) as srv:
        print(f"[lab] fake CGMiner API listening on {args.host}:{args.port} "
              f"(read-only version/summary; fake data)")
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            print("\n[lab] stopping")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
