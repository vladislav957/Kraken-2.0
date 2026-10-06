"""Tests for miner_audit.py — single-target, read-only miner check.

Uses a tiny in-process fake CGMiner API so nothing external is contacted.
"""
import contextlib
import io
import json
import os
import socket
import socketserver
import sys
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import audit_common as ac
import miner_audit


FAKE_VERSION = {
    "STATUS": [{"STATUS": "S", "Description": "cgminer 4.11.1 (test)"}],
    "VERSION": [{"CGMiner": "4.11.1", "API": "3.7", "Type": "TestMiner"}],
    "id": 1,
}


class _Handler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.recv(4096)
        self.request.sendall(json.dumps(FAKE_VERSION).encode() + b"\x00")


class _Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def by_check(findings):
    return {f.check: f for f in findings}


class TestMinerApi(unittest.TestCase):
    def setUp(self):
        self.srv = _Server(("127.0.0.1", 0), _Handler)
        self.port = self.srv.server_address[1]
        self.thread = threading.Thread(target=self.srv.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()

    def test_cgminer_version_parses(self):
        raw, parsed = miner_audit.cgminer_version("127.0.0.1", self.port)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["VERSION"][0]["CGMiner"], "4.11.1")

    def test_check_api_reachable_and_identity(self):
        findings = miner_audit.check_api("127.0.0.1", self.port)
        checks = by_check(findings)
        self.assertIn("miner-api-reachable", checks)
        self.assertIn("miner-identity", checks)
        # loopback target -> INFO, not MEDIUM
        self.assertEqual(checks["miner-api-reachable"].severity, ac.INFO)

    def test_tcp_open_true(self):
        self.assertTrue(miner_audit.tcp_open("127.0.0.1", self.port))


class TestMinerUnreachable(unittest.TestCase):
    def test_api_unreachable_is_ok(self):
        port = free_port()  # nothing listening here
        findings = miner_audit.check_api("127.0.0.1", port)
        self.assertIn("miner-api-unreachable", by_check(findings))

    def test_tcp_open_false(self):
        self.assertFalse(miner_audit.tcp_open("127.0.0.1", free_port(), timeout=1.0))


class TestExtractIdentity(unittest.TestCase):
    def test_pulls_fields(self):
        ident = miner_audit._extract_identity(FAKE_VERSION)
        self.assertEqual(ident["CGMiner"], "4.11.1")
        self.assertEqual(ident["Type"], "TestMiner")

    def test_empty_on_garbage(self):
        self.assertEqual(miner_audit._extract_identity(None), {})


class TestMainGuard(unittest.TestCase):
    def test_cidr_target_is_rejected(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                miner_audit.main(["--target", "10.0.0.0/8"])

    def test_range_target_is_rejected(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                miner_audit.main(["--target", "10.0.0.1-50"])


if __name__ == "__main__":
    unittest.main()
