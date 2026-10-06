"""Tests for lightning_audit.py — lnd / CLN auditor."""
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import audit_common as ac
import lightning_audit as la


def by_check(findings):
    return {f.check: f for f in findings}


LND_INSECURE = {
    "rpclisten": ["0.0.0.0:10009"],
    "restlisten": ["0.0.0.0:8080"],
    "no-macaroons": ["true"],
    "listen": ["0.0.0.0:9735"],
}
LND_HARDENED = {
    "rpclisten": ["127.0.0.1:10009"],
    "restlisten": ["127.0.0.1:8080"],
    "listen": ["0.0.0.0:9735"],
}
CLN_INSECURE = {
    "bind-addr": ["0.0.0.0:9735"],
    "grpc-port": ["9736"],
    "clnrest-port": ["3010"],
}


class TestParseKV(unittest.TestCase):
    def test_ignores_sections_and_lowercases(self):
        fd, path = tempfile.mkstemp()
        with os.fdopen(fd, "w") as fh:
            fh.write("[Application Options]\n# c\nRPCListen=127.0.0.1:10009\n"
                     "no-macaroons=true  # inline\n")
        try:
            values = la.parse_kv(path)
        finally:
            os.unlink(path)
        self.assertEqual(values["rpclisten"], ["127.0.0.1:10009"])
        self.assertEqual(values["no-macaroons"], ["true"])  # inline comment gone


class TestLnd(unittest.TestCase):
    def test_insecure(self):
        findings = la.check_lnd(LND_INSECURE, None)
        checks = by_check(findings)
        self.assertEqual(checks["lnd-grpc-exposed"].severity, ac.CRITICAL)
        self.assertEqual(checks["lnd-macaroons-disabled"].severity, ac.CRITICAL)
        self.assertEqual(checks["lnd-rest-exposed"].severity, ac.HIGH)

    def test_hardened_clean(self):
        findings = la.check_lnd(LND_HARDENED, None)
        self.assertFalse(any(f.severity == ac.CRITICAL for f in findings))
        self.assertIn("lnd-clean", by_check(findings))

    def test_world_readable_macaroon_flagged(self):
        base = tempfile.mkdtemp()
        macdir = os.path.join(base, "data", "chain", "bitcoin", "regtest")
        os.makedirs(macdir)
        mac = os.path.join(macdir, "admin.macaroon")
        with open(mac, "w") as fh:
            fh.write("x")
        os.chmod(mac, 0o644)
        findings = la.check_lnd(LND_HARDENED, base)
        checks = by_check(findings)
        self.assertIn("ln-file-perms", checks)
        self.assertEqual(checks["ln-file-perms"].severity, ac.HIGH)


class TestCln(unittest.TestCase):
    def test_insecure(self):
        findings = la.check_cln(CLN_INSECURE, None)
        checks = by_check(findings)
        self.assertEqual(checks["cln-grpc-exposed"].severity, ac.HIGH)
        self.assertEqual(checks["cln-rest-exposed"].severity, ac.HIGH)

    def test_world_accessible_socket_is_critical(self):
        base = tempfile.mkdtemp()
        netdir = os.path.join(base, "regtest")
        os.makedirs(netdir)
        sock = os.path.join(netdir, "lightning-rpc")
        with open(sock, "w") as fh:
            fh.write("x")
        os.chmod(sock, 0o666)
        findings = la.check_cln({}, base)
        checks = by_check(findings)
        self.assertIn("ln-file-perms", checks)
        self.assertEqual(checks["ln-file-perms"].severity, ac.CRITICAL)


class TestSockets(unittest.TestCase):
    def test_grpc_public_critical(self):
        with mock.patch.object(la, "local_listeners",
                               return_value=([("0.0.0.0", 10009)], None)):
            findings = la.check_sockets()
        self.assertEqual(by_check(findings)["socket-ln-grpc"].severity, ac.CRITICAL)

    def test_grpc_loopback_clean(self):
        with mock.patch.object(la, "local_listeners",
                               return_value=([("127.0.0.1", 10009)], None)):
            findings = la.check_sockets()
        self.assertIn("sockets-clean", by_check(findings))

    def test_p2p_public_info(self):
        with mock.patch.object(la, "local_listeners",
                               return_value=([("0.0.0.0", 9735)], None)):
            findings = la.check_sockets()
        self.assertEqual(by_check(findings)["socket-ln-p2p"].severity, ac.INFO)


if __name__ == "__main__":
    unittest.main()
