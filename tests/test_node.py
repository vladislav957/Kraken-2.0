"""Tests for node_audit.py — Bitcoin Core auditor."""
import contextlib
import io
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import audit_common as ac
import node_audit


def by_check(findings):
    return {f.check: f for f in findings}


INSECURE = """\
server=1
rpcuser=admin
rpcpassword=123456
rpcbind=0.0.0.0
rpcallowip=0.0.0.0/0
[regtest]
rpcport=18443
"""

HARDENED = """\
server=1
rpcbind=127.0.0.1
rpcallowip=127.0.0.1
"""


def write_tmp(text, suffix=".conf"):
    fd, path = tempfile.mkstemp(suffix=suffix)
    with os.fdopen(fd, "w") as fh:
        fh.write(text)
    return path


class TestParseConf(unittest.TestCase):
    def test_sections_comments_and_repeats(self):
        text = ("# comment\nserver=1\nrpcallowip=127.0.0.1\n"
                "rpcallowip=10.0.0.0/24  # inline\n[test]\nrpcallowip=192.168.0.0/16\n")
        path = write_tmp(text)
        try:
            values = node_audit.parse_conf(path)
        finally:
            os.unlink(path)
        self.assertEqual(values["server"], ["1"])
        self.assertIn("127.0.0.1", values["rpcallowip"])
        self.assertIn("10.0.0.0/24", values["rpcallowip"])          # inline comment stripped
        self.assertIn("192.168.0.0/16", values["test.rpcallowip"])  # section-qualified


class TestCheckConfig(unittest.TestCase):
    def test_insecure(self):
        path = write_tmp(INSECURE)
        try:
            findings = node_audit.check_config(node_audit.parse_conf(path))
        finally:
            os.unlink(path)
        checks = by_check(findings)
        self.assertEqual(checks["rpc-allowip-world"].severity, ac.CRITICAL)
        self.assertEqual(checks["rpc-bind-wildcard"].severity, ac.CRITICAL)
        self.assertEqual(checks["rpc-plaintext-password"].severity, ac.HIGH)
        self.assertEqual(checks["rpc-weak-password"].severity, ac.HIGH)
        self.assertEqual(ac.worst_exit_code(findings), 1)

    def test_hardened_uses_cookie_and_no_criticals(self):
        path = write_tmp(HARDENED)
        try:
            findings = node_audit.check_config(node_audit.parse_conf(path))
        finally:
            os.unlink(path)
        checks = by_check(findings)
        self.assertIn("rpc-cookie-auth", checks)
        self.assertFalse(any(f.severity == ac.CRITICAL for f in findings))


class TestCheckPermissions(unittest.TestCase):
    def test_world_readable_with_secret_is_high(self):
        path = write_tmp("rpcpassword=hunter2hunter2hunter2\n")
        os.chmod(path, 0o644)
        try:
            values = node_audit.parse_conf(path)
            findings = node_audit.check_permissions(path, values)
        finally:
            os.unlink(path)
        checks = by_check(findings)
        self.assertIn("conf-perms-secret", checks)
        self.assertEqual(checks["conf-perms-secret"].severity, ac.HIGH)

    def test_owner_only_with_secret_is_clean(self):
        path = write_tmp("rpcpassword=hunter2hunter2hunter2\n")
        os.chmod(path, 0o600)
        try:
            values = node_audit.parse_conf(path)
            findings = node_audit.check_permissions(path, values)
        finally:
            os.unlink(path)
        self.assertEqual(findings, [])


class TestCheckSockets(unittest.TestCase):
    def test_rpc_public_is_critical(self):
        with mock.patch.object(node_audit, "local_listeners",
                               return_value=([("0.0.0.0", 8332)], None)):
            findings = node_audit.check_sockets()
        self.assertEqual(by_check(findings)["socket-rpc-public"].severity, ac.CRITICAL)

    def test_rpc_loopback_is_clean(self):
        with mock.patch.object(node_audit, "local_listeners",
                               return_value=([("127.0.0.1", 8332)], None)):
            findings = node_audit.check_sockets()
        self.assertIn("sockets-clean", by_check(findings))

    def test_p2p_public_is_info(self):
        with mock.patch.object(node_audit, "local_listeners",
                               return_value=([("0.0.0.0", 8333)], None)):
            findings = node_audit.check_sockets()
        self.assertEqual(by_check(findings)["socket-p2p-public"].severity, ac.INFO)


class TestMainExitCode(unittest.TestCase):
    def test_insecure_file_exits_nonzero(self):
        path = write_tmp(INSECURE)
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                rc = node_audit.main(["--conf", path, "--no-sockets"])
        finally:
            os.unlink(path)
        self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main()
