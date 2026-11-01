"""Tests for exposure_audit.py — local network-exposure checks."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import exposure_audit as ex


def exposed(findings):
    return [f for f in findings if f.check == "exposed-port"]


class TestExposure(unittest.TestCase):
    def test_public_rpc_is_high(self):
        e = exposed(ex.check_exposure([("0.0.0.0", 8332)]))
        self.assertEqual(len(e), 1)
        self.assertEqual(e[0].severity, "HIGH")

    def test_public_redis_is_critical(self):
        e = exposed(ex.check_exposure([("0.0.0.0", 6379)]))
        self.assertEqual(e[0].severity, "CRITICAL")

    def test_public_p2p_is_info(self):
        e = exposed(ex.check_exposure([("0.0.0.0", 8333)]))
        self.assertEqual(e[0].severity, "INFO")

    def test_unknown_public_is_medium(self):
        e = exposed(ex.check_exposure([("0.0.0.0", 54321)]))
        self.assertEqual(e[0].severity, "MEDIUM")

    def test_loopback_is_clean(self):
        findings = ex.check_exposure([("127.0.0.1", 8332), ("::1", 10009)])
        self.assertEqual(exposed(findings), [])
        checks = {f.check for f in findings}
        self.assertIn("no-exposure", checks)
        self.assertIn("local-only", checks)

    def test_mixed(self):
        findings = ex.check_exposure([("0.0.0.0", 22), ("127.0.0.1", 8332),
                                      ("0.0.0.0", 8333)])
        e = exposed(findings)
        sevs = sorted(f.severity for f in e)
        self.assertEqual(sevs, ["HIGH", "INFO"])  # SSH public + P2P public


if __name__ == "__main__":
    unittest.main()
