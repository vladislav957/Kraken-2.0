"""Tests for kraken_core.py — the audit engine."""
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import kraken_core as core


def conf(name):
    return os.path.join(ROOT, "lab", "conf", name)


class TestCore(unittest.TestCase):
    def test_node_insecure(self):
        r = core.audit_node(conf("insecure.bitcoin.conf"), check_sockets=False)
        self.assertEqual(r.tool, "node")
        self.assertEqual(r.worst, "CRITICAL")
        self.assertEqual(r.exit_code, 1)

    def test_node_hardened(self):
        r = core.audit_node(conf("hardened.bitcoin.conf"), check_sockets=False)
        self.assertNotEqual(r.worst, "CRITICAL")
        self.assertEqual(r.exit_code, 0)

    def test_lightning_insecure(self):
        r = core.audit_lightning("lnd", conf("lnd.insecure.conf"), check_sockets=False)
        self.assertEqual(r.worst, "CRITICAL")

    def test_overall_aggregates(self):
        r = core.audit_node(conf("insecure.bitcoin.conf"), check_sockets=False)
        s = core.overall([r])
        self.assertEqual(s.worst, "CRITICAL")
        self.assertEqual(s.grade, "F")
        self.assertLess(s.score, 50)

    def test_overall_empty(self):
        s = core.overall([])
        self.assertEqual(s.label, "No audit run yet")

    def test_miner_guard_rejects_cidr(self):
        with self.assertRaises(core.ac.TargetError):
            core.audit_miner("10.0.0.0/8")


if __name__ == "__main__":
    unittest.main()
