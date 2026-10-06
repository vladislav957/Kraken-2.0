"""Tests for audit_common.py — shared primitives."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import audit_common as ac
from audit_common import Finding


class TestSingleTargetGuard(unittest.TestCase):
    """The guard is what keeps the suite un-weaponizable: one host only."""

    def test_plain_host_uses_default_port(self):
        self.assertEqual(ac.parse_single_target("192.168.1.50", 4028),
                         ("192.168.1.50", 4028))

    def test_host_with_port(self):
        self.assertEqual(ac.parse_single_target("192.168.1.50:4028"),
                         ("192.168.1.50", 4028))

    def test_hostname_with_port(self):
        self.assertEqual(ac.parse_single_target("miner.lan:80"),
                         ("miner.lan", 80))

    def test_cidr_rejected(self):
        with self.assertRaises(ac.TargetError):
            ac.parse_single_target("10.0.0.0/8")

    def test_list_rejected(self):
        with self.assertRaises(ac.TargetError):
            ac.parse_single_target("10.0.0.1,10.0.0.2")

    def test_space_list_rejected(self):
        with self.assertRaises(ac.TargetError):
            ac.parse_single_target("10.0.0.1 10.0.0.2")

    def test_octet_range_rejected(self):
        with self.assertRaises(ac.TargetError):
            ac.parse_single_target("10.0.0.1-50")

    def test_wildcard_rejected(self):
        with self.assertRaises(ac.TargetError):
            ac.parse_single_target("10.0.0.*")

    def test_empty_rejected(self):
        with self.assertRaises(ac.TargetError):
            ac.parse_single_target("")

    def test_bad_port_rejected(self):
        with self.assertRaises(ac.TargetError):
            ac.parse_single_target("host:notaport")


class TestAddressHelpers(unittest.TestCase):
    def test_is_loopback(self):
        self.assertTrue(ac.is_loopback("127.0.0.1"))
        self.assertTrue(ac.is_loopback("127.5.5.5"))
        self.assertTrue(ac.is_loopback("::1"))
        self.assertFalse(ac.is_loopback("0.0.0.0"))
        self.assertFalse(ac.is_loopback("10.0.0.1"))

    def test_is_wildcard(self):
        self.assertTrue(ac.is_wildcard("0.0.0.0"))
        self.assertTrue(ac.is_wildcard("::"))
        self.assertTrue(ac.is_wildcard(""))
        self.assertFalse(ac.is_wildcard("127.0.0.1"))

    def test_is_public_bind(self):
        self.assertTrue(ac.is_public_bind("0.0.0.0"))
        self.assertTrue(ac.is_public_bind("10.0.0.5"))
        self.assertFalse(ac.is_public_bind("127.0.0.1"))
        self.assertFalse(ac.is_public_bind("::1"))

    def test_host_from_bind(self):
        self.assertEqual(ac.host_from_bind("0.0.0.0:8332"), "0.0.0.0")
        self.assertEqual(ac.host_from_bind("[::]:8333"), "[::]")
        self.assertEqual(ac.host_from_bind("127.0.0.1"), "127.0.0.1")

    def test_parse_listen_addr(self):
        self.assertEqual(ac.parse_listen_addr("0.0.0.0:8332"), ("0.0.0.0", 8332))
        self.assertEqual(ac.parse_listen_addr("[::]:8333"), ("[::]", 8333))
        host, port = ac.parse_listen_addr("garbage")
        self.assertIsNone(port)


class TestEntropy(unittest.TestCase):
    def test_empty_is_zero(self):
        self.assertEqual(ac.password_entropy_bits(""), 0.0)

    def test_longer_complex_beats_short_simple(self):
        weak = ac.password_entropy_bits("123456")
        strong = ac.password_entropy_bits("Gk8$wQ2p!zR7vLm0xYt3")
        self.assertLess(weak, strong)

    def test_weak_below_threshold(self):
        self.assertLess(ac.password_entropy_bits("123456"), 60)


class TestReporting(unittest.TestCase):
    def test_worst_exit_code(self):
        self.assertEqual(ac.worst_exit_code([Finding(ac.CRITICAL, "c", "t", "d")]), 1)
        self.assertEqual(ac.worst_exit_code([Finding(ac.HIGH, "h", "t", "d")]), 1)
        self.assertEqual(ac.worst_exit_code([Finding(ac.INFO, "i", "t", "d"),
                                             Finding(ac.OK, "o", "t", "d")]), 0)
        self.assertEqual(ac.worst_exit_code([]), 0)

    def test_severity_counts(self):
        counts = ac.severity_counts([Finding(ac.HIGH, "a", "t", "d"),
                                     Finding(ac.HIGH, "b", "t", "d"),
                                     Finding(ac.OK, "c", "t", "d")])
        self.assertEqual(counts[ac.HIGH], 2)
        self.assertEqual(counts[ac.OK], 1)

    def test_render_terminal_has_summary(self):
        out = ac.render_terminal([Finding(ac.CRITICAL, "x", "Boom", "detail", "fix")])
        self.assertIn("Boom", out)
        self.assertIn("Summary:", out)

    def test_render_markdown_structure(self):
        md = ac.render_markdown([Finding(ac.CRITICAL, "x", "Boom", "detail", "fix")],
                                "My Report", [("Host", "`vm`")], "footer note")
        self.assertIn("# My Report", md)
        self.assertIn("Boom", md)
        self.assertIn("footer note", md)
        self.assertIn("Host", md)


if __name__ == "__main__":
    unittest.main()
