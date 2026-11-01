"""Tests for kraken_cli.py — the unified entry point / subcommand dispatcher."""
import io
import os
import sys
import unittest
from contextlib import redirect_stdout, redirect_stderr

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import kraken_cli


class TestCli(unittest.TestCase):
    def test_version(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = kraken_cli.main(["--version"])
        self.assertEqual(rc, 0)
        self.assertIn("kraken", buf.getvalue().lower())

    def test_help_lists_commands(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = kraken_cli.main(["--help"])
        out = buf.getvalue()
        self.assertEqual(rc, 0)
        for cmd in ("node", "lightning", "miner", "exposure", "report", "gui"):
            self.assertIn(cmd, out)

    def test_unknown_command_is_error(self):
        buf = io.StringIO()
        with redirect_stderr(buf):
            rc = kraken_cli.main(["definitely-not-a-command"])
        self.assertEqual(rc, 2)

    def test_every_command_dispatches(self):
        # Each entry must be callable and map to a real module main().
        for name in ("node", "lightning", "ln", "miner", "exposure", "report"):
            self.assertIn(name, kraken_cli._COMMANDS)
            func, desc = kraken_cli._COMMANDS[name]
            self.assertTrue(callable(func))
            self.assertIsInstance(desc, str)

    def test_exposure_runs_through_dispatcher(self):
        # A real, read-only subcommand run should return an int exit code.
        buf = io.StringIO()
        with redirect_stdout(buf), redirect_stderr(io.StringIO()):
            rc = kraken_cli.main(["exposure"])
        self.assertIsInstance(rc, int)


if __name__ == "__main__":
    unittest.main()
