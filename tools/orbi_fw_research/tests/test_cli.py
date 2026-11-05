"""CLI argparse smoke tests. Does not execute module subcommands."""
from __future__ import annotations

import unittest

from tools.orbi_fw_research import cli


class CliTest(unittest.TestCase):

    def test_help_parses(self) -> None:
        p = cli.build_parser()
        # Help exits with 0; use parse_args to walk the tree.
        with self.assertRaises(SystemExit):
            p.parse_args(["--help"])

    def test_known_subcommands(self) -> None:
        p = cli.build_parser()
        ns = p.parse_args(["inventory", "rbse_7215"])
        self.assertEqual(ns.cmd, "inventory")
        ns = p.parse_args(["compare", "rbse_7215", "rbse_7288"])
        self.assertEqual(ns.cmd, "compare")
        ns = p.parse_args(["compare-all"])
        self.assertEqual(ns.cmd, "compare-all")
        ns = p.parse_args(["ghidra", "check"])
        self.assertEqual(ns.cmd, "ghidra")
        self.assertEqual(ns.subaction, "check")
        ns = p.parse_args(["sinks", "rbse_7215"])
        self.assertEqual(ns.cmd, "sinks")

    def test_compare_requires_two_args(self) -> None:
        p = cli.build_parser()
        with self.assertRaises(SystemExit):
            p.parse_args(["compare"])


if __name__ == "__main__":
    unittest.main()
