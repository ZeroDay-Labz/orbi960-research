"""Compare module tests: synthetic inventories, verify diff classifications."""
from __future__ import annotations

import unittest
from pathlib import Path

from tools.orbi_fw_research import compare
from tools.orbi_fw_research.inventory import Entry


def _f(path: str, sha: str, size: int = 100, kind: str = "file") -> Entry:
    return Entry(path=path, kind=kind, size=size, mode="0644", sha256=sha)


class DiffTest(unittest.TestCase):

    def test_added_removed_changed(self) -> None:
        a = [
            _f("etc/a", "aaa", 10),
            _f("etc/b", "bbb", 20),
            _f("etc/c", "ccc", 30),
        ]
        b = [
            _f("etc/a", "aaa", 10),            # same
            _f("etc/b", "BBB", 21),            # changed
            _f("etc/d", "ddd", 40),            # added
        ]
        changes = compare.diff_inventories(a, b)
        status = {c.path: c.status for c in changes}
        self.assertEqual(status["etc/b"], "changed")
        self.assertEqual(status["etc/c"], "removed")
        self.assertEqual(status["etc/d"], "added")
        self.assertNotIn("etc/a", status)      # same -> not emitted

    def test_symlink_change_detected(self) -> None:
        a = [Entry(path="x", kind="symlink", size=0, mode="0777",
                   symlink_target="old")]
        b = [Entry(path="x", kind="symlink", size=0, mode="0777",
                   symlink_target="new")]
        changes = compare.diff_inventories(a, b)
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0].status, "changed")
        self.assertIn("symlink:", changes[0].note)

    def test_kind_change_detected(self) -> None:
        a = [Entry(path="x", kind="file", size=1, mode="0644", sha256="aaa")]
        b = [Entry(path="x", kind="symlink", size=0, mode="0777",
                   symlink_target="y")]
        changes = compare.diff_inventories(a, b)
        self.assertEqual(changes[0].status, "changed")
        self.assertIn("kind:file->symlink", changes[0].note)

    def test_priority_ranking(self) -> None:
        a = [
            _f("usr/sbin/cgi-bin/soap_agent", "aaa"),
            _f("etc/motd", "bbb"),
        ]
        b = [
            _f("usr/sbin/cgi-bin/soap_agent", "zzz"),
            _f("etc/motd", "ccc"),
        ]
        changes = compare.diff_inventories(a, b)
        # Priority 0 (soap_agent) should come before prio >=1 (etc/motd).
        self.assertEqual(changes[0].path, "usr/sbin/cgi-bin/soap_agent")
        self.assertEqual(changes[0].prio, 0)

    def test_summary(self) -> None:
        a = [_f("a", "x"), _f("b", "y")]
        b = [_f("a", "x"), _f("c", "z")]
        changes = compare.diff_inventories(a, b)
        summary = compare.summarise(changes)
        self.assertEqual(summary["by_status"].get("added", 0), 1)
        self.assertEqual(summary["by_status"].get("removed", 0), 1)


if __name__ == "__main__":
    unittest.main()
