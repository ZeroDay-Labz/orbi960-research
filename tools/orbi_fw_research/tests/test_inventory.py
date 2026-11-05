"""Inventory module tests. Build a tiny rootfs in a tmp dir and inventory it."""
from __future__ import annotations

import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from tools.orbi_fw_research import inventory
from tools.orbi_fw_research.common import sha256_file


class InventoryTest(unittest.TestCase):

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        # Shape: /etc/foo (file), /etc/bar -> foo (symlink),
        #        /usr/bin/hello (exec), /empty/ (dir)
        (self.root / "etc").mkdir()
        (self.root / "etc" / "foo").write_text("hello world\n")
        os.symlink("foo", self.root / "etc" / "bar")
        (self.root / "usr" / "bin").mkdir(parents=True)
        (self.root / "usr" / "bin" / "hello").write_text("#!/bin/sh\necho hi\n")
        os.chmod(self.root / "usr" / "bin" / "hello", 0o755)
        (self.root / "empty").mkdir()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_walk_and_kinds(self) -> None:
        entries = inventory.inventory_rootfs(self.root, with_file_type=False)
        by_path = {e.path: e for e in entries}

        self.assertIn("etc/foo", by_path)
        self.assertEqual(by_path["etc/foo"].kind, "file")
        self.assertTrue(by_path["etc/foo"].sha256)

        self.assertIn("etc/bar", by_path)
        self.assertEqual(by_path["etc/bar"].kind, "symlink")
        self.assertEqual(by_path["etc/bar"].symlink_target, "foo")
        self.assertEqual(by_path["etc/bar"].sha256, "")

        self.assertIn("usr/bin/hello", by_path)
        self.assertEqual(by_path["usr/bin/hello"].mode, "0755")

        self.assertIn("empty", by_path)
        self.assertEqual(by_path["empty"].kind, "dir")

    def test_sorted_output(self) -> None:
        entries = inventory.inventory_rootfs(self.root, with_file_type=False)
        paths = [e.path for e in entries]
        self.assertEqual(paths, sorted(paths))

    def test_jsonl_roundtrip(self) -> None:
        entries = inventory.inventory_rootfs(self.root, with_file_type=False)
        tmp_out = Path(self.tmp.name) / "inv.jsonl"
        inventory.write_jsonl(entries, tmp_out)
        reloaded = inventory.read_jsonl(tmp_out)
        self.assertEqual(len(reloaded), len(entries))
        a = {e.path: e for e in entries}
        b = {e.path: e for e in reloaded}
        for p, e in a.items():
            self.assertEqual(e.sha256, b[p].sha256)
            self.assertEqual(e.kind, b[p].kind)
            self.assertEqual(e.mode, b[p].mode)

    def test_sha256_matches_streaming(self) -> None:
        entries = inventory.inventory_rootfs(self.root, with_file_type=False)
        for e in entries:
            if e.kind == "file":
                p = self.root / e.path
                self.assertEqual(e.sha256, sha256_file(p))

    def test_summary(self) -> None:
        entries = inventory.inventory_rootfs(self.root, with_file_type=False)
        s = inventory.summarise(entries)
        self.assertGreaterEqual(s["entries"], 5)
        self.assertEqual(s["by_kind"].get("file", 0), 2)
        self.assertEqual(s["by_kind"].get("symlink", 0), 1)


if __name__ == "__main__":
    unittest.main()
