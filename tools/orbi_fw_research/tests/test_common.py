"""Common module tests."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tools.orbi_fw_research import common


class RankTest(unittest.TestCase):

    def test_exact_match(self) -> None:
        pats = [(0, "usr/sbin/cgi-bin/soap_agent", "soap")]
        p, label = common.rank_path("usr/sbin/cgi-bin/soap_agent", pats)
        self.assertEqual((p, label), (0, "soap"))

    def test_glob(self) -> None:
        pats = [(1, "usr/lib/rpcd/*.so", "rpcd plugin")]
        p, _ = common.rank_path("usr/lib/rpcd/upgrade.so", pats)
        self.assertEqual(p, 1)
        p2, _ = common.rank_path("usr/lib/rpcd/subdir/x.so", pats)
        self.assertEqual(p2, 99)  # fnmatch with * doesn't cross /

    def test_double_star(self) -> None:
        pats = [(2, "usr/lib/lua/**/*.lua", "lua")]
        p, _ = common.rank_path("usr/lib/lua/luci/foo.lua", pats)
        self.assertEqual(p, 2)
        p2, _ = common.rank_path("usr/lib/lua/luci/http/foo.lua", pats)
        self.assertEqual(p2, 2)

    def test_fallthrough(self) -> None:
        pats = [(0, "x", "x"), (5, "*", "other")]
        p, label = common.rank_path("anything", pats)
        self.assertEqual((p, label), (5, "other"))


class Sha256Test(unittest.TestCase):

    def test_streaming(self) -> None:
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"hello")
            path = Path(f.name)
        self.assertEqual(
            common.sha256_file(path),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
        )
        path.unlink()


if __name__ == "__main__":
    unittest.main()
