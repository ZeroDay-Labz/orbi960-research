"""Package map module tests: synthetic opkg info dir."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tools.orbi_fw_research import package_map


class PackageMapTest(unittest.TestCase):

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.info = self.root / "usr" / "lib" / "opkg" / "info"
        self.info.mkdir(parents=True)
        (self.info / "pkg_a.control").write_text(
            "Package: pkg_a\n"
            "Version: 1.0-r1\n"
            "Architecture: arm_cortex-a7_neon-vfpv4\n"
            "Description: alpha package\n"
            "Installed-Size: 123\n"
        )
        (self.info / "pkg_a.list").write_text("/usr/bin/a1\n/usr/lib/a.so\n")
        (self.info / "pkg_b.control").write_text(
            "Package: pkg_b\nVersion: 2.0\nDescription: b pkg\n"
        )
        (self.info / "pkg_b.list").write_text("/usr/bin/b1\n")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_build_map(self) -> None:
        pm, info, collisions = package_map.build_map(self.root)
        self.assertEqual(pm["usr/bin/a1"], "pkg_a")
        self.assertEqual(pm["usr/bin/b1"], "pkg_b")
        self.assertEqual(info["pkg_a"].version, "1.0-r1")
        self.assertEqual(info["pkg_a"].files_count, 2)
        self.assertEqual(collisions, {})

    def test_collisions_recorded(self) -> None:
        (self.info / "pkg_c.control").write_text("Package: pkg_c\nVersion: 3\n")
        (self.info / "pkg_c.list").write_text("/usr/bin/a1\n")
        _pm, _info, collisions = package_map.build_map(self.root)
        # pkg_a already claimed /usr/bin/a1; pkg_c collides.
        self.assertIn("usr/bin/a1", collisions)


if __name__ == "__main__":
    unittest.main()
