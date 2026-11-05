"""Opkg package metadata parser.

Builds, for each extracted rootfs:
    path -> package  (where path is rootfs-relative, "/"-prefixed in the .list)
    package -> {version, architecture, description, depends, files_count}

Sources:
    usr/lib/opkg/info/<pkg>.list      - one rootfs-rooted file path per line
    usr/lib/opkg/info/<pkg>.control   - RFC-822 style metadata

A file listed in a package's .list is considered owned by that package.
A single path may be claimed by multiple packages; we keep the first and
record collisions in the per-key report.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

from . import config
from .common import get_logger

LOG = get_logger("orbi_fw.packages")


@dataclass
class PackageInfo:
    name: str
    version: str = ""
    architecture: str = ""
    description: str = ""
    depends: str = ""
    installed_size: str = ""
    files_count: int = 0


def _parse_control(path: Path) -> PackageInfo:
    name = path.stem
    pkg = PackageInfo(name=name)
    if not path.is_file():
        return pkg
    key_map = {
        "Package": "name",
        "Version": "version",
        "Architecture": "architecture",
        "Description": "description",
        "Depends": "depends",
        "Installed-Size": "installed_size",
    }
    current_key: str | None = None
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if raw_line.startswith((" ", "\t")) and current_key:
            setattr(pkg, current_key, getattr(pkg, current_key) + "\n" + raw_line.strip())
            continue
        if ":" in raw_line:
            k, _, v = raw_line.partition(":")
            k = k.strip()
            v = v.strip()
            attr = key_map.get(k)
            if attr:
                setattr(pkg, attr, v)
                current_key = attr
            else:
                current_key = None
    return pkg


def _parse_list(path: Path) -> list[str]:
    """.list files hold rootfs-absolute paths (one per line). Normalise."""
    if not path.is_file():
        return []
    out: list[str] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        # drop leading / to match inventory relative paths
        out.append(line.lstrip("/"))
    return out


def build_map(rootfs: Path) -> tuple[dict[str, str], dict[str, PackageInfo], dict[str, list[str]]]:
    """Return (path_to_pkg, pkg_info_map, collisions).

    collisions: path -> [pkg_names] for paths claimed by >1 package.
    """
    info_dir = rootfs / "usr" / "lib" / "opkg" / "info"
    if not info_dir.is_dir():
        raise FileNotFoundError(f"opkg info dir missing: {info_dir}")
    path_to_pkg: dict[str, str] = {}
    collisions: dict[str, list[str]] = {}
    pkg_info: dict[str, PackageInfo] = {}

    control_files = sorted(info_dir.glob("*.control"))
    for ctrl in control_files:
        pkg = _parse_control(ctrl)
        lst = info_dir / f"{pkg.name}.list"
        files = _parse_list(lst)
        pkg.files_count = len(files)
        pkg_info[pkg.name] = pkg
        for p in files:
            if p in path_to_pkg and path_to_pkg[p] != pkg.name:
                collisions.setdefault(p, [path_to_pkg[p]]).append(pkg.name)
            else:
                path_to_pkg[p] = pkg.name
    return path_to_pkg, pkg_info, collisions


def build_for_key(fw_key: str) -> tuple[Path, Path]:
    if fw_key not in config.FIRMWARE_KEYS:
        raise KeyError(f"unknown firmware key: {fw_key}")
    key = config.FIRMWARE_KEYS[fw_key]
    path_to_pkg, pkg_info, collisions = build_map(key.rootfs)
    out_dir = config.RESEARCH_OUTPUT_DIR / "packages" / fw_key
    out_dir.mkdir(parents=True, exist_ok=True)
    path_map_path = out_dir / "path_to_pkg.json"
    pkg_info_path = out_dir / "pkg_info.json"
    collisions_path = out_dir / "collisions.json"
    path_map_path.write_text(
        json.dumps(path_to_pkg, indent=2, sort_keys=True) + "\n", encoding="utf-8",
    )
    pkg_info_path.write_text(
        json.dumps({n: asdict(p) for n, p in pkg_info.items()},
                   indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    collisions_path.write_text(
        json.dumps(collisions, indent=2, sort_keys=True) + "\n", encoding="utf-8",
    )
    LOG.info("packages %s: %d files, %d packages, %d path-collisions -> %s",
             fw_key, len(path_to_pkg), len(pkg_info), len(collisions), out_dir)
    return path_map_path, pkg_info_path


def load_path_map(fw_key: str) -> dict[str, str]:
    p = config.RESEARCH_OUTPUT_DIR / "packages" / fw_key / "path_to_pkg.json"
    if not p.is_file():
        return {}
    return json.loads(p.read_text(encoding="utf-8"))
