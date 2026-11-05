"""Shared helpers: subprocess wrapper, hashing, logging."""
from __future__ import annotations

import fnmatch
import hashlib
import logging
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Iterable, Sequence

_LOG_READY = False


def get_logger(name: str = "orbi_fw") -> logging.Logger:
    """Return a project-wide logger, configured once with a terse format."""
    global _LOG_READY
    log = logging.getLogger(name)
    if not _LOG_READY:
        h = logging.StreamHandler()
        h.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
        log.addHandler(h)
        log.setLevel(logging.INFO)
        log.propagate = False
        _LOG_READY = True
    return log


def sha256_file(path: Path, chunk: int = 1 << 20) -> str:
    """Streaming SHA-256 of a regular file. Empty string for non-regular files."""
    if not path.is_file() or path.is_symlink():
        return ""
    h = hashlib.sha256()
    try:
        with path.open("rb") as f:
            while True:
                buf = f.read(chunk)
                if not buf:
                    break
                h.update(buf)
    except (OSError, PermissionError):
        return ""
    return h.hexdigest()


@dataclass
class RunResult:
    """Captured stdout/stderr/returncode. .ok is True iff rc == 0."""
    args: Sequence[str]
    rc: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.rc == 0


def run(args: Sequence[str], *, cwd: Path | None = None, timeout: int = 60,
        input_data: bytes | None = None, check: bool = False) -> RunResult:
    """Subprocess wrapper. Never raises unless check=True and rc!=0."""
    proc = subprocess.run(
        list(args), cwd=str(cwd) if cwd else None, capture_output=True,
        timeout=timeout, input=input_data,
    )
    r = RunResult(
        args=list(args), rc=proc.returncode,
        stdout=proc.stdout.decode("utf-8", "replace"),
        stderr=proc.stderr.decode("utf-8", "replace"),
    )
    if check and not r.ok:
        raise RuntimeError(f"{args[0]} failed rc={proc.returncode}: {r.stderr[:200]}")
    return r


def have(tool: str) -> bool:
    """True iff `tool` is on PATH."""
    return shutil.which(tool) is not None


def rank_path(rel_path: str, patterns: Iterable[tuple[int, str, str]]) -> tuple[int, str]:
    """Return (priority, label) for `rel_path` using the first matching pattern.

    Patterns are (priority, glob_pattern, label). Smaller priority = higher.
    Matching is path-aware (a `*` does NOT cross `/`); use `**` for recursion.
    """
    pp = PurePosixPath(rel_path)
    for prio, pat, label in patterns:
        if _match_glob(pp, rel_path, pat):
            return prio, label
    return 99, "unmatched"


def _match_glob(pp: PurePosixPath, rel_path: str, pat: str) -> bool:
    """Path-aware glob. Uses PurePosixPath.match for single-level globs and
    custom handling for `**`. Exact-string patterns match literally too."""
    if "**" in pat:
        head, _, tail = pat.partition("**")
        head = head.rstrip("/")
        tail = tail.lstrip("/")
        if head and not (rel_path == head or rel_path.startswith(head + "/")):
            return False
        rest = rel_path[len(head):].lstrip("/") if head else rel_path
        if not tail:
            return True
        parts = rest.split("/")
        for i in range(len(parts) + 1):
            candidate = "/".join(parts[i:])
            if candidate and PurePosixPath(candidate).match(tail):
                return True
        return False
    # PurePosixPath.match treats * as not crossing /, which matches our intent.
    try:
        return pp.match(pat)
    except ValueError:
        return False
