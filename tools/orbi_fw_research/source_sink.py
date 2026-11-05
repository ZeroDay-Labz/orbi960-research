"""Source-to-sink scaffolding (binary + script).

Not a sound taint tracker - that needs Ghidra/angr. What this does:
    1. For each target binary, locate every call-site of a known-dangerous
       sink (system, popen, execl/execve, sprintf, strcpy, strcat, memcpy,
       mkstemp, fopen, unlink, rename, ...) via `objdump -d` plus a regex,
       and record the caller function name and nearby strings.
    2. For scripts, grep for shell command injection vectors.

Every finding is HYPOTHETICAL until confirmed with Ghidra/REA. We emit a
`confidence` field: "hint" (needs manual review) only, never "confirmed".
"""
from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable

from . import config
from .common import get_logger, have, run
from .elf_analysis import elf_strings, is_elf

LOG = get_logger("orbi_fw.sinks")


BINARY_SINKS: tuple[str, ...] = (
    "system", "popen", "execl", "execle", "execlp", "execv", "execve", "execvp",
    "sprintf", "snprintf", "vsprintf", "vsnprintf",
    "strcpy", "strncpy", "strcat", "strncat",
    "memcpy", "memmove",
    "mkstemp", "mktemp", "tmpnam",
    "fopen", "open", "openat", "creat",
    "unlink", "unlinkat", "rename", "renameat",
    "gets",  # ancient but worth flagging if present
)

SCRIPT_SINKS: tuple[str, ...] = (
    "eval", "exec", "`", "$(",
    # NOTE: raw `system`/`popen` are grep-friendly; keep for shell detection too
)


@dataclass
class SinkHit:
    path: str
    sink: str
    caller: str = ""            # resolved function name or "unknown"
    offset: str = ""            # hex offset or line number
    context: str = ""           # one-line snippet
    nearby_strings: list[str] = field(default_factory=list)
    confidence: str = "hint"
    note: str = ""


# Matches: 1234:  ebfffffe bl       <funcname@plt>  or  bl <funcname>
_OBJDUMP_BL = re.compile(
    r"^\s*(?P<off>[0-9a-fA-F]+):\s+[0-9a-fA-F ]+\s+bl\s+[0-9a-fA-F]+\s*<(?P<target>[^>]+)>",
)
# Matches function label lines in objdump -d output: "00011238 <FUN_name>:"
_OBJDUMP_FN = re.compile(r"^(?P<addr>[0-9a-fA-F]+)\s+<(?P<name>[^>]+)>:\s*$")


def _objdump(path: Path) -> str:
    """Return `objdump -d` output for a stripped ARM binary."""
    if not have("objdump"):
        return ""
    r = run(["objdump", "-d", "-M", "no-aliases", str(path)], timeout=120)
    return r.stdout if r.ok else ""


def _nearby_strings(strings: list[tuple[int, str]], off: int, window: int = 2048,
                    max_items: int = 6) -> list[str]:
    """Return up to max_items strings with file offset within +/- window of off.

    `off` is the disassembled text-section offset of a call site.
    It is a *rough* proximity hint - near-literals used by the caller tend to
    sit in .rodata at similar file offsets. Not sound; marked as hint only.
    """
    out: list[str] = []
    for so, s in strings:
        if abs(so - off) <= window:
            out.append(s)
            if len(out) >= max_items:
                break
    return out


def scan_binary(path: Path) -> list[SinkHit]:
    """Locate call sites for known sinks in a stripped ARM ELF.

    Walks `objdump -d` output; whenever a `bl <sink>` or `bl <sink@plt>` lands,
    we record the owning function label (last seen "<name>:" header), the
    offset, and nearby .rodata strings. Null function label becomes "unknown".
    """
    if not is_elf(path):
        return []
    dis = _objdump(path)
    if not dis:
        return []
    strings = elf_strings(path, min_len=4)

    hits: list[SinkHit] = []
    current_fn = "unknown"
    sink_set = set(BINARY_SINKS)
    for line in dis.splitlines():
        m_fn = _OBJDUMP_FN.match(line)
        if m_fn:
            current_fn = m_fn.group("name")
            continue
        m_bl = _OBJDUMP_BL.match(line)
        if not m_bl:
            continue
        target = m_bl.group("target").split("@", 1)[0].strip()
        if target in sink_set:
            off_hex = m_bl.group("off")
            try:
                off = int(off_hex, 16)
            except ValueError:
                off = 0
            hits.append(SinkHit(
                path=str(path), sink=target, caller=current_fn,
                offset=off_hex, context=line.strip(),
                nearby_strings=_nearby_strings(strings, off),
                confidence="hint",
                note="static disasm hit; confirm with Ghidra/REA",
            ))
    return hits


# ---- Scripts ----
_SCRIPT_RE = re.compile(
    r"(?P<kw>eval\b|exec\b|\$\([^)]*\)|`[^`]*`)"
)


def scan_script(path: Path) -> list[SinkHit]:
    """Shell/Lua/Perl script sink grep."""
    hits: list[SinkHit] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    for i, line in enumerate(text.splitlines(), start=1):
        for m in _SCRIPT_RE.finditer(line):
            hits.append(SinkHit(
                path=str(path), sink=m.group("kw")[:20],
                caller="script", offset=str(i),
                context=line.strip()[:200],
                confidence="hint",
                note="script expansion; check for untrusted input",
            ))
    return hits


def _looks_like_script(name: str) -> bool:
    return any(name.endswith(ext) for ext in
               (".sh", ".lua", ".pl", ".py", ".awk"))


def scan_for_key(fw_key: str, *, filter_glob: str | None = None) -> Path:
    """Scan a whole rootfs; write findings JSON. Returns output path.

    If `filter_glob` is given, only files whose rootfs-relative path matches
    the glob are scanned.
    """
    if fw_key not in config.FIRMWARE_KEYS:
        raise KeyError(fw_key)
    key = config.FIRMWARE_KEYS[fw_key]
    rootfs = key.rootfs
    hits: list[SinkHit] = []
    # Default: only scan high-priority binaries + scripts to keep runtime sane.
    default_bins = (
        "usr/sbin/cgi-bin/soap_agent",
        "usr/sbin/configd",
        "usr/libexec/webui-io",
        "usr/sbin/remoteshellenable",
        "usr/sbin/soapc",
        "usr/lib/librpc.so",
    )
    default_script_dirs = ("etc/init.d", "usr/sbin", "usr/bin", "ntgr")
    import fnmatch
    bin_targets: list[Path] = []
    if filter_glob:
        for p in rootfs.rglob("*"):
            rel = p.relative_to(rootfs).as_posix()
            if fnmatch.fnmatchcase(rel, filter_glob) and p.is_file():
                bin_targets.append(p)
    else:
        for rel in default_bins:
            p = rootfs / rel
            if p.is_file():
                bin_targets.append(p)
    LOG.info("scanning %d binaries", len(bin_targets))
    for p in bin_targets:
        hits.extend(scan_binary(p))

    script_targets: list[Path] = []
    if not filter_glob:
        for d in default_script_dirs:
            for p in (rootfs / d).rglob("*") if (rootfs / d).is_dir() else []:
                if p.is_file() and (_looks_like_script(p.name) or
                                    p.read_bytes()[:2] == b"#!"):
                    script_targets.append(p)
    LOG.info("scanning %d scripts", len(script_targets))
    for p in script_targets:
        hits.extend(scan_script(p))

    out_dir = config.RESEARCH_OUTPUT_DIR / "sinks" / fw_key
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / ("hits.json" if not filter_glob
                          else f"hits_{filter_glob.replace('/', '_')}.json")
    data = {
        "fw_key": fw_key,
        "scanned_binaries": [str(p) for p in bin_targets],
        "scanned_scripts": len(script_targets),
        "hits": [asdict(h) for h in hits],
        "hits_count": len(hits),
    }
    out_path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n",
                        encoding="utf-8")
    LOG.info("sinks %s: %d hits -> %s", fw_key, len(hits), out_path)
    return out_path
