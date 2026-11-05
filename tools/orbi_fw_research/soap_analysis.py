"""SOAP M1 method inventory for the satellite `soap_agent` CGI.

Extracts every `M1:*` and `m:*Response` string from the binary, pairs them,
and classifies each method as:
    pre_auth  - appears near the authentication-check function (heuristic)
    read_only - matches a Get / Is / Query / List / Show prefix
    state     - everything else (the default; assumes state-changing)

Tool: `strings`, `readelf`, `objdump`. No live-device contact.
"""
from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path

from . import config
from .common import get_logger, run
from .elf_analysis import elf_strings, is_elf

LOG = get_logger("orbi_fw.soap")

SAT_SOAP_AGENT_REL = "usr/sbin/cgi-bin/soap_agent"
MASTER_SOAPC_REL = "usr/sbin/soapc"

_METHOD_RE = re.compile(r"^M1:[A-Z][A-Za-z0-9_]{2,}$")
_RESPONSE_RE = re.compile(r"^m:([A-Z][A-Za-z0-9_]{2,})Response$")


READ_PREFIXES = ("Get", "Is", "Query", "List", "Show", "Check", "Fetch", "Read", "View")


def _classify_rw(method_name: str) -> str:
    """Return 'read_only' or 'state' from a bare method name (no 'M1:' prefix)."""
    for p in READ_PREFIXES:
        if method_name.startswith(p):
            return "read_only"
    return "state"


@dataclass
class SoapMethod:
    name: str                   # "Authenticate" (no M1: prefix)
    m1_offset: int = -1
    response_present: bool = False
    response_offset: int = -1
    classification: str = "state"   # pre_auth | read_only | state
    note: str = ""


def extract_methods(soap_agent: Path) -> list[SoapMethod]:
    """Pull M1:* and m:*Response strings from soap_agent."""
    if not is_elf(soap_agent):
        raise ValueError(f"not an ELF: {soap_agent}")
    strings = elf_strings(soap_agent, min_len=5)
    m1s: dict[str, int] = {}
    responses: dict[str, int] = {}
    for off, s in strings:
        if _METHOD_RE.match(s):
            name = s[len("M1:"):]
            m1s.setdefault(name, off)
        m_r = _RESPONSE_RE.match(s)
        if m_r:
            responses.setdefault(m_r.group(1), off)

    methods: list[SoapMethod] = []
    for name in sorted(set(m1s) | set(responses)):
        m = SoapMethod(
            name=name,
            m1_offset=m1s.get(name, -1),
            response_present=name in responses,
            response_offset=responses.get(name, -1),
            classification=_classify_rw(name),
        )
        if name == "Authenticate":
            m.classification = "pre_auth"
            m.note = "pre-auth: establishes session"
        methods.append(m)
    return methods


def build_for_key(fw_key: str) -> Path:
    if fw_key not in config.FIRMWARE_KEYS:
        raise KeyError(fw_key)
    key = config.FIRMWARE_KEYS[fw_key]
    soap_path = key.rootfs / SAT_SOAP_AGENT_REL
    if not soap_path.is_file():
        # The master doesn't have soap_agent; only sat does. Soft-return.
        out_dir = config.RESEARCH_OUTPUT_DIR / "soap" / fw_key
        out_dir.mkdir(parents=True, exist_ok=True)
        out = out_dir / "methods.json"
        out.write_text(
            json.dumps({"fw_key": fw_key, "note": "no soap_agent in rootfs",
                        "methods": []}, indent=2) + "\n",
            encoding="utf-8",
        )
        LOG.info("soap %s: no soap_agent (expected for master)", fw_key)
        return out
    methods = extract_methods(soap_path)

    # Summary counts by classification.
    counts: dict[str, int] = {}
    for m in methods:
        counts[m.classification] = counts.get(m.classification, 0) + 1

    out_dir = config.RESEARCH_OUTPUT_DIR / "soap" / fw_key
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / "methods.json"
    out.write_text(
        json.dumps({
            "fw_key": fw_key,
            "binary": str(soap_path.relative_to(key.rootfs)),
            "method_count": len(methods),
            "classification_counts": counts,
            "methods": [asdict(m) for m in methods],
            "disclaimer": ("Classification is heuristic (name prefix). "
                           "'pre_auth' is set only for 'Authenticate'. "
                           "Confirm boundaries with Ghidra/REA call-graph."),
        }, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    LOG.info("soap %s: %d methods -> %s", fw_key, len(methods), out)
    return out
