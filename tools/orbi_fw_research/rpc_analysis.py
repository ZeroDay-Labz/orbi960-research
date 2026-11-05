"""rpcd ACL + plugin method extraction.

Parses:
    usr/share/rpcd/acl.d/*.json  - advertised ACL for ubus objects
    usr/lib/rpcd/*.so            - plugin shared objects (extracts method names
                                   via `strings`, filtered to C-identifier form)

Produces three artefacts per firmware key:
    acls.json       - object -> role -> {read:[methods], write:[methods]}
    plugins.json    - plugin -> [candidate_method_strings]
    mismatch.json   - ACL-advertised methods that have no corresponding string
                      in any plugin .so (candidate phantom methods, matching
                      the prior report's telnet_* finding)
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from . import config
from .common import get_logger
from .elf_analysis import elf_strings, is_elf

LOG = get_logger("orbi_fw.rpc")


IDENT_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]{2,}$")
BLOCKLIST = {
    # Common C library strings we don't want flagged as "methods".
    "malloc", "free", "calloc", "strlen", "strdup", "fprintf", "sprintf",
    "printf", "fwrite", "fread", "exit", "abort",
}


def _parse_acl_json(path: Path) -> dict:
    """Return the raw ACL JSON structure. These files are rpcd ACL blobs."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        LOG.warning("ACL parse failed for %s: %s", path, e)
        return {}


def collect_acls(rootfs: Path) -> dict:
    """Gather all ACL files under usr/share/rpcd/acl.d into a single dict.

    Return shape: {role_name: {object_name: {read:{...}, write:{...}}, ...}}
    """
    acl_dir = rootfs / "usr" / "share" / "rpcd" / "acl.d"
    out: dict = {}
    if not acl_dir.is_dir():
        return out
    for p in sorted(acl_dir.glob("*.json")):
        role_data = _parse_acl_json(p)
        for role_name, perms in role_data.items():
            out[role_name] = perms
    return out


def extract_methods_advertised(acls: dict) -> dict:
    """role -> object -> {read:[methods], write:[methods]}

    The rpcd ACL schema is nested two ways:
      role.read.<direct_obj>  : [methods]         (e.g. webui-io, download)
      role.read.ubus.<obj>    : [methods]         (ubus methods under an object)
    We flatten both forms into a single role->obj->{read,write}->methods tree.
    """
    out: dict = {}
    for role, perms in acls.items():
        role_out: dict = {}
        for section in ("read", "write"):
            section_data = perms.get(section, {})
            if not isinstance(section_data, dict):
                continue
            for key, val in section_data.items():
                if isinstance(val, list):
                    # Direct form: section.<obj>: [methods]
                    role_out.setdefault(key, {"read": [], "write": []})
                    role_out[key][section] = sorted(set(role_out[key][section] + val))
                elif isinstance(val, dict):
                    # Wrapper form (ubus): section.<wrapper>.<obj>: [methods]
                    for obj_name, methods in val.items():
                        if isinstance(methods, list):
                            role_out.setdefault(obj_name, {"read": [], "write": []})
                            role_out[obj_name][section] = sorted(
                                set(role_out[obj_name][section] + methods)
                            )
        out[role] = role_out
    return out


def plugin_strings(path: Path) -> list[str]:
    """Return C-identifier-like strings from a plugin .so.

    Noisy but fast. Filtering via IDENT_RE + BLOCKLIST removes most false
    positives. Caller cross-checks against ACL advertised names.
    """
    if not is_elf(path):
        return []
    out: set[str] = set()
    for _off, s in elf_strings(path, min_len=3):
        if IDENT_RE.match(s) and s not in BLOCKLIST:
            out.add(s)
    return sorted(out)


def scan_plugins(rootfs: Path) -> dict[str, list[str]]:
    plug_dir = rootfs / "usr" / "lib" / "rpcd"
    out: dict[str, list[str]] = {}
    if not plug_dir.is_dir():
        return out
    for p in sorted(plug_dir.glob("*.so")):
        out[p.name] = plugin_strings(p)
    return out


# Objects that are NOT served by a plugin .so, so string-based mismatch
# detection produces false positives for them. These are served by the rpcd
# daemon itself or by separate CGI binaries.
_NON_PLUGIN_OBJECTS: frozenset[str] = frozenset({
    "webui-io",   # served by /usr/libexec/webui-io CGI
    "session",    # built into rpcd daemon core
    "system",     # built into rpcd daemon core
    "uci",        # built into rpcd daemon core
    "file",       # built into rpcd daemon core
    "service",    # built into rpcd daemon core
})


def find_mismatches(advertised: dict, plugins: dict[str, list[str]]) -> list[dict]:
    """ACL-advertised methods whose name does not appear as a string in ANY
    plugin .so. Candidate phantom/unimplemented methods.

    This is imprecise (a method's dispatcher may use a composed name) but
    reliably catches the known telnet_* case. Objects in _NON_PLUGIN_OBJECTS
    are excluded (they are not implemented by any .so so the check doesn't
    apply).
    """
    all_strings: set[str] = set()
    for strs in plugins.values():
        all_strings.update(strs)

    mismatches: list[dict] = []
    for role, objs in advertised.items():
        for obj_name, sections in objs.items():
            if obj_name in _NON_PLUGIN_OBJECTS:
                continue
            for section, methods in sections.items():
                for m in methods:
                    if m == "*":
                        continue
                    if m not in all_strings:
                        mismatches.append({
                            "role": role, "object": obj_name,
                            "section": section, "method": m,
                            "note": "method name not found as string in any rpcd/*.so",
                        })
    return mismatches


def build_for_key(fw_key: str) -> Path:
    if fw_key not in config.FIRMWARE_KEYS:
        raise KeyError(fw_key)
    key = config.FIRMWARE_KEYS[fw_key]
    acls = collect_acls(key.rootfs)
    advertised = extract_methods_advertised(acls)
    plugins = scan_plugins(key.rootfs)
    mismatches = find_mismatches(advertised, plugins)

    out_dir = config.RESEARCH_OUTPUT_DIR / "rpc" / fw_key
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "acls.json").write_text(
        json.dumps(advertised, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (out_dir / "plugins.json").write_text(
        json.dumps({k: {"method_candidates_count": len(v)}
                    for k, v in plugins.items()},
                   indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (out_dir / "plugins_full.json").write_text(
        json.dumps(plugins, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (out_dir / "mismatch.json").write_text(
        json.dumps({"mismatches": mismatches,
                    "count": len(mismatches)},
                   indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    LOG.info("rpc %s: %d roles, %d plugins, %d mismatches -> %s",
             fw_key, len(advertised), len(plugins), len(mismatches), out_dir)
    return out_dir
