"""Static configuration: firmware keys, paths, and priority maps.

Nothing here contacts a device. Repo root is auto-resolved so the toolkit
is relocatable; no absolute host paths are baked in.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

# Repo root = two levels up from this file (tools/orbi_fw_research/config.py).
REPO_ROOT: Path = Path(__file__).resolve().parents[2]

FIRMWARE_EXTRACTED_DIR: Path = REPO_ROOT / "firmware_analysis" / "extracted"
RESEARCH_OUTPUT_DIR: Path = REPO_ROOT / "firmware_analysis" / "research_output"
REPORTS_DIR: Path = REPO_ROOT / "firmware_analysis" / "reports"

# Ghidra install locations searched in order. First existing wins.
GHIDRA_CANDIDATES: tuple[Path, ...] = (
    Path("/opt/ghidra_12.1.3_PUBLIC"),
    Path("/opt/ghidra_12.1.2_PUBLIC"),
    Path.home() / "tools" / "ghidra_12.1.3_PUBLIC",
    Path.home() / "tools" / "ghidra_12.1.2_PUBLIC",
)


def resolve_ghidra() -> Path | None:
    """Return the Ghidra install directory or None if not found."""
    override = os.environ.get("GHIDRA_INSTALL_DIR")
    if override and Path(override).is_dir():
        return Path(override)
    for p in GHIDRA_CANDIDATES:
        if (p / "support" / "analyzeHeadless").is_file():
            return p
    return None


@dataclass(frozen=True)
class FirmwareKey:
    """Identifies an extracted rootfs. Does not contact a device."""
    key: str           # e.g. "rbse_7215"
    model: str         # e.g. "RBSE960"
    version: str       # e.g. "V7.2.7.15"

    @property
    def rootfs(self) -> Path:
        return FIRMWARE_EXTRACTED_DIR / self.key / "rootfs"


FIRMWARE_KEYS: dict[str, FirmwareKey] = {
    "rbre_7215": FirmwareKey("rbre_7215", "RBRE960", "V7.2.7.15"),
    "rbre_7288": FirmwareKey("rbre_7288", "RBRE960", "V7.2.8.8"),
    "rbse_7215": FirmwareKey("rbse_7215", "RBSE960", "V7.2.7.15"),
    "rbse_7288": FirmwareKey("rbse_7288", "RBSE960", "V7.2.8.8"),
}

# Paired comparisons we care about. (old, new).
PAIRS: list[tuple[str, str]] = [
    ("rbse_7215", "rbse_7288"),
    ("rbre_7215", "rbre_7288"),
    # cross-model within same firmware
    ("rbre_7215", "rbse_7215"),
    ("rbre_7288", "rbse_7288"),
]

# Patterns (fnmatch-style) prioritised when ranking changed files.
# Order matters: earlier patterns = higher priority. Priority value 0 = highest.
INTEREST_PATTERNS: list[tuple[int, str, str]] = [
    (0, "usr/sbin/cgi-bin/soap_agent", "SOAP CGI — authenticated management surface"),
    (0, "usr/sbin/configd", "Configuration DAL daemon — gates SOAP state changes"),
    (0, "usr/libexec/webui-io", "Admin upload/download multicall CGI"),
    (0, "usr/sbin/remoteshellenable", "UDP/23 magic-knock SSH enabler"),
    (0, "usr/sbin/soapc", "Master-side SOAP client"),
    (1, "usr/lib/librpc.so*", "RPC core library"),
    (1, "lib/librpc.so*", "RPC core library (/lib path)"),
    (1, "usr/lib/rpcd/*.so", "rpcd plugin (ubus methods)"),
    (1, "usr/libexec/rpcd", "rpcd daemon"),
    (1, "usr/sbin/uhttpd", "Internal HTTP front-end"),
    (1, "usr/sbin/lighttpd", "External HTTP reverse proxy"),
    (1, "www/soapapi.cgi", "SOAP CGI bridge"),
    (1, "www/*.cgi", "Web CGI handler"),
    (1, "usr/share/rpcd/acl.d/*.json", "rpcd ACL definitions"),
    (1, "usr/lib/libcrypto.so*", "OpenSSL libcrypto (CVE-sensitive)"),
    (1, "usr/lib/libssl.so*", "OpenSSL libssl (CVE-sensitive)"),
    (1, "usr/sbin/sshd", "OpenSSH server"),
    (1, "usr/sbin/dropbear", "Dropbear SSH"),
    (1, "lib/modules/*/qca-nss-crypto*.ko", "QCA NSS crypto driver"),
    (1, "lib/modules/*/cryptodev.ko", "cryptodev kmod"),
    (2, "etc/init.d/*", "Service init script"),
    (2, "etc/config/*", "UCI config file"),
    (2, "usr/sbin/ssh_update_ntgr.sh", "SSH-enable helper script"),
    (2, "usr/sbin/init_sshenable", "SSH-enable launcher"),
    (2, "usr/lib/lua/**/*.lua", "LuCI/Lua app"),
    (3, "usr/bin/*", "User binary"),
    (3, "usr/sbin/*", "Admin binary"),
    (3, "usr/lib/*.so*", "Shared library"),
    (4, "etc/ssl/certs/*", "Trusted root cert"),
    (5, "*", "Other"),
]


# File-type buckets for inventory summaries.
ELF_TYPE_HINTS: tuple[str, ...] = ("ELF", "shared object", "executable")
SCRIPT_TYPE_HINTS: tuple[str, ...] = (
    "shell script", "Python script", "Perl script", "Lua script", "POSIX shell script",
)
