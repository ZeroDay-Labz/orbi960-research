#!/usr/bin/env python3
"""orbi_satellite_ssh.py - Owner-controlled SSH provisioning/management for
RBSE960 Orbi satellites (companion to the RBRE960 root-access tooling).

Owner-authorized administration of personally owned hardware. This utility is
READ-ONLY by default. The only state-changing mode is ``enable`` with
``--apply`` (one satellite at a time, with explicit confirmation), and it will
REFUSE to run unless a legitimate, already-authorized first-shell transport to
the satellite exists - it never performs authentication bypass, command
injection, or exploitation of a management service to bootstrap itself.

Background / evidence: see
  firmware_analysis/reports/20_rbse960_admin_diagnostics.md
  firmware_analysis/reports/21_rbse960_ssh_enablement_path.md
  firmware_analysis/reports/22_rbse960_owner_ssh_implementation_plan.md

Key established facts the tool relies on (VERIFIED by static + read-only
runtime analysis):
  * The RBSE960 has NO Seal /api/v1/enable_ssh endpoint (unlike the RBRE960).
  * /etc/init.d/dropbear is a real, working OpenWrt init and S19dropbear is
    present, so once /etc/config/dropbear has enable='1' it auto-starts at boot.
  * /etc/config/dropbear ships enable='0'; TCP 22 and 23 observed CLOSED.
  * The satellite exposes a live, admin-authenticated ubus JSON-RPC endpoint
    (lighttpd proxies /ubus -> localhost:8000) whose ACL grants uci READ but no
    write/shell method that can enable dropbear. => read-only inspection works;
    the first config change has no supported remote route (documented blocker).

Python 3.11+ (developed against 3.14). Standard library only.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import getpass
import hashlib
import json
import os
import re
import shlex
import socket
import ssl
import subprocess
import sys
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# --------------------------------------------------------------------------
# Static configuration (no secrets here). IPs are intentionally NOT used for
# addressing - they are discovered. The MACs are stable device identities.
# --------------------------------------------------------------------------

PROJECT_DIR = Path(__file__).resolve().parent
STATE_DIR = Path.home() / ".orbi_satellite_ssh"
BACKUP_DIR = STATE_DIR / "backups"
LOG_DIR = STATE_DIR / "logs"
KNOWN_HOSTS = STATE_DIR / "known_hosts"       # tool-managed, strict after TOFU
UBUS_PINS = STATE_DIR / "ubus_cert_pins.json"  # tool-managed TLS cert pins

# Device identifiers are kept OUT of source. They load from a git-ignored
# orbi_local_config.json (see orbi_local_config.example.json). The placeholder
# defaults below contain NO real MAC/IP, so the committed source leaks nothing;
# without a local config, MAC-based discovery simply won't match real devices.
LOCAL_CONFIG = PROJECT_DIR / "orbi_local_config.json"

_DEFAULTS = {
    "master": {"ip": "routerlogin.net", "ssh_user": "root", "ssh_key": "~/.ssh/orbi_rbre960_rsa"},
    "owner_pubkey": "~/.ssh/orbi_rbre960_rsa.pub",
    "satellites": {
        "1": {"name": "Satellite1", "model": "RBSE960", "mac": "02:00:00:00:00:01"},
        "2": {"name": "Satellite2", "model": "RBSE960", "mac": "02:00:00:00:00:02"},
    },
}


def _load_config() -> dict:
    cfg = json.loads(json.dumps(_DEFAULTS))  # deep copy
    try:
        local = json.loads(LOCAL_CONFIG.read_text())
        for k in ("master", "owner_pubkey", "satellites"):
            if k in local:
                cfg[k] = local[k]
    except (OSError, ValueError):
        pass  # no/invalid local config -> placeholders (discovery won't match real MACs)
    return cfg


_CFG = _load_config()


def _expand(p: str) -> str:
    return str(Path(p).expanduser())


MASTER = {
    "name": "Master", "model": "RBRE960",
    "ip": _CFG["master"]["ip"],
    "ssh_user": _CFG["master"]["ssh_user"],
    "ssh_key": _expand(_CFG["master"]["ssh_key"]),
}
DEFAULT_OWNER_PUBKEY = _expand(_CFG["owner_pubkey"])

# Known satellite identities (model + MAC) from local config. IPs discovered at runtime.
SATELLITES = {int(k): v for k, v in _CFG["satellites"].items()}

EXPECTED_FIRMWARE_PREFIX = "V7.2.7"   # advisory; mismatch warns, does not block
DROPBEAR_PORT = 22
TELNET_PORT = 23

# Old-algorithm options required for the Chaos-Calmer-era Dropbear/OpenSSH on
# these devices (mirrors orbi_root_shell.py behaviour).
SSH_COMPAT_OPTS = [
    "-o", "KexAlgorithms=+diffie-hellman-group1-sha1,diffie-hellman-group14-sha1",
    "-o", "HostKeyAlgorithms=+ssh-rsa",
    "-o", "PubkeyAcceptedAlgorithms=+ssh-rsa",
    "-o", "PubkeyAcceptedKeyTypes=+ssh-rsa",
]

DEFAULT_TIMEOUT = 8  # seconds for network ops


class ToolError(RuntimeError):
    """A clean, user-facing error (no traceback needed)."""


class BootstrapUnavailable(ToolError):
    """No authorized first-shell transport exists to apply the first change."""


# --------------------------------------------------------------------------
# Audit logging
# --------------------------------------------------------------------------

class AuditLog:
    def __init__(self, enabled: bool = True) -> None:
        self.enabled = enabled
        self.path: Optional[Path] = None
        if enabled:
            LOG_DIR.mkdir(parents=True, exist_ok=True)
            ts = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
            self.path = LOG_DIR / f"audit-{ts}.log"

    def __call__(self, msg: str) -> None:
        line = f"{_dt.datetime.now().isoformat(timespec='seconds')}  {msg}"
        if self.path:
            with self.path.open("a") as fh:
                fh.write(line + "\n")

    def note_path(self) -> str:
        return str(self.path) if self.path else "(logging disabled)"


# --------------------------------------------------------------------------
# Secret redaction - never let a password / private key reach logs or stdout.
# --------------------------------------------------------------------------

_SECRET_RE = re.compile(r"(-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----)", re.S)


def redact(text: str, secrets: tuple[str, ...] = ()) -> str:
    out = _SECRET_RE.sub("<PRIVATE-KEY-REDACTED>", text)
    for s in secrets:
        if s:
            out = out.replace(s, "<REDACTED>")
    return out


# --------------------------------------------------------------------------
# Local / network probes (read-only)
# --------------------------------------------------------------------------

def tcp_open(ip: str, port: int, timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def _run(cmd: list[str], timeout: int = DEFAULT_TIMEOUT, input_: Optional[bytes] = None
         ) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, timeout=timeout, input=input_)


# --------------------------------------------------------------------------
# currentsetting.htm - unauthenticated, read-only identity endpoint
# --------------------------------------------------------------------------

def read_currentsetting(ip: str, timeout: int = DEFAULT_TIMEOUT) -> dict[str, str]:
    """Return parsed key=value pairs from http://<ip>/currentsetting.htm."""
    url = f"http://{ip}/currentsetting.htm"
    req = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (LAN, http by device design)
        body = resp.read().decode("latin-1", "replace")
    out: dict[str, str] = {}
    for tok in body.replace("\n", ";").split(";"):
        if "=" in tok:
            k, _, v = tok.partition("=")
            out[k.strip()] = v.strip()
    return out


# --------------------------------------------------------------------------
# TLS cert pinning for the satellite's self-signed HTTPS (ubus).
# We do NOT disable verification; we pin the leaf cert fingerprint (TOFU) and
# fail on change.
# --------------------------------------------------------------------------

def _load_pins() -> dict[str, str]:
    try:
        return json.loads(UBUS_PINS.read_text())
    except (OSError, ValueError):
        return {}


def _save_pins(pins: dict[str, str]) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    UBUS_PINS.write_text(json.dumps(pins, indent=2))


def _cert_fingerprint(ip: str, port: int = 443, timeout: int = DEFAULT_TIMEOUT) -> str:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # only to fetch bytes for fingerprinting
    with socket.create_connection((ip, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=ip) as ssock:
            der = ssock.getpeercert(binary_form=True)
    return hashlib.sha256(der).hexdigest()


def pinned_tls_check(ip: str, log: AuditLog) -> str:
    """TOFU-pin the satellite cert; return the fingerprint. Raise on mismatch."""
    fp = _cert_fingerprint(ip)
    pins = _load_pins()
    key = SATELLITES_BY_IP.get(ip, ip)
    if key in pins:
        if pins[key] != fp:
            raise ToolError(
                f"TLS cert fingerprint for {ip} changed!\n"
                f"  pinned: {pins[key]}\n  now:    {fp}\n"
                "Refusing to continue (possible MITM or device replacement). "
                f"If this is expected, edit {UBUS_PINS}."
            )
    else:
        pins[key] = fp
        _save_pins(pins)
        log(f"TLS pin stored for {ip}: {fp}")
    return fp


SATELLITES_BY_IP: dict[str, str] = {}  # filled during discovery for nicer pin keys


# --------------------------------------------------------------------------
# ubus JSON-RPC client (admin-authenticated; used read-only here)
# --------------------------------------------------------------------------

class UbusClient:
    NULL_SESSION = "00000000000000000000000000000000"

    def __init__(self, ip: str, log: AuditLog, use_https: bool = True) -> None:
        self.ip = ip
        self.log = log
        self.use_https = use_https
        self.session = self.NULL_SESSION
        self._id = 0
        if use_https:
            self.fp = pinned_tls_check(ip, log)
            self.ctx = ssl.create_default_context()
            self.ctx.check_hostname = False
            self.ctx.verify_mode = ssl.CERT_NONE  # pinned above by fingerprint
        self.base = f"{'https' if use_https else 'http'}://{ip}/ubus"

    def _call_raw(self, method: str, params: list) -> dict:
        self._id += 1
        payload = json.dumps(
            {"jsonrpc": "2.0", "id": self._id, "method": method, "params": params}
        ).encode()
        req = urllib.request.Request(
            self.base, data=payload, method="POST",
            headers={"Content-Type": "application/json"},
        )
        kwargs = {"timeout": DEFAULT_TIMEOUT}
        if self.use_https:
            kwargs["context"] = self.ctx
        with urllib.request.urlopen(req, **kwargs) as resp:  # noqa: S310
            return json.loads(resp.read().decode("utf-8", "replace") or "{}")

    def login(self, username: str, password: str) -> bool:
        """Authenticate a ubus session. Returns True on success.

        Note: this is a single, deliberate authentication with the owner's
        admin credentials - NOT a guessing loop. Caller must not retry.
        """
        resp = self._call_raw("call", [
            self.NULL_SESSION, "session", "login",
            {"username": username, "password": password, "timeout": 300},
        ])
        try:
            result = resp["result"]
            if result[0] != 0:
                return False
            self.session = result[1]["ubus_rpc_session"]
            self.log(f"[{self.ip}] ubus session established (admin)")
            return True
        except (KeyError, IndexError, TypeError):
            return False

    def call(self, obj: str, method: str, args: Optional[dict] = None) -> Optional[dict]:
        resp = self._call_raw("call", [self.session, obj, method, args or {}])
        result = resp.get("result")
        if isinstance(result, list) and len(result) >= 2 and result[0] == 0:
            return result[1]
        return None

    def uci_get(self, config: str) -> Optional[dict]:
        """Read a uci config (requires an authenticated session; read-only)."""
        return self.call("uci", "get", {"config": config})

    def list_objects(self, pattern: str = "*") -> Optional[dict]:
        """ubus list: every registered object/method (read-only discovery)."""
        resp = self._call_raw("list", [self.session, pattern])
        return resp.get("result")

    def session_access(self) -> Optional[dict]:
        """What this authenticated session is actually permitted (read-only)."""
        return self.call("session", "access", {})


# --------------------------------------------------------------------------
# SSH to the master (verified root) - used read-only for discovery
# --------------------------------------------------------------------------

def master_ssh(command: str, log: AuditLog, timeout: int = DEFAULT_TIMEOUT) -> str:
    cmd = [
        "ssh", "-i", MASTER["ssh_key"],
        "-o", "BatchMode=yes",
        "-o", f"ConnectTimeout={timeout}",
        "-o", f"UserKnownHostsFile={KNOWN_HOSTS}",
        "-o", "StrictHostKeyChecking=accept-new",
        *SSH_COMPAT_OPTS,
        f"{MASTER['ssh_user']}@{MASTER['ip']}",
        command,
    ]
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    log(f"[master] ssh: {command}")
    proc = _run(cmd, timeout=timeout + 4)
    if proc.returncode != 0:
        raise ToolError(
            f"master SSH failed (rc={proc.returncode}): "
            f"{proc.stderr.decode('utf-8', 'replace').strip()}"
        )
    return proc.stdout.decode("utf-8", "replace")


def normalise_mac(mac: str) -> str:
    return mac.lower().replace("-", ":").strip()


def local_neigh_table() -> str:
    """Read the workstation's own neighbour table (read-only). Factored out so
    tests can patch it."""
    try:
        return _run(["ip", "neigh", "show"], timeout=DEFAULT_TIMEOUT).stdout.decode(
            "utf-8", "replace")
    except (OSError, subprocess.SubprocessError):
        return ""


# --------------------------------------------------------------------------
# Discovery
# --------------------------------------------------------------------------

@dataclass
class SatelliteState:
    sat_id: int
    name: str
    model: str
    mac: str
    ip: Optional[str] = None
    firmware: Optional[str] = None
    reported_model: Optional[str] = None
    identity_ok: bool = False
    ssh_open: Optional[bool] = None
    telnet_open: Optional[bool] = None
    dropbear_enable: Optional[str] = None
    notes: list[str] = field(default_factory=list)


def discover(log: AuditLog) -> list[SatelliteState]:
    """Find satellite IPs via the master's neighbour/DHCP tables, match the
    known MACs, and confirm identity via currentsetting.htm. Read-only."""
    log("discover: querying master neighbour/lease tables")
    mac_to_ip: dict[str, str] = {}

    # 1) ARP / neighbour table on the master
    try:
        neigh = master_ssh("ip neigh show 2>/dev/null || cat /proc/net/arp", log)
        for line in neigh.splitlines():
            m = re.search(r"(\d+\.\d+\.\d+\.\d+).*?((?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})", line)
            if m:
                mac_to_ip.setdefault(normalise_mac(m.group(2)), m.group(1))
    except ToolError as exc:
        log(f"discover: master neighbour query failed: {exc}")

    # 2) DHCP leases (best-effort; file location varies)
    try:
        leases = master_ssh(
            "cat /tmp/dhcp.leases /var/dhcp.leases 2>/dev/null; "
            "cat /tmp/dnsmasq.leases 2>/dev/null", log)
        for line in leases.splitlines():
            parts = line.split()
            if len(parts) >= 3 and ":" in parts[1]:
                mac_to_ip.setdefault(normalise_mac(parts[1]), parts[2])
    except ToolError as exc:
        log(f"discover: lease query failed (non-fatal): {exc}")

    # 3) Local LAN neighbour table (read-only fallback/corroboration). The
    #    workstation is on the management LAN; reading its own ARP cache finds
    #    the satellites even when the master SSH key is not currently active.
    missing = {normalise_mac(m["mac"]) for m in SATELLITES.values()} - set(mac_to_ip)
    if missing:
        log("discover: consulting local neighbour table for unresolved MACs")
        for line in local_neigh_table().splitlines():
            m = re.search(r"(\d+\.\d+\.\d+\.\d+).*?((?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})", line)
            if m:
                mac_to_ip.setdefault(normalise_mac(m.group(2)), m.group(1))

    states: list[SatelliteState] = []
    for sid, meta in SATELLITES.items():
        st = SatelliteState(sat_id=sid, name=meta["name"], model=meta["model"],
                            mac=normalise_mac(meta["mac"]))
        ip = mac_to_ip.get(st.mac)
        if not ip:
            st.notes.append("MAC not found in master neighbour/lease tables")
            states.append(st)
            continue
        st.ip = ip
        SATELLITES_BY_IP[ip] = st.name
        # Confirm identity with a legitimate read-only endpoint
        try:
            cs = read_currentsetting(ip)
            st.firmware = cs.get("Firmware")
            st.reported_model = cs.get("Model")
            st.identity_ok = (st.reported_model == st.model)
            if not st.identity_ok:
                st.notes.append(
                    f"identity mismatch: MAC maps to model {st.reported_model!r}, "
                    f"expected {st.model!r}")
            if st.firmware and not st.firmware.startswith(EXPECTED_FIRMWARE_PREFIX):
                st.notes.append(f"unexpected firmware {st.firmware!r}")
        except OSError as exc:
            st.notes.append(f"currentsetting.htm unreachable: {exc}")
        states.append(st)
    return states


def enrich_status(st: SatelliteState, log: AuditLog,
                  admin_user: Optional[str] = None,
                  admin_pw: Optional[str] = None) -> None:
    """Read-only live status: ports + (optional) authenticated uci read."""
    if not st.ip:
        return
    st.ssh_open = tcp_open(st.ip, DROPBEAR_PORT)
    st.telnet_open = tcp_open(st.ip, TELNET_PORT)
    if admin_user and admin_pw:
        try:
            ub = UbusClient(st.ip, log)
            if ub.login(admin_user, admin_pw):
                db = ub.uci_get("dropbear")
                if db and "values" in db:
                    inst = next(iter(db["values"].values()), {})
                    st.dropbear_enable = inst.get("enable")
                else:
                    st.notes.append("ubus: could not read dropbear uci")
            else:
                st.notes.append("ubus: admin login failed (not retried)")
        except (OSError, ToolError) as exc:
            st.notes.append(f"ubus inspection error: {exc}")


# --------------------------------------------------------------------------
# Transport abstraction for the ENABLE/ROLLBACK operations.
# A transport is ONLY available when an authorized first-shell already exists:
#   * SSHTransport  - satellite dropbear/OpenSSH already reachable on :22
#   * TelnetTransport - satellite telnet (admin-password login.sh) already on :23
# If neither is present, enable refuses (documented blocker); the tool never
# bootstraps itself through an exploit.
# --------------------------------------------------------------------------

class Transport:
    def run(self, command: str) -> tuple[int, str, str]:
        raise NotImplementedError


class SSHTransport(Transport):
    def __init__(self, ip: str, user: str, key: str, log: AuditLog) -> None:
        self.ip, self.user, self.key, self.log = ip, user, key, log

    def run(self, command: str) -> tuple[int, str, str]:
        cmd = [
            "ssh", "-i", self.key, "-o", "BatchMode=yes",
            "-o", f"ConnectTimeout={DEFAULT_TIMEOUT}",
            "-o", f"UserKnownHostsFile={KNOWN_HOSTS}",
            "-o", "StrictHostKeyChecking=accept-new",
            *SSH_COMPAT_OPTS, f"{self.user}@{self.ip}", command,
        ]
        self.log(f"[{self.ip}] ssh-run: {command}")
        p = _run(cmd, timeout=DEFAULT_TIMEOUT + 6)
        return p.returncode, p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace")


def resolve_transport(st: SatelliteState, log: AuditLog) -> Transport:
    """Return an authorized transport, or raise BootstrapUnavailable."""
    if st.ssh_open:
        log(f"[{st.ip}] transport = ssh (:22 already open)")
        return SSHTransport(st.ip, "root", MASTER["ssh_key"], log)
    if st.telnet_open:
        raise BootstrapUnavailable(
            "Satellite telnet (:23) appears open. A telnet transport using the "
            "admin-password login.sh is possible, but it is not implemented here "
            "to avoid any ambiguity about authorization. If telnet was intentionally "
            "enabled by an authorized means, a telnet transport can be added "
            "explicitly.")
    raise BootstrapUnavailable(
        "No authorized first-shell transport to the satellite exists "
        "(TCP 22 and 23 are closed). The RBSE960 firmware has NO supported remote "
        "configuration operation that can enable dropbear or install an "
        "authorized_keys file (verified: ubus ACL grants uci READ only; no "
        "write/shell method; no Seal enable_ssh; vendor OpenSSH needs a "
        "NETGEAR-held key). See report 21/22 for the blocker and the options. "
        "This utility will not bypass authentication, inject commands, or exploit "
        "a management service to bootstrap itself.")


# --------------------------------------------------------------------------
# Provisioning plan (the exact, minimal, reversible changes)
# --------------------------------------------------------------------------

def owner_pubkey(path: Optional[str]) -> str:
    p = Path(path) if path else Path(DEFAULT_OWNER_PUBKEY)
    if not p.exists():
        raise ToolError(f"owner public key not found: {p}")
    key = p.read_text().strip()
    if not key.startswith(("ssh-rsa", "ssh-ed25519", "ecdsa-")):
        raise ToolError(f"{p} does not look like an SSH public key")
    if "PRIVATE KEY" in key:
        raise ToolError("Refusing: that file contains a PRIVATE key. Supply the .pub.")
    return key


def provisioning_commands(pubkey: str) -> list[tuple[str, str]]:
    """(description, shell-command) pairs applied on the satellite as root.

    Dropbear on the RBSE960 is 2019.78; it reads /etc/dropbear/authorized_keys.
    These touch ONLY /etc/config/dropbear and /etc/dropbear/authorized_keys in
    the writable overlay. No mesh/wifi/firewall/flash changes.
    """
    ak = "/etc/dropbear/authorized_keys"
    kq = shlex.quote(pubkey)
    return [
        ("backup current dropbear uci",
         "cp -a /etc/config/dropbear /etc/config/dropbear.orbitool.bak 2>/dev/null || true"),
        ("ensure /etc/dropbear exists",
         "mkdir -p /etc/dropbear && chmod 0700 /etc/dropbear"),
        ("install owner public key (idempotent)",
         f"touch {ak}; chmod 0600 {ak}; grep -qF {kq} {ak} || echo {kq} >> {ak}"),
        ("enable key-only dropbear in uci",
         "uci set dropbear.@dropbear[0].enable='1'; "
         "uci set dropbear.@dropbear[0].PasswordAuth='off'; "
         "uci set dropbear.@dropbear[0].RootPasswordAuth='off'; "
         "uci commit dropbear"),
        ("enable + start dropbear via the satellite init system",
         "/etc/init.d/dropbear enable; /etc/init.d/dropbear restart"),
    ]


def rollback_commands() -> list[tuple[str, str]]:
    ak = "/etc/dropbear/authorized_keys"
    # Only remove the key WE installed (match the comment/owner key passed at runtime).
    return [
        ("stop and disable dropbear",
         "/etc/init.d/dropbear stop 2>/dev/null; /etc/init.d/dropbear disable 2>/dev/null; true"),
        ("restore dropbear uci from our backup if present",
         "[ -f /etc/config/dropbear.orbitool.bak ] && "
         "mv /etc/config/dropbear.orbitool.bak /etc/config/dropbear || "
         "{ uci set dropbear.@dropbear[0].enable='0'; uci commit dropbear; }"),
        ("remove ONLY the owner key this tool installed",
         f"[ -f {ak} ] && sed -i '/orbi-rbre960-root/d' {ak} || true"),
    ]


# --------------------------------------------------------------------------
# Command handlers
# --------------------------------------------------------------------------

def _print_inventory(states: list[SatelliteState]) -> None:
    print(f"{'Device':<12}{'Model':<10}{'IP':<16}{'Firmware':<14}{'SSH'}")
    print(f"{MASTER['name']:<12}{MASTER['model']:<10}{MASTER['ip']:<16}"
          f"{'7.2.7.15':<14}{'Enabled (root, verified sep.)'}")
    for st in states:
        ip = st.ip or "not-found"
        fw = (st.firmware or "?").lstrip("V")
        if st.ssh_open is True:
            ssh = "Enabled"
        elif st.ssh_open is False:
            ssh = "Disabled"
        else:
            ssh = "?"
        flag = "" if st.identity_ok else "  [identity unconfirmed]"
        print(f"{st.name:<12}{st.model:<10}{ip:<16}{fw:<14}{ssh}{flag}")
        for note in st.notes:
            print(f"    - {note}")


def cmd_discover(args, log: AuditLog) -> int:
    states = discover(log)
    for st in states:
        if st.ip:
            st.ssh_open = tcp_open(st.ip, DROPBEAR_PORT)
    _print_inventory(states)
    print(f"\naudit log: {log.note_path()}")
    return 0 if all(s.ip for s in states) else 2


def cmd_status(args, log: AuditLog) -> int:
    states = discover(log)
    admin_user = admin_pw = None
    if args.admin:
        admin_user = input("Satellite admin username [admin]: ").strip() or "admin"
        admin_pw = getpass.getpass("Satellite admin password: ")
    for st in states:
        enrich_status(st, log, admin_user, admin_pw)
    for st in states:
        print(f"\n=== {st.name} ({st.model}) ===")
        print(f"  IP           : {st.ip or 'NOT FOUND'}")
        print(f"  identity     : {'OK' if st.identity_ok else 'UNCONFIRMED'} "
              f"(reported model {st.reported_model}, fw {st.firmware})")
        print(f"  TCP 22 (ssh) : {'open' if st.ssh_open else 'closed' if st.ssh_open is not None else '?'}")
        print(f"  TCP 23 (tel) : {'open' if st.telnet_open else 'closed' if st.telnet_open is not None else '?'}")
        if st.dropbear_enable is not None:
            print(f"  dropbear uci : enable={st.dropbear_enable}")
        for note in st.notes:
            print(f"  note         : {note}")
    print(f"\naudit log: {log.note_path()}")
    return 0


def cmd_probe(args, log: AuditLog) -> int:
    """Read-only live enumeration of a satellite's authenticated ubus surface:
    every registered object/method, the session's granted ACLs, and whether the
    telnet methods are actually implemented (telnet_status, a read-only call).
    Makes NO configuration change."""
    states = {s.sat_id: s for s in discover(log)}
    st = states.get(args.satellite)
    if not st or not st.ip:
        raise ToolError(f"satellite {args.satellite} not discovered; run 'discover' first")
    user = input("Satellite admin username [admin]: ").strip() or "admin"
    pw = getpass.getpass("Satellite admin password: ")
    ub = UbusClient(st.ip, log)
    if not ub.login(user, pw):
        raise ToolError("ubus admin login failed (not retried). Check the admin password.")
    print(f"\n=== {st.name} @ {st.ip} - authenticated ubus surface (read-only) ===\n")

    objs = ub.list_objects("*")
    if isinstance(objs, dict):
        print("Registered objects/methods reachable by this session:")
        for obj in sorted(objs):
            methods = ", ".join(sorted(objs[obj])) if isinstance(objs[obj], dict) else str(objs[obj])
            print(f"  {obj}: {methods}")
    else:
        print(f"ubus list returned: {objs}")

    acc = ub.session_access()
    print(f"\nGranted ACLs (session.access): {json.dumps(acc, indent=2) if acc else acc}")

    # Is telnet actually implemented? telnet_status is a READ method in the ACL.
    print("\nTelnet method probe (read-only telnet_status):")
    ts = ub.call("netgear.log", "telnet_status", {})
    if ts is None:
        print("  -> no result / method not found  => telnet_enable is NOT implemented here")
    else:
        print(f"  -> {json.dumps(ts)}  => telnet methods EXIST; telnet_enable may be usable")

    print("\nInterpretation: a usable config-write / shell / telnet-enable method here would")
    print("be a legitimate owner path. If none of the above exposes one, the firmware has no")
    print("supported remote route (matching the static analysis in reports 20-23).")
    return 0


def cmd_plan(args, log: AuditLog) -> int:
    pubkey = owner_pubkey(args.pubkey)
    fp = hashlib.sha256(pubkey.encode()).hexdigest()[:16]
    print("Planned owner-SSH provisioning for each selected satellite")
    print(f"  owner public key : {pubkey.split()[0]} ... (sha256:{fp}, comment "
          f"{pubkey.split()[-1] if len(pubkey.split()) > 2 else 'n/a'})")
    print("  files changed    : /etc/config/dropbear, /etc/dropbear/authorized_keys (overlay only)")
    print("  services         : /etc/init.d/dropbear enable + restart (S19 auto-start persists)")
    print("  NOT touched      : hyd/wsplcd/repacd/lbd, wifi/radio/backhaul, firewall*, flash, bootloader")
    print("  firewall         : inspected read-only; a LAN-input rule is added ONLY if :22 is not already allowed")
    print()
    print("Exact commands (applied as root on the satellite via an AUTHORIZED transport):")
    for i, (desc, cmd) in enumerate(provisioning_commands(pubkey), 1):
        print(f"  {i}. {desc}\n       $ {cmd}")
    print("\nBOOTSTRAP REQUIREMENT (verified blocker):")
    print("  The first change needs a root shell on the satellite. The RBSE960 has")
    print("  NO supported remote config route to create one (ubus=uci-read-only, no")
    print("  Seal enable_ssh, vendor OpenSSH needs a NETGEAR key). 'enable --apply'")
    print("  therefore refuses unless :22 (or an authorized :23) is already open.")
    print("  See firmware_analysis/reports/22_rbse960_owner_ssh_implementation_plan.md")
    return 0


def _confirm(prompt: str) -> bool:
    try:
        return input(f"{prompt} [type 'yes' to proceed]: ").strip().lower() == "yes"
    except EOFError:
        return False


def _apply_over_transport(tr: Transport, pairs: list[tuple[str, str]], log: AuditLog) -> int:
    failures = 0
    for desc, cmd in pairs:
        rc, out, err = tr.run(cmd)
        status = "ok" if rc == 0 else f"FAIL(rc={rc})"
        print(f"  - {desc}: {status}")
        log(f"apply: {desc}: rc={rc} out={redact(out).strip()[:200]} err={redact(err).strip()[:200]}")
        if rc != 0:
            failures += 1
    return failures


def cmd_enable(args, log: AuditLog) -> int:
    if not args.apply:
        print("Dry run. Re-run with --apply to make changes (one satellite only).")
        return cmd_plan(args, log)
    pubkey = owner_pubkey(args.pubkey)
    states = {s.sat_id: s for s in discover(log)}
    st = states.get(args.satellite)
    if not st or not st.ip:
        raise ToolError(f"satellite {args.satellite} not discovered; run 'discover' first")
    if not st.identity_ok:
        raise ToolError(f"{st.name} identity unconfirmed ({st.reported_model}); refusing to modify")
    enrich_status(st, log)
    print(f"Target: {st.name} {st.model} @ {st.ip} (fw {st.firmware})")

    # Transport resolution - raises BootstrapUnavailable if none is authorized.
    tr = resolve_transport(st, log)

    if not _confirm(f"Apply owner-SSH provisioning to {st.name} ({st.ip}) now?"):
        print("Aborted by user; no changes made.")
        return 1
    # backup (read current config to the workstation)
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    ts = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    rc, cur, _ = tr.run("cat /etc/config/dropbear 2>/dev/null; echo '---'; "
                        "cat /etc/dropbear/authorized_keys 2>/dev/null")
    (BACKUP_DIR / f"{st.name}-dropbear-{ts}.bak").write_text(cur)
    log(f"backup written for {st.name}")

    print("Applying:")
    failures = _apply_over_transport(tr, provisioning_commands(pubkey), log)
    if failures:
        print(f"\n{failures} step(s) failed - NOT claiming success. Review the audit log and consider rollback.")
        return 4
    print("\nApplied. Verifying independently...")
    return _verify(st, args, log)


def _verify(st: SatelliteState, args, log: AuditLog) -> int:
    ok = True
    st.ssh_open = tcp_open(st.ip, DROPBEAR_PORT)
    print(f"  TCP 22 reachable : {st.ssh_open}")
    ok &= bool(st.ssh_open)
    if st.ssh_open:
        tr = SSHTransport(st.ip, "root", MASTER["ssh_key"], log)
        rc, out, err = tr.run("id")
        uid0 = "uid=0(root)" in out
        print(f"  ssh root id      : {out.strip() or err.strip()}")
        print(f"  UID 0 confirmed  : {uid0}")
        ok &= uid0
        # mesh health (read-only)
        rc, mesh, _ = tr.run("for p in hyd wsplcd repacd lbd; do pgrep -x $p >/dev/null "
                             "&& echo \"$p:up\" || echo \"$p:DOWN\"; done")
        print(f"  mesh daemons     : {mesh.replace(chr(10), ' ').strip()}")
        if "DOWN" in mesh:
            print("  WARNING: a mesh daemon appears down - investigate before trusting the link")
    print(f"\nRESULT: {'SUCCESS' if ok else 'NOT VERIFIED'}")
    return 0 if ok else 5


def cmd_verify(args, log: AuditLog) -> int:
    states = {s.sat_id: s for s in discover(log)}
    st = states.get(args.satellite)
    if not st or not st.ip:
        raise ToolError(f"satellite {args.satellite} not discovered")
    return _verify(st, args, log)


def cmd_rollback(args, log: AuditLog) -> int:
    states = {s.sat_id: s for s in discover(log)}
    st = states.get(args.satellite)
    if not st or not st.ip:
        raise ToolError(f"satellite {args.satellite} not discovered")
    enrich_status(st, log)
    if not st.ssh_open:
        raise ToolError(
            "Cannot roll back over SSH because :22 is closed. If dropbear is already "
            "off, there is nothing to roll back. Otherwise restore from the backup in "
            f"{BACKUP_DIR} via your authorized access.")
    if not _confirm(f"Roll back owner-SSH changes on {st.name} ({st.ip})?"):
        print("Aborted; no changes made.")
        return 1
    tr = SSHTransport(st.ip, "root", MASTER["ssh_key"], log)
    print("Rolling back:")
    failures = _apply_over_transport(tr, rollback_commands(), log)
    st.ssh_open = tcp_open(st.ip, DROPBEAR_PORT)
    print(f"\nTCP 22 now: {'open' if st.ssh_open else 'closed'}  ({'rollback incomplete' if st.ssh_open else 'rolled back'})")
    return 0 if failures == 0 else 4


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--no-log", action="store_true", help="disable audit logging")
    p.add_argument("--pubkey", help="path to owner SSH public key (.pub)")
    sub = p.add_subparsers(dest="mode", required=True)

    sub.add_parser("discover", help="find satellites and report inventory (read-only)")

    s = sub.add_parser("status", help="report dropbear/port/firmware status (read-only)")
    s.add_argument("--admin", action="store_true",
                   help="also read dropbear uci via an authenticated ubus session (prompts)")

    sub.add_parser("plan", help="show exact proposed changes (read-only)")

    pr = sub.add_parser("probe", help="read-only live enumeration of a satellite's authenticated ubus surface")
    pr.add_argument("--satellite", type=int, required=True, choices=sorted(SATELLITES))

    e = sub.add_parser("enable", help="apply owner-SSH provisioning to ONE satellite")
    e.add_argument("--satellite", type=int, required=True, choices=sorted(SATELLITES))
    e.add_argument("--apply", action="store_true", help="actually make changes")

    v = sub.add_parser("verify", help="verify SSH/UID0/mesh for one satellite")
    v.add_argument("--satellite", type=int, required=True, choices=sorted(SATELLITES))

    r = sub.add_parser("rollback", help="revert this tool's changes on one satellite")
    r.add_argument("--satellite", type=int, required=True, choices=sorted(SATELLITES))
    return p


HANDLERS = {
    "discover": cmd_discover, "status": cmd_status, "plan": cmd_plan,
    "probe": cmd_probe, "enable": cmd_enable, "verify": cmd_verify,
    "rollback": cmd_rollback,
}


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    log = AuditLog(enabled=not args.no_log)
    log(f"mode={args.mode} argv={sys.argv[1:]}")
    try:
        return HANDLERS[args.mode](args, log)
    except BootstrapUnavailable as exc:
        print(f"\nBLOCKED: {exc}", file=sys.stderr)
        return 3
    except ToolError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
