#!/usr/bin/env python3
"""
orbi_root_shell.py
==================

One command to go from "SSH disabled" to a root shell on the owner's
Netgear Orbi RBRE960, using the stock firmware's administrator-authenticated
enablement mechanism.

This is a thin ORCHESTRATION wrapper. All of the security-sensitive logic
(the verified POST /api/v1/enable_ssh contract, the SECLEVEL=1 TLS pin,
password shell-safety validation, the counter-safe probe) lives in
seal_dropbear_enable.py and is IMPORTED here, not duplicated.

Flow:
  1. Ensure an RSA key pair exists.
       This firmware ships an OLD Dropbear: it presents only an `ssh-rsa`
       host key and does NOT accept ed25519 *user* keys. RSA is required.
  2. Counter-safe reachability probe (confirms :443, the endpoint, and the
       certificate pin). Aborts cleanly if the router is refusing right now
       (e.g. a transient Router-Protection / anti-scan block) instead of
       burning an authentication attempt.
  3. Owner-authenticated enable: prompts for ENABLE confirmation and then the
       admin credentials (interactive, via getpass; never stored or logged).
  4. Connect:
       - Dropbear REGENERATES its host key every time it restarts (this
         firmware doesn't persist it), so the prior known_hosts entry is
         stale after every enable/reboot. We clear it, then accept-new.
       - Wait for TCP 22, verify `uid=0(root)`, then open an interactive shell.

What this changes on the device (and rollback):
    Writes YOUR public key to /etc/dropbear/authorized_keys and starts Dropbear
    (key-only root login) on TCP 22. Both the authorized_keys file and the
    /tmp attempt counter live on tmpfs, so a reboot fully reverts it; you can
    also remove the key or stop dropbear from the shell.

It does NOT bypass authentication, guess/brute-force, or exploit the firmware's
password-shell weakness. At most 5 failed admin attempts before the endpoint
locks out until reboot -- so enter the correct password.

Usage:
    python3 orbi_root_shell.py                 # enable (if needed) then shell
    python3 orbi_root_shell.py --connect-only  # skip enable, just connect
    python3 orbi_root_shell.py -c "id; uname -a"   # run a command, don't open a shell
    python3 orbi_root_shell.py --yes           # skip the ENABLE confirmation prompt
"""

from __future__ import annotations

import argparse
import shutil
import socket
import subprocess
import sys
from pathlib import Path

import seal_dropbear_enable as seal

# The router's self-signed TLS certificate SHA-256 fingerprint is device-specific
# and is NOT bundled here. Capture your own device's fingerprint and pass it with
# --pin-sha256 (see the capture command in RBRE960_ROOT_ACCESS_WRITEUP.md). The
# connection is pinned to exactly that certificate; there is no default.
DEFAULT_PIN = None

DEFAULT_KEY = Path("~/.ssh/orbi_rbre960_rsa").expanduser()

# Options every ssh/scp to this old Dropbear needs:
#   +ssh-rsa host key               -> the router offers only an RSA host key
#   +ssh-rsa pubkey algorithm       -> modern OpenSSH won't sign with ssh-rsa otherwise
#   accept-new                      -> auto-learn the freshly regenerated host key
#   IdentitiesOnly                  -> offer only our key, nothing from the agent
SSH_COMPAT_OPTS = [
    "-o", "HostKeyAlgorithms=+ssh-rsa",
    "-o", "PubkeyAcceptedAlgorithms=+ssh-rsa",
    "-o", "StrictHostKeyChecking=accept-new",
    "-o", "IdentitiesOnly=yes",
]


def info(msg: str) -> None:
    print(f"[*] {msg}")


def fail(msg: str, code: int = 1) -> "int":
    print(f"[!] {msg}", file=sys.stderr)
    return code


def ensure_rsa_key(priv: Path) -> Path:
    """Return the public-key path, generating an RSA key pair if missing."""
    pub = priv.with_suffix(priv.suffix + ".pub") if priv.suffix else Path(str(priv) + ".pub")
    if priv.exists() and pub.exists():
        info(f"Using existing key: {priv}")
        return pub
    if not shutil.which("ssh-keygen"):
        raise FileNotFoundError("ssh-keygen not found on PATH.")
    priv.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    info(f"Generating a new RSA key pair at {priv} (no passphrase, for lab use)...")
    subprocess.run(
        ["ssh-keygen", "-t", "rsa", "-b", "2048", "-N", "",
         "-f", str(priv), "-C", "orbi-rbre960-root"],
        check=True,
    )
    return pub


def port_open(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def wait_for_port(host: str, port: int, attempts: int = 10, delay: float = 1.5) -> bool:
    for i in range(attempts):
        if port_open(host, port, timeout=2.0):
            return True
        info(f"  waiting for TCP {port}... ({i + 1}/{attempts})")
        if i < attempts - 1:
            import time
            time.sleep(delay)
    return False


def clear_stale_host_key(host: str) -> None:
    """Dropbear regenerates its host key on every restart; drop the old entry."""
    if shutil.which("ssh-keygen"):
        subprocess.run(["ssh-keygen", "-R", host],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        info(f"Cleared any stale known_hosts entry for {host}.")


def ssh_base(priv: Path, host: str) -> list[str]:
    return ["ssh", "-i", str(priv), *SSH_COMPAT_OPTS, f"root@{host}"]


def verify_root(priv: Path, host: str) -> bool:
    """Run `id` non-interactively and confirm uid=0."""
    try:
        res = subprocess.run(
            ssh_base(priv, host) + ["id"],
            capture_output=True, text=True, timeout=20,
        )
    except subprocess.TimeoutExpired:
        print("[!] SSH timed out running `id`.", file=sys.stderr)
        return False
    out = (res.stdout + res.stderr).strip()
    if out:
        print("    " + out.replace("\n", "\n    "))
    return "uid=0" in res.stdout


def do_enable(host: str, pub_path: Path, pin: str, assume_yes: bool) -> bool:
    """Run the owner-authenticated enable via the imported, verified module."""
    cfg = seal.RouterConfig(address=host)

    info("Counter-safe reachability probe (no credentials)...")
    probe = seal.probe_reachability(cfg, pin_sha256=pin)
    if probe.outcome is not seal.Outcome.PROBE_REACHABLE:
        if probe.outcome is seal.Outcome.TRANSPORT_ERROR:
            fail("Router is not answering on :443 right now. This is usually the "
                 "transient Router-Protection/anti-scan block -- stop probing, wait "
                 "a few minutes, and retry. No attempt was used.")
        else:
            fail(f"Unexpected probe result: {probe.outcome.value} "
                 f"(HTTP {probe.status}). Aborting before sending credentials.")
        return False
    info("Endpoint reachable and certificate pin verified.")

    public_key = seal.load_public_key(pub_path)  # validates format + shell-safety

    print("\n  DEVICE CHANGE: install your public key into "
          "/etc/dropbear/authorized_keys and start Dropbear (key-only root) on TCP 22.")
    print("  Rollback: reboot the router, or remove the key / stop dropbear from the shell.")
    if not assume_yes:
        if input("  Type ENABLE to authorize: ").strip() != "ENABLE":
            fail("Not confirmed; nothing sent.")
            return False

    username, password = seal.collect_credentials()  # getpass; validates password
    result = seal.enable_ssh(cfg, username, password, public_key, pin_sha256=pin)

    if result.outcome is seal.Outcome.SUCCESS:
        info("Router returned HTTP 200 (request accepted).")
        return True
    if result.outcome is seal.Outcome.AUTH_FAILED_OR_RATELIMITED:
        fail("HTTP 418: wrong admin credentials OR the 5-attempt lockout was hit. "
             "Do NOT re-run blindly -- a reboot clears the counter.")
    else:
        fail(f"Enable did not succeed: {result.outcome.value} "
             f"(HTTP {result.status}) {result.detail}")
    return False


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Enable stock Dropbear SSH and open a root shell on the RBRE960.")
    ap.add_argument("--router", default="routerlogin.net")
    ap.add_argument("--key", type=Path, default=DEFAULT_KEY,
                    help="Private key path (its .pub is installed). RSA required for this firmware.")
    ap.add_argument("--pin-sha256", default=DEFAULT_PIN,
                    help="Your router's TLS certificate SHA-256 pin (hex). Required for the "
                         "enable step (not needed with --connect-only). Capture it with the "
                         "openssl command in RBRE960_ROOT_ACCESS_WRITEUP.md.")
    ap.add_argument("--connect-only", action="store_true",
                    help="Skip the enable step; just fix the host key and connect.")
    ap.add_argument("--yes", action="store_true",
                    help="Skip the interactive ENABLE confirmation (still prompts for credentials).")
    ap.add_argument("-c", "--command",
                    help="Run this command over SSH and exit, instead of opening an interactive shell.")
    args = ap.parse_args(argv)

    host = args.router
    priv = args.key.expanduser()

    print("RBRE960 root-shell helper")
    print("-------------------------")
    print(f"Router: {host}   Key: {priv}\n")

    try:
        pub_path = ensure_rsa_key(priv)
    except (FileNotFoundError, subprocess.CalledProcessError) as exc:
        return fail(str(exc))

    if not args.connect_only:
        if not args.pin_sha256:
            return fail("--pin-sha256 is required for the enable step (the router's TLS cert "
                        "is device-specific and not bundled). Capture your device's fingerprint "
                        "per RBRE960_ROOT_ACCESS_WRITEUP.md, or use --connect-only if SSH is up.")
        if not do_enable(host, pub_path, args.pin_sha256, args.yes):
            return 1

    clear_stale_host_key(host)

    info("Waiting for Dropbear on TCP 22...")
    if not wait_for_port(host, 22):
        return fail("TCP 22 never came up. HTTP 200 does not guarantee Dropbear "
                    "started; check the router, or re-run the enable.")

    info("Verifying root access (id)...")
    if not verify_root(priv, host):
        return fail("Connected to Dropbear but authentication/`id` did not confirm "
                    "uid=0. Re-run without --connect-only to reinstall the key, or "
                    "run `ssh -v` manually to see the rejection.")
    print("\n[+] Confirmed uid=0(root).")

    if args.command:
        info(f"Running: {args.command}")
        return subprocess.run(ssh_base(priv, host) + [args.command]).returncode

    print("[+] Opening interactive root shell (Ctrl-D / exit to leave)...\n")
    # Replace this process with ssh so the shell gets a real TTY.
    import os
    os.execvp("ssh", ssh_base(priv, host))
    return 0  # unreachable


if __name__ == "__main__":
    sys.exit(main())
