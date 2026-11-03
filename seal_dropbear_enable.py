#!/usr/bin/env python3
"""
seal_dropbear_enable.py
=======================

Netgear Orbi RBRE960
Seal REST / Dropbear owner-access utility.

Target:
    Router:       RBRE960
    Firmware:     V7.2.7.15_5.1.16
    Address:      routerlogin.net
    API handler:  POST /api/v1/enable_ssh      (VERIFIED, see below)
    SSH service:  Dropbear
    SSH user:     root

Purpose:
    Investigate and automate the stock firmware's
    administrator-authenticated SSH enablement mechanism.

API contract (VERIFIED by re-disassembling the on-disk Lua 5.1 bytecode
of www-seal/rest/rest.lua and usr/share/lua/seal-development.lua from the
running 7.2.7.15 image; the saved disassembly reproduces byte-for-byte):

    Method  : POST   (the route is registered POST-only; there is NO GET route)
    URL     : https://routerlogin.net/api/v1/enable_ssh
    Body    : JSON object, keys "username", "password", "pubkey"
              (parsed by rxi-json-lua decode of HTTP_CONTENT and merged into
               the request table; query-string params are NOT used by the
               handler, so the body must be JSON)
    Auth    : self-authenticating inside the handler via verify_admin();
              no separate web session / CSRF token in the handler path.

    Responses (CGI "Status:" line -> HTTP status; body printed after):
        200  "OK"                                     -> success
        418  "I'm a teapot"                           -> enable_ssh() returned
                                                         false: WRONG CREDENTIALS
                                                         *or* rate-limited
                                                         (ambiguous by design)
        400  "Bad Request - Message body is not valid JSON"
        500  "Server Error"                           -> handler raised

Rate limiter (VERIFIED, seal-development.lua):
    Counter file /tmp/enable-ssh-attempt-counter. enable_ssh() refuses once the
    counter is >= 5 (checked BEFORE credentials). The counter increments only on
    a FAILED verify_admin and is never reset on success and never time-decays; it
    is only cleared by removing the file or by a reboot (it lives on tmpfs).
    => At most 5 failed attempts before the endpoint locks out until reboot.
       Do not brute force. Use the correct admin credentials.

Security note (VERIFIED, not this client's bug but relevant):
    verify_admin() computes the password digest with
        run_shell("echo -n " .. password .. " | sha256sum | ...")
    i.e. the password is interpolated UNQUOTED into a device shell. A normal
    password is fine (it simply hashes); a password containing shell
    metacharacters would (a) likely fail to authenticate and (b) be a
    command-injection sink on the device. This utility is for the owner's own
    credentials only; it does not attempt injection.

TLS note (VERIFIED by runtime cert inspection):
    The device presents an RSA-1024 certificate (sha256WithRSAEncryption,
    CN=routerlogin.net, O=NetgearFieldDevices, valid 2024..2124). Fedora's
    system crypto policy (OpenSSL SECLEVEL=2) rejects it with
    "EE certificate key too weak" - a key-strength policy rejection, NOT a
    trust/hostname failure. Therefore a CA bundle alone does not make it verify.

    This client handles that WITHOUT weakening Fedora's global TLS policy, by
    building a per-connection ssl.SSLContext at SECLEVEL=1 (affects only that one
    socket) and anchoring trust narrowly:
      * --pin-sha256 <hex> : pin the server certificate's SHA-256 fingerprint.
        The connection is rejected unless the peer presents exactly that single
        certificate. Recommended for connecting by IP. This is leaf pinning, not
        PKI chain validation.
      * --ca-bundle <path> : place the router's certificate in the trust store.
        The captured router cert is a SELF-SIGNED LEAF (CA:FALSE, issuer==subject,
        RSA-1024, SAN routerlogin.net) - there is no separate CA. OpenSSL accepts
        it ONLY because the exact leaf is a trust anchor (trust-anchor pinning),
        and the SAN is still hostname-checked; this is NOT multi-cert CA-chain
        verification. Use with --router routerlogin.net so the hostname matches.
    Authenticated --enable ALWAYS verifies (one of the two above, or plain
    verify=True by default); it can never be downgraded to no-verification.

    The no-credential reachability probe may bypass verification with
    --insecure-probe (equivalent to curl -k). That flag applies to the probe
    ONLY and can never affect --enable.

The default mode performs NO network request. A request is only sent with
--enable, after an explicit typed confirmation, using credentials collected
interactively (never from argv or source).
"""

from __future__ import annotations

import argparse
import getpass
import logging
import ssl
import sys

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Literal

import requests
import requests.adapters


# ============================================================
# CONFIGURATION
# ============================================================

@dataclass(frozen=True)
class RouterConfig:
    address: str = "routerlogin.net"
    scheme: str = "https"
    timeout: float = 10.0

    @property
    def base_url(self) -> str:
        return f"{self.scheme}://{self.address}"


ROUTER = RouterConfig()

# VERIFIED against the extracted 7.2.7.15 firmware (rest.lua route table and
# body parser). These are no longer guesses.
API_PATH: str = "/api/v1/enable_ssh"
REQUEST_FORMAT: Literal["json"] = "json"

# Response contract (VERIFIED, rest.lua respond()).
HTTP_SUCCESS = 200
BODY_SUCCESS = "OK"
HTTP_TEAPOT = 418            # enable_ssh() false: bad creds OR rate-limited
BODY_TEAPOT = "I'm a teapot"
HTTP_BAD_REQUEST = 400       # body not valid JSON
HTTP_SERVER_ERROR = 500      # handler raised

# seal-development.lua rate-limit threshold (for user-facing warnings only).
MAX_FAILED_ATTEMPTS = 5


# ============================================================
# LOGGING
# ============================================================

logging.basicConfig(
    level=logging.INFO,
    format="[%(levelname)s] %(message)s",
)

log = logging.getLogger("RBRE960")


# ============================================================
# RESULT MODEL
# ============================================================

class Outcome(str, Enum):
    SUCCESS = "success"
    AUTH_FAILED_OR_RATELIMITED = "auth_failed_or_ratelimited"
    BAD_REQUEST = "bad_request"
    SERVER_ERROR = "server_error"
    UNEXPECTED = "unexpected"
    TRANSPORT_ERROR = "transport_error"
    # Probe-only: the expected 400-malformed-JSON reply. NOT an auth success and
    # does NOT mean the /enable_ssh handler ran.
    PROBE_REACHABLE = "probe_reachable"


@dataclass(frozen=True)
class EnableResult:
    outcome: Outcome
    status: int | None = None
    body: str = ""
    detail: str = ""

    @property
    def ok(self) -> bool:
        return self.outcome is Outcome.SUCCESS


def classify_response(status: int, body: str) -> EnableResult:
    """Map an HTTP (status, body) pair onto the verified handler contract.

    Success keys on HTTP 200 (authoritative); the "OK" body is treated as
    confirmation and a mismatch is surfaced rather than silently trusted.
    """
    normalized = body.strip()

    if status == HTTP_SUCCESS:
        if normalized != BODY_SUCCESS:
            return EnableResult(
                Outcome.UNEXPECTED, status, body,
                f"HTTP 200 but body was {normalized!r}, expected {BODY_SUCCESS!r}.",
            )
        return EnableResult(
            Outcome.SUCCESS, status, body,
            "Router accepted the request (HTTP 200 OK): verify_admin passed and "
            "the handler ran. NOTE: enable_ssh() returns true even if the dropbear "
            "command itself failed (the handler only prints per-command errors), so "
            "a 200 does NOT by itself prove Dropbear is listening, the key was "
            "installed, or TCP 22 is open. Verify those separately.",
        )

    if status == HTTP_TEAPOT:
        return EnableResult(
            Outcome.AUTH_FAILED_OR_RATELIMITED, status, body,
            "Handler returned false: wrong admin username/password, OR the "
            f"/tmp attempt counter has reached {MAX_FAILED_ATTEMPTS} "
            "(lockout until the router is rebooted). These are indistinguishable "
            "from the response alone.",
        )

    if status == HTTP_BAD_REQUEST:
        return EnableResult(
            Outcome.BAD_REQUEST, status, body,
            "Router rejected the body as invalid JSON before authentication.",
        )

    if status == HTTP_SERVER_ERROR:
        return EnableResult(
            Outcome.SERVER_ERROR, status, body,
            "Handler raised on the device (500 Server Error).",
        )

    return EnableResult(
        Outcome.UNEXPECTED, status, body,
        f"Unexpected HTTP {status}. A 404 typically means the route/method or "
        "URL prefix is wrong for this firmware build.",
    )


# Body substring the firmware returns for a malformed JSON body (VERIFIED,
# rest.lua), used to confirm the *expected* probe result rather than any 400.
PROBE_EXPECTED_BODY_SUBSTR = "not valid json"


def classify_probe_response(status: int, body: str) -> EnableResult:
    """Classify the NO-CREDENTIAL reachability probe's response.

    This is deliberately NOT classify_response(): the probe submits no
    credentials and an invalid JSON body, which the firmware rejects *before*
    route dispatch and before verify_admin(). Therefore:
      * the ONLY expected/healthy result is HTTP 400 carrying the malformed-JSON
        message -> Outcome.PROBE_REACHABLE;
      * every other status (200, 418, 404, 500, ...) is Outcome.UNEXPECTED;
      * this function NEVER returns SUCCESS and never claims authentication
        succeeded or that the /enable_ssh handler executed.
    Transport errors are handled by the caller (kept distinct from HTTP results).
    """
    if status == HTTP_BAD_REQUEST and PROBE_EXPECTED_BODY_SUBSTR in body.lower():
        return EnableResult(
            Outcome.PROBE_REACHABLE, status, body,
            "Expected probe result: the Seal REST JSON layer is reachable and "
            "rejected the malformed body before authentication. No credentials "
            "were sent and the /enable_ssh handler did not run. (Route "
            "registration is established by static analysis, not by this probe.)",
        )

    return EnableResult(
        Outcome.UNEXPECTED, status, body,
        f"Unexpected probe response (HTTP {status}). The probe sends no "
        "credentials and an invalid body, so this is NOT success and does NOT "
        "indicate the /enable_ssh handler ran or that authentication occurred; "
        f"only HTTP {HTTP_BAD_REQUEST} with the malformed-JSON message is expected.",
    )


# ============================================================
# SSH PUBLIC KEY HANDLING
# ============================================================

def validate_public_key(key: str) -> str:
    """Validate an SSH public key and reject anything unsafe for the handler.

    The device handler writes the key with:
        /bin/echo '<pubkey>' > /etc/dropbear/authorized_keys
    so a single quote or newline in the key would break out of that shell
    quoting. A well-formed public key never contains either; reject them.
    """
    key = key.strip()
    parts = key.split()

    if len(parts) < 2:
        raise ValueError("Invalid SSH public key format (expected 'type base64 [comment]').")

    if not parts[0].startswith(("ssh-", "ecdsa-", "sk-")):
        raise ValueError(f"Unsupported SSH public key type: {parts[0]!r}")

    if "'" in key or "\n" in key or "\r" in key:
        raise ValueError(
            "Public key contains a quote or newline; refusing to send "
            "(would corrupt the device-side authorized_keys write)."
        )

    return key


def load_public_key(path: Path) -> str:
    """Read and validate the owner's SSH public key. The private key is never read."""
    if not path.is_file():
        raise FileNotFoundError(f"Public key not found: {path}")

    key = validate_public_key(path.read_text(encoding="utf-8"))
    log.info("SSH public key loaded and validated.")
    return key


# ============================================================
# ADMINISTRATIVE AUTHENTICATION
# ============================================================

# Characters the firmware would mishandle: verify_admin() builds
#   run_shell("echo -n " .. password .. " | sha256sum | ...")
# and run_shell() passes that string to io.popen() => /bin/sh -c. The password
# is NOT quoted or escaped. We therefore REJECT (never transform/escape) any
# password containing whitespace, shell metacharacters, glob/brace/tilde
# characters, or non-printable / non-ASCII bytes, all of which would alter the
# command (and several of which are an injection vector). A clear error is
# raised before any socket is opened. We never construct an injection payload.
_PASSWORD_UNSAFE_CHARS = set(" \t\r\n\"'`$&;|<>()[]{}*?~\\#")


def validate_password_safe(password: str) -> None:
    """Reject a password that cannot be sent safely to the firmware's shell.

    Raises ValueError (without echoing the password) for empty input or any
    disallowed character. Does not modify the password in any way.
    """
    if not password:
        raise ValueError("Password cannot be empty.")

    categories = set()
    for ch in password:
        o = ord(ch)
        if o < 0x20 or o == 0x7F:
            categories.add("control characters")
        elif o > 0x7F:
            categories.add("non-ASCII characters")
        elif ch == " " or ch in "\t\r\n":
            categories.add("whitespace")
        elif ch in _PASSWORD_UNSAFE_CHARS:
            categories.add("shell metacharacters")

    if categories:
        raise ValueError(
            "Password contains " + ", ".join(sorted(categories)) + ". This tool "
            "refuses to transmit such a password because the device inserts it "
            "UNQUOTED into a /bin/sh command (firmware weakness), where these "
            "characters would corrupt the request or act as a command-injection "
            "vector. Use the router's own admin credentials without these "
            "characters, or change the admin password. (The password was not "
            "logged or modified.)"
        )


def collect_credentials() -> tuple[str, str]:
    """Collect administrator credentials interactively.

    No credentials are stored in source code or command-line arguments.
    """
    username = input("Router administrator username: ").strip()
    if not username:
        raise ValueError("Username cannot be empty.")

    password = getpass.getpass("Router administrator password: ")
    validate_password_safe(password)

    return username, password


# ============================================================
# API REQUEST CONSTRUCTION
# ============================================================

def build_payload(username: str, password: str, public_key: str) -> dict[str, str]:
    """Body keys taken from the decompiled handler: req.username/password/pubkey."""
    return {
        "username": username,
        "password": password,
        "pubkey": public_key,
    }


# ============================================================
# SEAL REST COMMUNICATION
# ============================================================

def _new_session() -> requests.Session:
    session = requests.Session()
    # Avoid unexpected environment-configured HTTP proxies.
    session.trust_env = False
    return session


def normalize_fingerprint(fp: str) -> str:
    """Normalize a SHA-256 fingerprint: strip ':'/whitespace, lowercase, validate."""
    cleaned = fp.replace(":", "").replace(" ", "").strip().lower()
    if len(cleaned) != 64 or any(c not in "0123456789abcdef" for c in cleaned):
        raise ValueError("--pin-sha256 must be a 64-hex-character SHA-256 fingerprint.")
    return cleaned


def _seclevel1_context(cafile: str | None, verify: bool) -> ssl.SSLContext:
    """A per-connection SSLContext that tolerates the router's weak (1024-bit) key.

    SECLEVEL=1 is set on THIS context only; Fedora's system-wide crypto policy
    is untouched. When verify is True the context requires and checks the
    certificate (and hostname); when False it is unverified and relies on a
    fingerprint pin applied by the adapter.
    """
    if verify:
        ctx = ssl.create_default_context(cafile=cafile)
    else:
        ctx = ssl._create_unverified_context()  # CERT_NONE, check_hostname False
    try:
        ctx.set_ciphers("DEFAULT@SECLEVEL=1")
    except ssl.SSLError:  # pragma: no cover - platform dependent
        pass
    return ctx


class _SSLContextAdapter(requests.adapters.HTTPAdapter):
    """Mounts a specific SSLContext (and optional fingerprint pin) on a session.

    max_retries is left at 0 (requests default) - no automatic retries.
    """

    def __init__(
        self,
        ssl_context: ssl.SSLContext,
        assert_fingerprint: str | None = None,
        ca_bundle: str | None = None,
    ):
        self._ssl_context = ssl_context
        self.assert_fingerprint = assert_fingerprint
        self.ca_bundle = ca_bundle
        super().__init__(max_retries=0)

    def _augment(self, pool_kwargs: dict) -> dict:
        pool_kwargs["ssl_context"] = self._ssl_context
        if self.assert_fingerprint:
            pool_kwargs["assert_fingerprint"] = self.assert_fingerprint
        return pool_kwargs

    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        return super().init_poolmanager(
            connections, maxsize, block=block, **self._augment(pool_kwargs)
        )

    def proxy_manager_for(self, proxy, **proxy_kwargs):
        return super().proxy_manager_for(proxy, **self._augment(proxy_kwargs))


@dataclass(frozen=True)
class TlsPolicy:
    """Resolved TLS behavior for one request.

    verify           : value passed to requests' `verify=` kwarg.
    ca_bundle        : CA/pinned cert file, if any.
    pin_sha256       : server-cert SHA-256 pin, if any.
    weak_key_ok      : mount a SECLEVEL=1 adapter so the 1024-bit cert is accepted.
    """
    verify: bool | str
    ca_bundle: str | None = None
    pin_sha256: str | None = None
    weak_key_ok: bool = False

    @property
    def verifies_certificate(self) -> bool:
        """True iff the peer certificate is cryptographically checked."""
        return bool(self.pin_sha256) or self.verify is not False


def enable_tls_policy(ca_bundle: str | None, pin_sha256: str | None) -> TlsPolicy:
    """TLS for AUTHENTICATED operations - always verifies; never insecure.

    --insecure-probe deliberately has no influence here.
    """
    if pin_sha256:
        # Trust anchored by the certificate fingerprint; chain/hostname not needed.
        return TlsPolicy(verify=False, pin_sha256=normalize_fingerprint(pin_sha256),
                         weak_key_ok=True)
    if ca_bundle:
        # The router cert is a SELF-SIGNED LEAF (CA:FALSE, issuer==subject), so
        # this is NOT a normal multi-cert CA-chain validation: OpenSSL accepts it
        # only because the exact leaf is placed in the trust store (trust-anchor
        # pinning), and the SAN (routerlogin.net) is still hostname-checked. Use
        # --router routerlogin.net so the hostname matches.
        return TlsPolicy(verify=True, ca_bundle=ca_bundle, weak_key_ok=True)
    # Secure default. Against the weak cert this fails with "key too weak";
    # the caller surfaces guidance to use --pin-sha256 or --ca-bundle.
    return TlsPolicy(verify=True)


def probe_tls_policy(
    ca_bundle: str | None, pin_sha256: str | None, insecure_probe: bool
) -> TlsPolicy:
    """TLS for the NO-CREDENTIAL probe only. --insecure-probe may disable verify."""
    if insecure_probe:
        log.warning(
            "Probe TLS verification DISABLED (--insecure-probe). This affects the "
            "no-credential reachability probe ONLY; --enable always verifies."
        )
        return TlsPolicy(verify=False)
    return enable_tls_policy(ca_bundle, pin_sha256)


def _apply_tls(session: requests.Session, policy: TlsPolicy) -> None:
    """Mount the SECLEVEL=1 pinning/CA adapter when needed.

    No-op when the policy needs no special context, or when the session does not
    support mounting (e.g. a test double).
    """
    if not policy.weak_key_ok or not hasattr(session, "mount"):
        return
    ctx = _seclevel1_context(cafile=policy.ca_bundle, verify=policy.verify is not False)
    session.mount("https://", _SSLContextAdapter(
        ctx, assert_fingerprint=policy.pin_sha256, ca_bundle=policy.ca_bundle,
    ))


def enable_ssh(
    config: RouterConfig,
    username: str,
    password: str,
    public_key: str,
    ca_bundle: str | None = None,
    pin_sha256: str | None = None,
) -> EnableResult:
    """Submit the owner-authenticated SSH enablement request.

    Always certificate-verified (via --pin-sha256, --ca-bundle, or plain
    verify=True). There is deliberately no insecure path here. No automatic
    retries. HTTP redirects are disabled so credentials are never re-sent to a
    redirected URL (HTTP->HTTPS is a 308 on this device).

    The password is validated for shell safety BEFORE any socket is opened; an
    unsafe password raises ValueError and nothing is sent.
    """
    # Fail closed before any network activity if the password is shell-unsafe.
    validate_password_safe(password)

    url = config.base_url + API_PATH
    payload = build_payload(username, password, public_key)
    policy = enable_tls_policy(ca_bundle, pin_sha256)

    session = _new_session()
    _apply_tls(session, policy)
    try:
        log.info(
            "Submitting authenticated administrative request (POST %s, cert "
            "verification: %s).", API_PATH, "on" if policy.verifies_certificate else "off",
        )
        response = session.post(
            url,
            json=payload,
            timeout=(5, config.timeout),
            verify=policy.verify,
            allow_redirects=False,
        )

        log.info("Router returned HTTP %s", response.status_code)
        result = classify_response(response.status_code, response.text)

        if result.ok:
            log.info("Request accepted (HTTP 200). %s", result.detail)
        else:
            log.error("Enablement not confirmed (%s): %s", result.outcome.value, result.detail)
        return result

    except requests.RequestException as exc:
        log.error("HTTP communication failed: %s", exc)
        return EnableResult(Outcome.TRANSPORT_ERROR, None, "", str(exc))
    finally:
        session.close()


def probe_reachability(
    config: RouterConfig,
    ca_bundle: str | None = None,
    pin_sha256: str | None = None,
    insecure_probe: bool = False,
) -> EnableResult:
    """Counter-safe reachability probe.

    Sends a POST with a DELIBERATELY invalid JSON body. The device rejects
    invalid JSON with HTTP 400 *before* the route handler and therefore before
    verify_admin() - so this does NOT touch the attempt counter and enables
    nothing. A 400 confirms the Seal REST JSON layer is reachable over POST on
    this URL; it is NOT by itself proof of the /enable_ssh route (any API path
    returns 400 on bad JSON - route registration is established by static
    analysis). It never sends credentials or a key.

    This is the only path that may run with TLS verification disabled, via
    --insecure-probe.
    """
    url = config.base_url + API_PATH
    policy = probe_tls_policy(ca_bundle, pin_sha256, insecure_probe)

    session = _new_session()
    _apply_tls(session, policy)
    try:
        log.info(
            "Probing reachability with an invalid body (counter-safe; cert "
            "verification: %s).", "on" if policy.verifies_certificate else "off",
        )
        response = session.post(
            url,
            data=b"{ this is not json",
            headers={"Content-Type": "application/json"},
            timeout=(5, config.timeout),
            verify=policy.verify,
            allow_redirects=False,
        )
        log.info("Router returned HTTP %s", response.status_code)
        return classify_probe_response(response.status_code, response.text)
    except requests.RequestException as exc:
        log.error("HTTP communication failed: %s", exc)
        return EnableResult(Outcome.TRANSPORT_ERROR, None, "", str(exc))
    finally:
        session.close()


# ============================================================
# COMMAND LINE INTERFACE
# ============================================================

def parse_arguments(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="RBRE960 Seal REST / Dropbear owner-access utility"
    )
    parser.add_argument("--router", default="routerlogin.net")
    parser.add_argument(
        "--public-key",
        type=Path,
        default=Path("~/.ssh/orbi_rbre960.pub").expanduser(),
    )
    parser.add_argument(
        "--ca-bundle",
        help="Trusted CA / pinned router certificate. For --enable, use together "
             "with --router routerlogin.net so the hostname matches.",
    )
    parser.add_argument(
        "--pin-sha256",
        help="Pin the server certificate's SHA-256 fingerprint (hex, colons "
             "optional). Recommended for authenticated connections by IP.",
    )
    parser.add_argument(
        "--insecure-probe",
        action="store_true",
        help="Disable TLS verification for the --probe reachability check ONLY "
             "(like curl -k). Has no effect on --enable, which always verifies.",
    )
    parser.add_argument(
        "--probe",
        action="store_true",
        help="Counter-safe reachability probe (invalid body -> HTTP 400). "
             "Sends no credentials and enables nothing.",
    )
    parser.add_argument(
        "--enable",
        action="store_true",
        help="Explicitly request the SSH enablement operation (device change).",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_arguments(argv)
    config = RouterConfig(address=args.router)

    print("\nRBRE960 Seal / Dropbear Research Utility")
    print("----------------------------------------")
    print(f"Router: {config.base_url}")
    print(f"Endpoint: POST {API_PATH}  (body: {REQUEST_FORMAT})")
    print(f"Public key: {args.public_key}")

    if args.probe and args.enable:
        log.error("Choose either --probe or --enable, not both.")
        return 2

    if args.probe:
        print("\nREACHABILITY PROBE (counter-safe, no credentials)")
        result = probe_reachability(
            config, args.ca_bundle, args.pin_sha256, args.insecure_probe
        )
        print(f"Outcome: {result.outcome.value} (HTTP {result.status}) - {result.detail}")
        # PROBE_REACHABLE (the expected 400 malformed-JSON reply) is the only
        # healthy result; anything else (incl. HTTP 200) is not success.
        return 0 if result.outcome is Outcome.PROBE_REACHABLE else 1

    if not args.enable:
        print("\nREAD-ONLY MODE")
        print("No router requests or modifications performed.")
        print("Use --probe for a counter-safe reachability check, or --enable to act.")
        return 0

    try:
        public_key = load_public_key(args.public_key)

        print("\nDEVICE-CHANGING OPERATION")
        print("This installs your SSH public key into /etc/dropbear/authorized_keys")
        print("and starts Dropbear (key-only root login) on TCP 22.")
        print(f"NOTE: at most {MAX_FAILED_ATTEMPTS} failed attempts before the")
        print("endpoint locks out until the router reboots. Use correct credentials.")

        confirmation = input("\nType ENABLE to authorize this operation: ")
        if confirmation != "ENABLE":
            log.info("Operation cancelled.")
            return 1

        # NOTE: args.insecure_probe is deliberately NOT passed here; --enable
        # always verifies the certificate.
        username, password = collect_credentials()
        result = enable_ssh(
            config, username, password, public_key, args.ca_bundle, args.pin_sha256
        )

        if result.ok:
            print("\nRouter returned HTTP 200 OK (request accepted).")
            print("This does NOT confirm Dropbear is running. Verify, then connect:")
            print(f"  nc -z -w3 {args.router} 22        # is TCP 22 open?")
            print(f"  ssh -i <your_private_key> root@{args.router}")
        return 0 if result.ok else 1

    except (ValueError, FileNotFoundError) as exc:
        log.error("%s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
