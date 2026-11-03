#!/usr/bin/env python3
"""
Unit tests for seal_dropbear_enable.py

All HTTP is mocked; these tests never contact the router. They lock the client
to the VERIFIED firmware contract:
    POST https://routerlogin.net/api/v1/enable_ssh
    JSON body {username, password, pubkey}
    200 "OK" | 418 "I'm a teapot" | 400 bad-json | 500 server-error

Run:
    python3 -m unittest test_seal_dropbear_enable -v
"""
from __future__ import annotations

import hashlib
import http.server
import io
import logging
import os
import shutil
import ssl
import subprocess
import tempfile
import threading
import unittest
from unittest import mock

import requests

import seal_dropbear_enable as sde


VALID_ED25519 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIabcdef0123456789 owner@workstation"
VALID_RSA = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDexample owner@workstation"


class FakeResponse:
    def __init__(self, status_code: int, text: str):
        self.status_code = status_code
        self.text = text


class FakeSession:
    """Records the single .post() call and returns a preloaded response/exception."""

    def __init__(self, response=None, exc=None):
        self._response = response
        self._exc = exc
        self.trust_env = True
        self.post_calls: list[tuple[tuple, dict]] = []
        self.mounts: dict[str, object] = {}
        self.closed = False

    def post(self, *args, **kwargs):
        self.post_calls.append((args, kwargs))
        if self._exc is not None:
            raise self._exc
        return self._response

    def mount(self, prefix, adapter):
        self.mounts[prefix] = adapter

    def close(self):
        self.closed = True

    # convenience accessors for assertions
    @property
    def last_verify(self):
        return self.post_calls[-1][1]["verify"]

    @property
    def https_adapter(self):
        return self.mounts.get("https://")


def patch_session(session: FakeSession):
    return mock.patch.object(sde, "_new_session", return_value=session)


# ----------------------------------------------------------------------
# Contract constants
# ----------------------------------------------------------------------

class TestContractConstants(unittest.TestCase):
    def test_path_and_format(self):
        self.assertEqual(sde.API_PATH, "/api/v1/enable_ssh")
        self.assertEqual(sde.REQUEST_FORMAT, "json")

    def test_status_codes(self):
        self.assertEqual(sde.HTTP_SUCCESS, 200)
        self.assertEqual(sde.HTTP_TEAPOT, 418)
        self.assertEqual(sde.HTTP_BAD_REQUEST, 400)
        self.assertEqual(sde.HTTP_SERVER_ERROR, 500)
        self.assertEqual(sde.MAX_FAILED_ATTEMPTS, 5)


# ----------------------------------------------------------------------
# Payload / key handling
# ----------------------------------------------------------------------

class TestPayload(unittest.TestCase):
    def test_build_payload_keys(self):
        payload = sde.build_payload("admin", "secret", VALID_ED25519)
        self.assertEqual(set(payload), {"username", "password", "pubkey"})
        self.assertEqual(payload["username"], "admin")
        self.assertEqual(payload["password"], "secret")
        self.assertEqual(payload["pubkey"], VALID_ED25519)


class TestPublicKeyValidation(unittest.TestCase):
    def test_accepts_ed25519_and_rsa(self):
        self.assertEqual(sde.validate_public_key(VALID_ED25519), VALID_ED25519)
        self.assertEqual(sde.validate_public_key(VALID_RSA), VALID_RSA)

    def test_strips_whitespace(self):
        self.assertEqual(sde.validate_public_key(f"  {VALID_RSA}\n"), VALID_RSA)

    def test_rejects_unsupported_type(self):
        with self.assertRaises(ValueError):
            sde.validate_public_key("rsa-sha2 AAAA comment")

    def test_rejects_too_short(self):
        with self.assertRaises(ValueError):
            sde.validate_public_key("ssh-rsa")

    def test_rejects_single_quote(self):
        # Would break the device-side  /bin/echo '<pubkey>' > authorized_keys
        with self.assertRaises(ValueError):
            sde.validate_public_key("ssh-rsa AAAA'; reboot; '")

    def test_rejects_embedded_newline(self):
        with self.assertRaises(ValueError):
            sde.validate_public_key("ssh-rsa AAAA\nssh-rsa BBBB")


# ----------------------------------------------------------------------
# Response classification
# ----------------------------------------------------------------------

class TestClassify(unittest.TestCase):
    def test_200_ok_is_success(self):
        r = sde.classify_response(200, "OK\n")
        self.assertIs(r.outcome, sde.Outcome.SUCCESS)
        self.assertTrue(r.ok)

    def test_200_wrong_body_is_unexpected(self):
        r = sde.classify_response(200, "weird")
        self.assertIs(r.outcome, sde.Outcome.UNEXPECTED)
        self.assertFalse(r.ok)

    def test_418_is_auth_or_ratelimit(self):
        r = sde.classify_response(418, "I'm a teapot\n")
        self.assertIs(r.outcome, sde.Outcome.AUTH_FAILED_OR_RATELIMITED)
        self.assertFalse(r.ok)

    def test_400_is_bad_request(self):
        r = sde.classify_response(400, "Bad Request - Message body is not valid JSON")
        self.assertIs(r.outcome, sde.Outcome.BAD_REQUEST)

    def test_500_is_server_error(self):
        r = sde.classify_response(500, "Server Error")
        self.assertIs(r.outcome, sde.Outcome.SERVER_ERROR)

    def test_404_is_unexpected(self):
        r = sde.classify_response(404, "not found")
        self.assertIs(r.outcome, sde.Outcome.UNEXPECTED)

    def test_308_redirect_is_unexpected(self):
        # http->https 308 with redirects disabled must not be read as success.
        r = sde.classify_response(308, "")
        self.assertIs(r.outcome, sde.Outcome.UNEXPECTED)
        self.assertFalse(r.ok)

    def test_success_detail_does_not_claim_dropbear_running(self):
        r = sde.classify_response(200, "OK")
        self.assertTrue(r.ok)
        low = r.detail.lower()
        self.assertIn("does not", low)
        self.assertIn("dropbear", low)


class TestFingerprintNormalization(unittest.TestCase):
    def test_strips_colons_and_lowercases(self):
        fp = ":".join(["AB"] * 32)  # 64 hex chars with colons
        self.assertEqual(sde.normalize_fingerprint(fp), "ab" * 32)

    def test_rejects_wrong_length(self):
        with self.assertRaises(ValueError):
            sde.normalize_fingerprint("deadbeef")

    def test_rejects_non_hex(self):
        with self.assertRaises(ValueError):
            sde.normalize_fingerprint("z" * 64)


class TestTlsPolicy(unittest.TestCase):
    def test_enable_default_verifies(self):
        p = sde.enable_tls_policy(None, None)
        self.assertIs(p.verify, True)
        self.assertFalse(p.weak_key_ok)
        self.assertTrue(p.verifies_certificate)

    def test_enable_ca_bundle_verifies_and_tolerates_weak_key(self):
        p = sde.enable_tls_policy("/tmp/router.pem", None)
        self.assertIs(p.verify, True)
        self.assertEqual(p.ca_bundle, "/tmp/router.pem")
        self.assertTrue(p.weak_key_ok)
        self.assertTrue(p.verifies_certificate)

    def test_enable_pin_anchors_trust_by_fingerprint(self):
        p = sde.enable_tls_policy(None, "AB:" + ":".join(["CD"] * 31))
        self.assertIs(p.verify, False)          # requests-level verify off...
        self.assertTrue(p.verifies_certificate)  # ...but cert IS checked (pinned)
        self.assertIsNotNone(p.pin_sha256)
        self.assertEqual(len(p.pin_sha256 or ""), 64)
        self.assertTrue(p.weak_key_ok)

    def test_probe_insecure_disables_verification(self):
        p = sde.probe_tls_policy(None, None, insecure_probe=True)
        self.assertIs(p.verify, False)
        self.assertFalse(p.verifies_certificate)

    def test_probe_without_insecure_matches_enable_policy(self):
        self.assertEqual(
            sde.probe_tls_policy("/tmp/router.pem", None, insecure_probe=False),
            sde.enable_tls_policy("/tmp/router.pem", None),
        )

    def test_enable_policy_ignores_insecure_probe_concept(self):
        # enable_tls_policy has no insecure parameter at all: there is no way to
        # make an authenticated request skip verification.
        import inspect
        params = inspect.signature(sde.enable_tls_policy).parameters
        self.assertNotIn("insecure", params)
        self.assertNotIn("insecure_probe", params)


# ----------------------------------------------------------------------
# enable_ssh() over a mocked session
# ----------------------------------------------------------------------

class TestEnableSsh(unittest.TestCase):
    def setUp(self):
        self.config = sde.RouterConfig(address="routerlogin.net")

    def _run(self, session):
        with patch_session(session):
            return sde.enable_ssh(self.config, "admin", "pw", VALID_ED25519)

    def test_success(self):
        session = FakeSession(FakeResponse(200, "OK\n"))
        result = self._run(session)
        self.assertTrue(result.ok)
        self.assertIs(result.outcome, sde.Outcome.SUCCESS)
        self.assertTrue(session.closed)

    def test_teapot_failure(self):
        session = FakeSession(FakeResponse(418, "I'm a teapot\n"))
        result = self._run(session)
        self.assertFalse(result.ok)
        self.assertIs(result.outcome, sde.Outcome.AUTH_FAILED_OR_RATELIMITED)

    def test_transport_error(self):
        session = FakeSession(exc=requests.ConnectionError("no route"))
        result = self._run(session)
        self.assertIs(result.outcome, sde.Outcome.TRANSPORT_ERROR)
        self.assertTrue(session.closed)

    def test_request_shape_is_verified_contract(self):
        session = FakeSession(FakeResponse(200, "OK"))
        self._run(session)
        self.assertEqual(len(session.post_calls), 1)
        args, kwargs = session.post_calls[0]
        # URL
        self.assertEqual(args[0], "https://routerlogin.net/api/v1/enable_ssh")
        # JSON body (not form), exact keys
        self.assertIn("json", kwargs)
        self.assertNotIn("data", kwargs)
        self.assertEqual(
            kwargs["json"],
            {"username": "admin", "password": "pw", "pubkey": VALID_ED25519},
        )
        # Redirects disabled; TLS verified; connect/read timeout tuple
        self.assertFalse(kwargs["allow_redirects"])
        self.assertEqual(kwargs["verify"], True)
        self.assertEqual(kwargs["timeout"], (5, self.config.timeout))

    def test_default_enable_verifies_certificate(self):
        # Required: --enable uses certificate verification by default.
        session = FakeSession(FakeResponse(200, "OK"))
        self._run(session)
        self.assertIs(session.last_verify, True)
        self.assertIsNone(session.https_adapter)  # no weak-key adapter needed

    def test_ca_bundle_mounts_seclevel_adapter_and_verifies(self):
        # Required (Priority 2): CA bundle is supplied to a mounted adapter,
        # verification stays on, SECLEVEL is applied to the custom context only,
        # and the test depends on no pre-existing files (it mocks the context
        # builder - but does NOT skip the adapter initialization it verifies).
        sentinel_ctx = mock.MagicMock(name="ssl_context")
        session = FakeSession(FakeResponse(200, "OK"))
        with patch_session(session), \
             mock.patch.object(sde, "_seclevel1_context", return_value=sentinel_ctx) as ctxf:
            sde.enable_ssh(self.config, "admin", "pw", VALID_ED25519, ca_bundle="/tmp/router.pem")
        # Verification remains enabled at the requests level.
        self.assertIs(session.last_verify, True)
        # The HTTPS adapter was actually mounted (initialization not skipped).
        adapter = session.https_adapter
        self.assertIsInstance(adapter, sde._SSLContextAdapter)
        self.assertEqual(adapter.ca_bundle, "/tmp/router.pem")
        self.assertIsNone(adapter.assert_fingerprint)
        # SECLEVEL relaxation is confined to this one custom context: the builder
        # was called with the bundle + verify=True, and that very context object
        # is what the adapter carries (not any global/default context).
        ctxf.assert_called_once_with(cafile="/tmp/router.pem", verify=True)
        self.assertIs(adapter._ssl_context, sentinel_ctx)

    def test_pin_sha256_anchors_by_fingerprint(self):
        session = FakeSession(FakeResponse(200, "OK"))
        pin = ":".join(["AB"] * 32)
        with patch_session(session):
            sde.enable_ssh(self.config, "admin", "pw", VALID_ED25519, pin_sha256=pin)
        adapter = session.https_adapter
        self.assertIsInstance(adapter, sde._SSLContextAdapter)
        self.assertEqual(adapter.assert_fingerprint, "ab" * 32)
        # verify kwarg is False, but trust is anchored by the fingerprint pin.
        self.assertIs(session.last_verify, False)

    def test_enable_has_no_insecure_parameter(self):
        # Required: enable can never inherit an insecure/probe-bypass setting.
        import inspect
        params = inspect.signature(sde.enable_ssh).parameters
        self.assertNotIn("insecure", params)
        self.assertNotIn("insecure_probe", params)

    def test_bad_request_outcome(self):
        session = FakeSession(FakeResponse(400, "Bad Request - Message body is not valid JSON"))
        result = self._run(session)
        self.assertIs(result.outcome, sde.Outcome.BAD_REQUEST)

    def test_server_error_outcome(self):
        session = FakeSession(FakeResponse(500, "Server Error"))
        result = self._run(session)
        self.assertIs(result.outcome, sde.Outcome.SERVER_ERROR)

    def test_200_wrong_body_is_unexpected_end_to_end(self):
        session = FakeSession(FakeResponse(200, "something else"))
        result = self._run(session)
        self.assertIs(result.outcome, sde.Outcome.UNEXPECTED)
        self.assertFalse(result.ok)

    def test_password_not_logged(self):
        buf = io.StringIO()
        handler = logging.StreamHandler(buf)
        sde.log.addHandler(handler)
        try:
            session = FakeSession(FakeResponse(418, "I'm a teapot"))
            with patch_session(session):
                sde.enable_ssh(self.config, "admin", "SuperSecret123!", VALID_ED25519)
        finally:
            sde.log.removeHandler(handler)
        self.assertNotIn("SuperSecret123!", buf.getvalue())


# ----------------------------------------------------------------------
# probe_reachability() - counter-safe, sends no secrets
# ----------------------------------------------------------------------

class TestProbe(unittest.TestCase):
    def setUp(self):
        self.config = sde.RouterConfig(address="routerlogin.net")

    def test_probe_sends_invalid_body_and_no_credentials(self):
        session = FakeSession(FakeResponse(400, "Bad Request - Message body is not valid JSON"))
        with patch_session(session):
            result = sde.probe_reachability(self.config)
        self.assertIs(result.outcome, sde.Outcome.PROBE_REACHABLE)
        self.assertIsNot(result.outcome, sde.Outcome.SUCCESS)

        args, kwargs = session.post_calls[0]
        self.assertEqual(args[0], "https://routerlogin.net/api/v1/enable_ssh")
        # Must NOT use the json= encoder (that would produce valid JSON).
        self.assertNotIn("json", kwargs)
        self.assertIn("data", kwargs)
        # No credential/key material anywhere in the call.
        blob = repr((args, kwargs))
        for secret in ("password", "pubkey", "admin", "ssh-ed25519", "ssh-rsa"):
            self.assertNotIn(secret, blob)
        self.assertFalse(kwargs["allow_redirects"])

    def test_probe_non_400_reports_failure_outcome(self):
        session = FakeSession(FakeResponse(404, "not found"))
        with patch_session(session):
            result = sde.probe_reachability(self.config)
        self.assertIs(result.outcome, sde.Outcome.UNEXPECTED)

    def test_probe_transport_error(self):
        session = FakeSession(exc=requests.ConnectTimeout("timeout"))
        with patch_session(session):
            result = sde.probe_reachability(self.config)
        self.assertIs(result.outcome, sde.Outcome.TRANSPORT_ERROR)

    def test_probe_insecure_uses_verify_false(self):
        # Required: --insecure-probe disables verification for the probe.
        session = FakeSession(FakeResponse(400, "Bad Request"))
        with patch_session(session):
            sde.probe_reachability(self.config, insecure_probe=True)
        self.assertIs(session.last_verify, False)
        self.assertIsNone(session.https_adapter)  # plain insecure, no adapter

    def test_probe_ca_bundle_uses_that_bundle(self):
        # Required (Priority 2): a CA bundle is used as the probe's trust anchor,
        # with no dependency on pre-existing files and without skipping adapter
        # initialization (the context builder is mocked, not the mount).
        sentinel_ctx = mock.MagicMock(name="ssl_context")
        session = FakeSession(FakeResponse(400, "Bad Request - not valid JSON"))
        with patch_session(session), \
             mock.patch.object(sde, "_seclevel1_context", return_value=sentinel_ctx) as ctxf:
            sde.probe_reachability(self.config, ca_bundle="/tmp/router.pem")
        self.assertIs(session.last_verify, True)
        adapter = session.https_adapter
        self.assertIsInstance(adapter, sde._SSLContextAdapter)
        self.assertEqual(adapter.ca_bundle, "/tmp/router.pem")
        ctxf.assert_called_once_with(cafile="/tmp/router.pem", verify=True)
        self.assertIs(adapter._ssl_context, sentinel_ctx)

    def test_probe_insecure_still_sends_no_credentials(self):
        session = FakeSession(FakeResponse(400, "Bad Request"))
        with patch_session(session):
            sde.probe_reachability(self.config, insecure_probe=True)
        args, kwargs = session.post_calls[0]
        self.assertNotIn("json", kwargs)
        blob = repr((args, kwargs))
        for secret in ("password", "pubkey", "admin", "ssh-ed25519", "ssh-rsa"):
            self.assertNotIn(secret, blob)

    def test_probe_has_no_bearing_on_enable_via_cli(self):
        # Required: --insecure-probe can never make --enable skip verification.
        session = FakeSession(FakeResponse(200, "OK\n"))
        with mock.patch.object(sde, "load_public_key", return_value=VALID_ED25519), \
             mock.patch("builtins.input", return_value="ENABLE"), \
             mock.patch.object(sde, "collect_credentials", return_value=("admin", "pw")), \
             patch_session(session):
            # --enable alongside --insecure-probe (probe flag present but enabling)
            rc = sde.main(["--enable", "--insecure-probe"])
        self.assertEqual(rc, 0)
        self.assertIsNot(session.last_verify, False)  # enable still verifies


# ----------------------------------------------------------------------
# CLI safety: default mode performs no request
# ----------------------------------------------------------------------

class TestCliSafety(unittest.TestCase):
    def test_default_mode_sends_nothing(self):
        with mock.patch.object(sde, "_new_session") as new_session:
            rc = sde.main(["--router", "routerlogin.net"])
        self.assertEqual(rc, 0)
        new_session.assert_not_called()

    def test_probe_and_enable_mutually_exclusive(self):
        with mock.patch.object(sde, "_new_session") as new_session:
            rc = sde.main(["--probe", "--enable"])
        self.assertEqual(rc, 2)
        new_session.assert_not_called()

    def test_enable_aborts_when_confirmation_not_typed(self):
        # Key loading is mocked; a wrong confirmation must stop before any request.
        with mock.patch.object(sde, "load_public_key", return_value=VALID_ED25519), \
             mock.patch("builtins.input", return_value="no"), \
             mock.patch.object(sde, "_new_session") as new_session:
            rc = sde.main(["--enable"])
        self.assertEqual(rc, 1)
        new_session.assert_not_called()

    def test_enable_happy_path_sends_request_after_confirmation(self):
        session = FakeSession(FakeResponse(200, "OK\n"))
        with mock.patch.object(sde, "load_public_key", return_value=VALID_ED25519), \
             mock.patch("builtins.input", return_value="ENABLE"), \
             mock.patch.object(sde, "collect_credentials", return_value=("admin", "pw")), \
             patch_session(session):
            rc = sde.main(["--enable"])
        self.assertEqual(rc, 0)
        self.assertEqual(len(session.post_calls), 1)
        self.assertEqual(session.post_calls[0][0][0], "https://routerlogin.net/api/v1/enable_ssh")

    def test_probe_returns_zero_on_400(self):
        session = FakeSession(FakeResponse(400, "Bad Request - Message body is not valid JSON"))
        with patch_session(session):
            rc = sde.main(["--probe"])
        self.assertEqual(rc, 0)

    def test_probe_returns_one_on_non_400(self):
        session = FakeSession(FakeResponse(200, "OK"))
        with patch_session(session):
            rc = sde.main(["--probe"])
        self.assertEqual(rc, 1)


class TestLoadPublicKey(unittest.TestCase):
    def test_missing_file_raises(self):
        with self.assertRaises(FileNotFoundError):
            sde.load_public_key(sde.Path("/nonexistent/key.pub"))

    def test_private_key_is_rejected(self):
        # Pointing at a private key by mistake must be refused (no ssh- prefix).
        with mock.patch.object(sde.Path, "is_file", return_value=True), \
             mock.patch.object(
                 sde.Path, "read_text",
                 return_value="-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n",
             ):
            with self.assertRaises(ValueError):
                sde.load_public_key(sde.Path("/home/user/.ssh/id_ed25519"))


# ----------------------------------------------------------------------
# Priority 1: the probe must never interpret 200/418/404/500 as success
# ----------------------------------------------------------------------

class TestProbeClassify(unittest.TestCase):
    def test_expected_400_is_probe_reachable(self):
        r = sde.classify_probe_response(400, "Bad Request - Message body is not valid JSON")
        self.assertIs(r.outcome, sde.Outcome.PROBE_REACHABLE)
        self.assertFalse(r.ok)

    def test_400_with_unexpected_body_is_unexpected(self):
        r = sde.classify_probe_response(400, "something else entirely")
        self.assertIs(r.outcome, sde.Outcome.UNEXPECTED)

    def test_no_status_is_ever_probe_success(self):
        # HTTP 200/418/404/500 must NOT be success and must NOT claim auth ran.
        for status, body in [(200, "OK"), (418, "I'm a teapot"),
                             (404, "not found"), (500, "Server Error")]:
            r = sde.classify_probe_response(status, body)
            self.assertIsNot(r.outcome, sde.Outcome.SUCCESS, status)
            self.assertIsNot(r.outcome, sde.Outcome.PROBE_REACHABLE, status)
            self.assertIs(r.outcome, sde.Outcome.UNEXPECTED, status)
            self.assertFalse(r.ok, status)
            # Must not affirmatively claim auth/handler success.
            low = r.detail.lower()
            self.assertNotIn("verify_admin passed", low)
            self.assertNotIn("handler ran.", low)

    def test_probe_200_end_to_end_not_success(self):
        # The original bug: a mocked 200 to the probe was reported as SUCCESS.
        session = FakeSession(FakeResponse(200, "OK\n"))
        with patch_session(session):
            r = sde.probe_reachability(sde.RouterConfig(address="routerlogin.net"))
        self.assertIs(r.outcome, sde.Outcome.UNEXPECTED)
        self.assertFalse(r.ok)


# ----------------------------------------------------------------------
# Priority 4: conservative local password-safety validation
# ----------------------------------------------------------------------

class TestPasswordSafety(unittest.TestCase):
    def test_accepts_ordinary_strong_password(self):
        # Letters, digits, and safe punctuation are allowed.
        sde.validate_password_safe("Str0ng-Pass_word.99")  # must not raise

    def test_rejects_empty(self):
        with self.assertRaises(ValueError):
            sde.validate_password_safe("")

    def test_rejects_shell_metacharacters(self):
        for bad in ["pa;ss", "pa|ss", "pa&ss", "pa`ss", "pa$ss", "pa>ss",
                    "pa(ss)", "pa'ss", 'pa"ss', "pa\\ss", "pa*ss", "pa?ss"]:
            with self.assertRaises(ValueError, msg=bad):
                sde.validate_password_safe(bad)

    def test_rejects_whitespace_and_newline(self):
        for bad in ["pa ss", "pa\tss", "pa\nss", "pa\rss"]:
            with self.assertRaises(ValueError, msg=repr(bad)):
                sde.validate_password_safe(bad)

    def test_rejects_control_and_non_ascii(self):
        for bad in ["pa\x00ss", "pa\x1bss", "pa\x7fss", "café"]:
            with self.assertRaises(ValueError, msg=repr(bad)):
                sde.validate_password_safe(bad)

    def test_error_does_not_echo_password(self):
        secret = "evil;rm -rf /`whoami`"
        try:
            sde.validate_password_safe(secret)
            self.fail("expected ValueError")
        except ValueError as exc:
            self.assertNotIn(secret, str(exc))
            self.assertNotIn("whoami", str(exc))

    def test_enable_ssh_rejects_unsafe_password_before_any_request(self):
        session = FakeSession(FakeResponse(200, "OK"))
        with patch_session(session):
            with self.assertRaises(ValueError):
                sde.enable_ssh(sde.RouterConfig(address="routerlogin.net"),
                               "admin", "pa;ss", VALID_ED25519)
        self.assertEqual(session.post_calls, [])  # nothing was sent


# ----------------------------------------------------------------------
# Priority 3 & 5: real local TLS handshake - pinning and trust semantics
# against a locally generated certificate (never the router).
# ----------------------------------------------------------------------

def _sha256_fingerprint(pem_path: str) -> str:
    der = ssl.PEM_cert_to_DER_cert(open(pem_path).read())
    return hashlib.sha256(der).hexdigest()


class _OKHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = b"OK\n"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):  # noqa: A002 - match base signature
        pass


@unittest.skipIf(shutil.which("openssl") is None, "openssl needed to generate test certs")
class TestTlsHandshake(unittest.TestCase):
    """Starts a local HTTPS server with a generated self-signed leaf (CA:FALSE,
    SAN DNS:localhost) and drives the real client TLS code against it."""

    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp(prefix="orbi_tls_")
        cls.cert = os.path.join(cls.dir, "server.pem")
        cls.key = os.path.join(cls.dir, "server.key")
        cls.other = os.path.join(cls.dir, "other.pem")
        okey = os.path.join(cls.dir, "other.key")
        for c, k in ((cls.cert, cls.key), (cls.other, okey)):
            subprocess.run(
                ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                 "-keyout", k, "-out", c, "-days", "1", "-subj", "/CN=localhost",
                 "-addext", "subjectAltName=DNS:localhost",
                 "-addext", "basicConstraints=critical,CA:FALSE"],
                check=True, capture_output=True,
            )
        cls.fp_good = _sha256_fingerprint(cls.cert)
        cls.fp_other = _sha256_fingerprint(cls.other)

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cls.cert, cls.key)
        cls.httpd = http.server.HTTPServer(("127.0.0.1", 0), _OKHandler)
        cls.httpd.socket = ctx.wrap_socket(cls.httpd.socket, server_side=True)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        shutil.rmtree(cls.dir, ignore_errors=True)

    def _cfg(self, host):
        return sde.RouterConfig(address=f"{host}:{self.port}")

    # --- Priority 3: fingerprint enforcement over a real handshake ---
    def test_correct_pin_connects(self):
        r = sde.enable_ssh(self._cfg("127.0.0.1"), "admin", "pw", VALID_ED25519,
                           pin_sha256=self.fp_good)
        self.assertIs(r.outcome, sde.Outcome.SUCCESS)

    def test_wrong_pin_rejected_by_handshake(self):
        r = sde.enable_ssh(self._cfg("127.0.0.1"), "admin", "pw", VALID_ED25519,
                           pin_sha256=self.fp_other)
        self.assertIs(r.outcome, sde.Outcome.TRANSPORT_ERROR)

    def test_malformed_pin_rejected_before_connection(self):
        # No server interaction: normalization fails first.
        with self.assertRaises(ValueError):
            sde.enable_ssh(self._cfg("127.0.0.1"), "admin", "pw", VALID_ED25519,
                           pin_sha256="not-a-fingerprint")

    def test_authenticated_request_cannot_disable_fingerprint(self):
        # The enable policy for a pin always carries the fingerprint; there is no
        # switch to turn it off, and a wrong cert therefore cannot be accepted.
        policy = sde.enable_tls_policy(None, self.fp_good)
        self.assertEqual(policy.pin_sha256, self.fp_good)
        self.assertTrue(policy.verifies_certificate)
        r = sde.enable_ssh(self._cfg("127.0.0.1"), "admin", "pw", VALID_ED25519,
                           pin_sha256=self.fp_other)
        self.assertIsNot(r.outcome, sde.Outcome.SUCCESS)

    def test_insecure_probe_does_not_affect_authenticated_pin(self):
        # Even if a probe ran insecurely, enable with a WRONG pin still fails.
        sde.probe_tls_policy(None, None, insecure_probe=True)  # sets nothing global
        r = sde.enable_ssh(self._cfg("127.0.0.1"), "admin", "pw", VALID_ED25519,
                           pin_sha256=self.fp_other)
        self.assertIs(r.outcome, sde.Outcome.TRANSPORT_ERROR)

    # --- Priority 5: distinguish trust-anchor pinning / hostname / wrong cert ---
    def test_ca_bundle_trust_anchor_with_matching_hostname(self):
        # Self-signed leaf (CA:FALSE) as ca-bundle + hostname match -> accepted.
        r = sde.enable_ssh(self._cfg("localhost"), "admin", "pw", VALID_ED25519,
                           ca_bundle=self.cert)
        self.assertIs(r.outcome, sde.Outcome.SUCCESS)

    def test_ca_bundle_hostname_mismatch_fails(self):
        # Same trusted cert, but connect by IP (not in SAN DNS:localhost) -> the
        # hostname check rejects it. Proves ca-bundle mode verifies hostname.
        r = sde.enable_ssh(self._cfg("127.0.0.1"), "admin", "pw", VALID_ED25519,
                           ca_bundle=self.cert)
        self.assertIs(r.outcome, sde.Outcome.TRANSPORT_ERROR)

    def test_ca_bundle_wrong_certificate_fails(self):
        # Trusting a DIFFERENT cert rejects the server's real cert.
        r = sde.enable_ssh(self._cfg("localhost"), "admin", "pw", VALID_ED25519,
                           ca_bundle=self.other)
        self.assertIs(r.outcome, sde.Outcome.TRANSPORT_ERROR)


if __name__ == "__main__":
    unittest.main(verbosity=2)
