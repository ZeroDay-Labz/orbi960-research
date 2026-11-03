#!/usr/bin/env python3
"""Mocked unit tests for orbi_satellite_ssh.py.

These tests NEVER contact a real router or satellite. All network/SSH calls are
patched. Run:  .venv/bin/python -m pytest test_orbi_satellite_ssh.py
         or:  .venv/bin/python -m unittest test_orbi_satellite_ssh
"""

from __future__ import annotations

import contextlib
import tempfile
import unittest
from unittest import mock

import orbi_satellite_ssh as sat


# Real known MACs from the module, lower-cased.
MAC1 = sat.normalise_mac(sat.SATELLITES[1]["mac"])
MAC2 = sat.normalise_mac(sat.SATELLITES[2]["mac"])

ARP_OUTPUT = (
    f"198.51.100.7 dev br-lan lladdr {MAC1} REACHABLE\n"
    f"198.51.100.11 dev br-lan lladdr {MAC2} REACHABLE\n"
    "198.51.100.50 dev br-lan lladdr aa:bb:cc:dd:ee:ff STALE\n"
)

CS_RBSE = {"Model": "RBSE960", "Firmware": "V7.2.7.15", "RegionTag": "RBSE960_NA"}


class _NullLog:
    def __call__(self, *_a, **_k):
        pass

    def note_path(self):
        return "(test)"


@contextlib.contextmanager
def _patch_discovery(arp=ARP_OUTPUT, cs_map=None, local_neigh=""):
    """Patch the master SSH, currentsetting reads, and the local neighbour table
    so discovery is fully isolated from the host/network."""
    cs_map = cs_map or {"198.51.100.7": dict(CS_RBSE), "198.51.100.11": dict(CS_RBSE)}

    def fake_master_ssh(command, log, timeout=sat.DEFAULT_TIMEOUT):
        if "neigh" in command or "arp" in command:
            return arp
        return ""  # leases empty

    def fake_cs(ip, timeout=sat.DEFAULT_TIMEOUT):
        if ip in cs_map:
            return cs_map[ip]
        raise OSError("unreachable")

    with mock.patch.object(sat, "master_ssh", side_effect=fake_master_ssh), \
         mock.patch.object(sat, "read_currentsetting", side_effect=fake_cs), \
         mock.patch.object(sat, "local_neigh_table", return_value=local_neigh):
        yield


class DiscoveryTests(unittest.TestCase):
    def test_two_satellite_inventory_and_ip_discovery(self):
        with _patch_discovery():
            states = sat.discover(_NullLog())
        self.assertEqual(len(states), 2)
        by_id = {s.sat_id: s for s in states}
        self.assertEqual(by_id[1].ip, "198.51.100.7")
        self.assertEqual(by_id[2].ip, "198.51.100.11")

    def test_mac_to_device_matching(self):
        with _patch_discovery():
            states = sat.discover(_NullLog())
        for st in states:
            self.assertTrue(st.identity_ok, st.notes)
            self.assertEqual(st.firmware, "V7.2.7.15")

    def test_incorrect_model_detection(self):
        cs = {"198.51.100.7": {"Model": "RBRE960", "Firmware": "V7.2.7.15"},
              "198.51.100.11": dict(CS_RBSE)}
        with _patch_discovery(cs_map=cs):
            states = sat.discover(_NullLog())
        s1 = next(s for s in states if s.sat_id == 1)
        self.assertFalse(s1.identity_ok)
        self.assertTrue(any("identity mismatch" in n for n in s1.notes))

    def test_unexpected_firmware_version_warns(self):
        cs = {"198.51.100.7": {"Model": "RBSE960", "Firmware": "V7.2.8.8"},
              "198.51.100.11": dict(CS_RBSE)}
        with _patch_discovery(cs_map=cs):
            states = sat.discover(_NullLog())
        s1 = next(s for s in states if s.sat_id == 1)
        self.assertTrue(any("unexpected firmware" in n for n in s1.notes))
        # identity still OK (model matches); firmware is advisory only
        self.assertTrue(s1.identity_ok)

    def test_mac_not_found(self):
        with _patch_discovery(arp="198.51.100.50 dev br-lan lladdr aa:bb:cc:dd:ee:ff STALE\n"):
            states = sat.discover(_NullLog())
        self.assertTrue(all(s.ip is None for s in states))
        self.assertTrue(all(any("MAC not found" in n for n in s.notes) for s in states))

    def test_local_neighbour_fallback(self):
        # master SSH yields nothing; the local neighbour table resolves the MACs
        with _patch_discovery(arp="", local_neigh=ARP_OUTPUT):
            states = sat.discover(_NullLog())
        by_id = {s.sat_id: s for s in states}
        self.assertEqual(by_id[1].ip, "198.51.100.7")
        self.assertEqual(by_id[2].ip, "198.51.100.11")

    def test_ssh_connection_failure_is_non_fatal_for_discovery(self):
        def boom(command, log, timeout=sat.DEFAULT_TIMEOUT):
            raise sat.ToolError("master SSH failed (rc=255): Connection refused")
        with mock.patch.object(sat, "master_ssh", side_effect=boom), \
             mock.patch.object(sat, "read_currentsetting", side_effect=OSError), \
             mock.patch.object(sat, "local_neigh_table", return_value=""):
            states = sat.discover(_NullLog())
        self.assertEqual(len(states), 2)
        self.assertTrue(all(s.ip is None for s in states))


class PubkeyTests(unittest.TestCase):
    def _write(self, text):
        f = tempfile.NamedTemporaryFile("w", suffix=".pub", delete=False)
        f.write(text)
        f.close()
        return f.name

    def test_valid_rsa_pubkey(self):
        path = self._write("ssh-rsa AAAAB3Nza... owner@host\n")
        self.assertTrue(sat.owner_pubkey(path).startswith("ssh-rsa"))

    def test_rejects_private_key(self):
        path = self._write("-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----\n")
        with self.assertRaises(sat.ToolError):
            sat.owner_pubkey(path)

    def test_rejects_unknown_algorithm(self):
        path = self._write("ssh-dss AAAAB3Nza... owner@host\n")
        with self.assertRaises(sat.ToolError):
            sat.owner_pubkey(path)

    def test_missing_file(self):
        with self.assertRaises(sat.ToolError):
            sat.owner_pubkey("/nonexistent/key.pub")


class ProvisioningCommandTests(unittest.TestCase):
    def setUp(self):
        self.pub = "ssh-rsa AAAAKEYDATA orbi-rbre960-root"
        self.cmds = dict(sat.provisioning_commands(self.pub))

    def test_key_install_is_idempotent(self):
        install = next(c for d, c in sat.provisioning_commands(self.pub)
                       if "install owner public key" in d)
        self.assertIn("grep -qF", install)  # no duplicate append
        self.assertIn("/etc/dropbear/authorized_keys", install)

    def test_enables_keyonly_dropbear(self):
        enable = next(c for d, c in sat.provisioning_commands(self.pub)
                      if "enable key-only" in d)
        self.assertIn("enable='1'", enable)
        self.assertIn("PasswordAuth='off'", enable)
        self.assertIn("uci commit dropbear", enable)

    def test_uses_init_system_for_autostart(self):
        self.assertTrue(any("/etc/init.d/dropbear enable" in c
                            for c in self.cmds.values()))

    def test_no_mesh_or_flash_commands(self):
        joined = " ".join(self.cmds.values())
        for forbidden in ("hyd", "wsplcd", "repacd", "lbd", "mtd", "nand", "flash_erase",
                           "sysupgrade", "iptables -F", "firewall restart"):
            self.assertNotIn(forbidden, joined)

    def test_rollback_disables_and_removes_only_our_key(self):
        rb = dict(sat.rollback_commands())
        joined = " ".join(rb.values())
        self.assertIn("/etc/init.d/dropbear disable", joined)
        self.assertIn("orbi-rbre960-root", joined)  # removes only OUR key by comment
        self.assertNotIn("rm -f /etc/dropbear/authorized_keys", joined)  # never wipe all keys


class FakeTransport(sat.Transport):
    def __init__(self, results):
        self.results = results  # list of (rc, out, err)
        self.calls = []

    def run(self, command):
        self.calls.append(command)
        return self.results.pop(0) if self.results else (0, "", "")


class ApplyTests(unittest.TestCase):
    def test_partial_failure_is_counted(self):
        tr = FakeTransport([(0, "", ""), (0, "", ""), (1, "", "boom"),
                            (0, "", ""), (0, "", "")])
        pairs = sat.provisioning_commands("ssh-rsa X orbi-rbre960-root")
        failures = sat._apply_over_transport(tr, pairs, _NullLog())
        self.assertEqual(failures, 1)

    def test_all_success(self):
        tr = FakeTransport([(0, "", "")] * 5)
        pairs = sat.provisioning_commands("ssh-rsa X orbi-rbre960-root")
        self.assertEqual(sat._apply_over_transport(tr, pairs, _NullLog()), 0)


class TransportResolutionTests(unittest.TestCase):
    def _state(self, ssh_open, telnet_open):
        st = sat.SatelliteState(sat_id=1, name="Satellite1", model="RBSE960", mac=MAC1,
                                ip="198.51.100.7")
        st.ssh_open, st.telnet_open = ssh_open, telnet_open
        return st

    def test_ssh_open_gives_ssh_transport(self):
        tr = sat.resolve_transport(self._state(True, False), _NullLog())
        self.assertIsInstance(tr, sat.SSHTransport)

    def test_nothing_open_blocks(self):
        with self.assertRaises(sat.BootstrapUnavailable):
            sat.resolve_transport(self._state(False, False), _NullLog())

    def test_telnet_open_blocks_pending_confirmation(self):
        with self.assertRaises(sat.BootstrapUnavailable):
            sat.resolve_transport(self._state(False, True), _NullLog())


class AlreadyEnabledTests(unittest.TestCase):
    def test_status_reports_already_enabled_dropbear(self):
        st = sat.SatelliteState(sat_id=1, name="Satellite1", model="RBSE960", mac=MAC1,
                                ip="198.51.100.7")

        class UB:
            def __init__(self, *a, **k):
                pass

            def login(self, u, p):
                return True

            def uci_get(self, config):
                return {"values": {"cfg": {"enable": "1", ".type": "dropbear"}}}

        with mock.patch.object(sat, "tcp_open", return_value=True), \
             mock.patch.object(sat, "UbusClient", UB):
            sat.enrich_status(st, _NullLog(), "admin", "pw")
        self.assertEqual(st.dropbear_enable, "1")
        self.assertTrue(st.ssh_open)


class RedactionTests(unittest.TestCase):
    def test_private_key_redacted(self):
        txt = "x -----BEGIN OPENSSH PRIVATE KEY-----\nSECRET\n-----END OPENSSH PRIVATE KEY----- y"
        out = sat.redact(txt)
        self.assertNotIn("SECRET", out)
        self.assertIn("PRIVATE-KEY-REDACTED", out)

    def test_secret_string_redacted(self):
        self.assertNotIn("hunter2", sat.redact("pw=hunter2 ok", secrets=("hunter2",)))


class MacTests(unittest.TestCase):
    def test_normalise(self):
        self.assertEqual(sat.normalise_mac("02-00-00-AB-CD-EF"), "02:00:00:ab:cd:ef")


if __name__ == "__main__":
    unittest.main(verbosity=2)
