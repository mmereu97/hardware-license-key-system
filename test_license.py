"""Tests for the licensing core and the client manager.

    python -m unittest -v test_license

No Windows, no Qt, no network: hardware IDs, clocks and keys are injected.
"""
from __future__ import annotations

import json
import tempfile
import unittest
from datetime import date, datetime, timedelta
from pathlib import Path

from license_core import (
    EMPTY_COMPONENT,
    LicenseError,
    check_license,
    component_hash,
    format_hardware_id,
    generate_keypair,
    hardware_matches,
    issue_license,
    load_private_key,
    parse_hardware_id,
    read_license,
    load_public_key,
)
from security_system import SecureLicenseManager

TODAY = date(2026, 10, 29)
HW = format_hardware_id({"cpu": "BFEBFBFF000B0671:i5-13600K", "bios": "AMI:SN123",
                         "board": "ASUS:PRIME:BRD456", "disk": "Samsung 990 EVO:S7XYZ"})


def with_component(hwid: str, index: int, value: str) -> str:
    parts = hwid.split("-")
    parts[index] = component_hash(value)
    return "-".join(parts)


class Clock:
    def __init__(self, start: datetime):
        self.t = start

    def __call__(self) -> datetime:
        return self.t


class CoreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        priv, pub = generate_keypair()
        cls.priv, cls.pub = load_private_key(priv), load_public_key(pub)
        other_priv, _ = generate_keypair()
        cls.other_priv = load_private_key(other_priv)

    def test_roundtrip(self):
        key = issue_license(self.priv, HW, 30, today=TODAY)
        lic = read_license(key, self.pub)
        self.assertEqual(lic.hardware_id, HW)
        self.assertEqual(lic.expires, TODAY + timedelta(days=30))
        self.assertEqual(lic.days_left(TODAY), 30)
        check_license(lic, HW, TODAY)

    def test_pasted_with_spaces_and_newlines(self):
        key = issue_license(self.priv, HW, 30, today=TODAY)
        messy = "  " + key[:20] + "\n" + key[20:] + " \n"
        self.assertEqual(read_license(messy, self.pub).key, key)

    def test_key_from_another_vendor_is_rejected(self):
        key = issue_license(self.other_priv, HW, 30, today=TODAY)
        with self.assertRaisesRegex(LicenseError, "not issued"):
            read_license(key, self.pub)

    def test_edited_payload_is_rejected(self):
        key = issue_license(self.priv, HW, 30, today=TODAY)
        payload, sig = key.split(".")
        import base64
        raw = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        raw["exp"] = "2099-01-01"
        forged = base64.urlsafe_b64encode(json.dumps(raw, separators=(",", ":"), sort_keys=True).encode()).rstrip(b"=").decode()
        with self.assertRaisesRegex(LicenseError, "not issued"):
            read_license(f"{forged}.{sig}", self.pub)

    def test_malformed_key(self):
        for bad in ["", "abc", "a.b.c", "!!!.???"]:
            with self.assertRaises(LicenseError):
                read_license(bad, self.pub)

    def test_one_changed_component_is_tolerated(self):
        lic = read_license(issue_license(self.priv, HW, 30, today=TODAY), self.pub)
        check_license(lic, with_component(HW, 3, "new disk"), TODAY)

    def test_two_changed_components_are_rejected(self):
        lic = read_license(issue_license(self.priv, HW, 30, today=TODAY), self.pub)
        other = with_component(with_component(HW, 3, "new disk"), 2, "new board")
        with self.assertRaisesRegex(LicenseError, "different computer"):
            check_license(lic, other, TODAY)

    def test_unreadable_components_never_count_as_matches(self):
        sparse = "-".join([component_hash("cpu"), EMPTY_COMPONENT, component_hash("board"), EMPTY_COMPONENT])
        self.assertTrue(hardware_matches(sparse, sparse))
        self.assertFalse(hardware_matches(sparse, with_component(sparse, 2, "other board")))

    def test_placeholder_serials_are_empty(self):
        for value in ["To be filled by O.E.M.", "Default string", "0", "", None]:
            self.assertEqual(component_hash(value), EMPTY_COMPONENT)

    def test_hardware_id_validation(self):
        with self.assertRaises(LicenseError):
            parse_hardware_id("not-a-hardware-id")
        with self.assertRaises(LicenseError):   # only one readable component
            parse_hardware_id("-".join([component_hash("x")] + [EMPTY_COMPONENT] * 3))
        self.assertEqual(parse_hardware_id(HW.lower()), HW.split("-"))

    def test_expired(self):
        lic = read_license(issue_license(self.priv, HW, 30, today=TODAY), self.pub)
        check_license(lic, HW, TODAY + timedelta(days=29))
        with self.assertRaisesRegex(LicenseError, "expired"):
            check_license(lic, HW, TODAY + timedelta(days=30))

    def test_clock_before_issue_date(self):
        lic = read_license(issue_license(self.priv, HW, 30, today=TODAY), self.pub)
        with self.assertRaisesRegex(LicenseError, "earlier than the license issue date"):
            check_license(lic, HW, TODAY - timedelta(days=1))

    def test_extension_starts_after_current_expiry(self):
        key = issue_license(self.priv, HW, 30, start=TODAY + timedelta(days=10), today=TODAY)
        self.assertEqual(read_license(key, self.pub).expires, TODAY + timedelta(days=40))

    def test_start_in_the_past_counts_from_today(self):
        key = issue_license(self.priv, HW, 30, start=TODAY - timedelta(days=100), today=TODAY)
        self.assertEqual(read_license(key, self.pub).expires, TODAY + timedelta(days=30))

    def test_days_bounds(self):
        for days in (0, -1, 10_000):
            with self.assertRaises(LicenseError):
                issue_license(self.priv, HW, days, today=TODAY)

    def test_encrypted_private_key(self):
        priv_pem, _ = generate_keypair(b"correct horse")
        load_private_key(priv_pem, b"correct horse")
        with self.assertRaises(Exception):
            load_private_key(priv_pem, b"wrong")


class ManagerTests(unittest.TestCase):
    def setUp(self):
        priv_pem, self.pub_pem = generate_keypair()
        self.priv = load_private_key(priv_pem)
        self.dir = tempfile.TemporaryDirectory()
        self.file = str(Path(self.dir.name) / "license.dat")
        self.clock = Clock(datetime(2026, 10, 29, 12, 0))

    def tearDown(self):
        self.dir.cleanup()

    def manager(self, hwid: str = HW) -> SecureLicenseManager:
        return SecureLicenseManager(self.file, self.pub_pem, hwid, now=self.clock, check_internet_time=False)

    def issue(self, days=30, start=None, hwid=HW):
        return issue_license(self.priv, hwid, days, start=start, today=self.clock().date())

    def test_no_license(self):
        self.assertFalse(self.manager().status().valid)

    def test_survives_restart(self):
        """The v1 bug: the license had to survive a new manager instance (= app restart)."""
        ok, msg = self.manager().save_license(self.issue())
        self.assertTrue(ok, msg)
        status = self.manager().status()
        self.assertTrue(status.valid, status.message)
        self.assertEqual(status.days_left, 30)

    def test_compat_api(self):
        self.manager().save_license(self.issue())
        ok, message = self.manager().verify_license()
        self.assertTrue(ok)
        self.assertEqual(int(message.split(": ")[1]), 30)

    def test_wrong_computer(self):
        ok, msg = self.manager().save_license(self.issue(hwid=with_component(with_component(HW, 0, "a"), 1, "b")))
        self.assertFalse(ok)
        self.assertIn("different computer", msg)

    def test_editing_the_state_file_is_detected(self):
        self.manager().save_license(self.issue())
        data = json.loads(Path(self.file).read_text())
        data["last_seen"] -= 86400 * 365
        Path(self.file).write_text(json.dumps(data))
        status = self.manager().status()
        self.assertFalse(status.valid)
        self.assertIn("modified", status.message)

    def test_clock_moved_back_is_detected(self):
        m = self.manager()
        m.save_license(self.issue())
        self.clock.t += timedelta(days=5)
        self.assertTrue(m.status().valid)
        self.clock.t -= timedelta(days=3)
        status = self.manager().status()
        self.assertFalse(status.valid)
        self.assertIn("moved back", status.message)

    def test_small_clock_adjustment_is_tolerated(self):
        m = self.manager()
        m.save_license(self.issue())
        self.clock.t -= timedelta(minutes=5)
        self.assertTrue(m.status().valid)

    def test_extension_keeps_the_longest_license(self):
        m = self.manager()
        m.save_license(self.issue(30))
        current = m.status().expires
        ok, msg = m.save_license(self.issue(60, start=current))
        self.assertTrue(ok, msg)
        self.assertEqual(m.status().days_left, 90)

    def test_expiry(self):
        m = self.manager()
        m.save_license(self.issue(30))
        self.clock.t += timedelta(days=30)
        status = m.status()
        self.assertFalse(status.valid)
        self.assertIn("expired", status.message)

    def test_expired_keys_are_dropped_on_save(self):
        m = self.manager()
        m.save_license(self.issue(1))
        self.clock.t += timedelta(days=2)
        m.save_license(self.issue(30))
        self.assertEqual(len(json.loads(Path(self.file).read_text())["keys"]), 1)

    def test_state_file_contains_no_code_or_secrets(self):
        self.manager().save_license(self.issue())
        data = json.loads(Path(self.file).read_text())
        self.assertEqual(set(data), {"keys", "last_seen", "seal"})


if __name__ == "__main__":
    unittest.main()
