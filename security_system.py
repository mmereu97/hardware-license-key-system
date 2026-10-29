"""Client-side license manager: what the protected application uses.

    manager = SecureLicenseManager()
    status = manager.status()            # LicenseStatus(valid, message, days_left, expires)
    ok, message = manager.save_license(key)
    manager.get_hardware_id()            # shown to the user, sent to the vendor

Local state (license.dat) is plain JSON: the license keys themselves (signed,
so they cannot be edited) and the last time the application saw the clock.
An HMAC over the state makes casual edits detectable; it is not a secret
(the key is derived from data on this machine), only a tamper seal.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import random
import sys
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from typing import Callable, List, Optional, Tuple

from license_core import (
    License,
    LicenseError,
    check_license,
    hardware_matches,
    load_public_key,
    read_license,
)

CLOCK_TOLERANCE_SECONDS = 10 * 60      # how far back the clock may move (DST, sync jitter)
NTP_TOLERANCE_SECONDS = 5 * 60
NTP_SERVERS = ["pool.ntp.org", "time.google.com", "time.windows.com", "time.cloudflare.com"]


@dataclass(frozen=True)
class LicenseStatus:
    valid: bool
    message: str
    days_left: int = 0
    expires: Optional[date] = None


def app_dir() -> Path:
    """Folder of the running application (the .exe when frozen with PyInstaller)."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def ntp_offset_seconds(timeout: float = 2.0) -> Optional[float]:
    """Local clock minus internet time, or None when offline."""
    try:
        import ntplib
    except ImportError:
        return None
    client = ntplib.NTPClient()
    for server in random.sample(NTP_SERVERS, 2):
        try:
            return -client.request(server, version=3, timeout=timeout).offset
        except Exception:
            continue
    return None


class SecureLicenseManager:
    def __init__(
        self,
        license_file: Optional[str] = None,
        public_key_pem: Optional[bytes] = None,
        hardware_id: Optional[str] = None,
        now: Callable[[], datetime] = datetime.now,
        check_internet_time: bool = True,
    ):
        if public_key_pem is None:
            from public_key import PUBLIC_KEY_PEM
            public_key_pem = PUBLIC_KEY_PEM
        if not public_key_pem:
            raise RuntimeError("No public key configured: run `python generate_keys.py` first")
        self._public_key = load_public_key(public_key_pem)
        self._public_key_pem = public_key_pem
        self.license_file = Path(license_file) if license_file else app_dir() / "license.dat"
        self._hardware_id = hardware_id
        self._now = now
        self._check_internet_time = check_internet_time
        self._ntp_checked_at: Optional[float] = None   # internet time is checked at most once per hour

    # ------------------------------------------------------------ public API

    def get_hardware_id(self) -> str:
        if self._hardware_id is None:
            from hardware_id import current_hardware_id
            self._hardware_id = current_hardware_id()
        return self._hardware_id

    def status(self) -> LicenseStatus:
        now = self._now()
        problem = self._clock_problem(now)
        if problem:
            return LicenseStatus(False, problem)

        keys, state_ok = self._load_state()
        if not state_ok:
            return LicenseStatus(False, "The license file was modified: please enter your license key again")
        if not keys:
            return LicenseStatus(False, "No license found")

        best: Optional[License] = None
        last_error = "No valid license"
        for key in keys:
            try:
                lic = read_license(key, self._public_key)
                check_license(lic, self.get_hardware_id(), now.date())
            except LicenseError as exc:
                last_error = str(exc)
                continue
            if best is None or lic.expires > best.expires:
                best = lic
        if best is None:
            return LicenseStatus(False, last_error)

        self._save_state(keys, now)   # remember the clock: detects it being moved back later
        days = best.days_left(now.date())
        return LicenseStatus(True, f"License valid. Days remaining: {days}", days, best.expires)

    def verify_license(self) -> Tuple[bool, str]:
        """Kept for compatibility with the v1 API."""
        s = self.status()
        return s.valid, s.message

    def save_license(self, key: str) -> Tuple[bool, str]:
        now = self._now()
        problem = self._clock_problem(now)
        if problem:
            return False, problem
        try:
            lic = read_license(key, self._public_key)
            check_license(lic, self.get_hardware_id(), now.date())
        except LicenseError as exc:
            return False, str(exc)

        keys, state_ok = self._load_state()
        if not state_ok:
            keys = []
        # keep only keys that still matter: valid for this machine and not expired
        kept: List[str] = []
        for old in keys:
            try:
                old_lic = read_license(old, self._public_key)
            except LicenseError:
                continue
            if (old_lic.key != lic.key and old_lic.expires > now.date()
                    and hardware_matches(old_lic.hardware_id, self.get_hardware_id())):
                kept.append(old)
        self._save_state(kept + [lic.key], now)
        return True, f"License activated. Expires on {lic.expires.isoformat()}"

    # ------------------------------------------------------------ clock

    def _clock_problem(self, now: datetime) -> Optional[str]:
        last_seen = self._last_seen()
        if last_seen is not None and now.timestamp() < last_seen - CLOCK_TOLERANCE_SECONDS:
            return "The system clock was moved back: set the correct date and time"
        if self._check_internet_time and (
            self._ntp_checked_at is None or abs(now.timestamp() - self._ntp_checked_at) > 3600
        ):
            offset = ntp_offset_seconds()
            if offset is not None and abs(offset) > NTP_TOLERANCE_SECONDS:
                return "The system clock differs from internet time: set the correct date and time"
            if offset is not None:
                self._ntp_checked_at = now.timestamp()
        return None

    # ------------------------------------------------------------ state file

    def _seal_key(self) -> bytes:
        return hashlib.sha256(b"license-state|" + self.get_hardware_id().encode() + b"|" + self._public_key_pem).digest()

    def _seal(self, keys: List[str], last_seen: float) -> str:
        body = json.dumps({"keys": keys, "last_seen": last_seen}, sort_keys=True).encode()
        return hmac.new(self._seal_key(), body, hashlib.sha256).hexdigest()

    def _read_raw(self) -> Optional[dict]:
        try:
            return json.loads(self.license_file.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return None
        except (OSError, ValueError):
            return {}

    def _load_state(self) -> Tuple[List[str], bool]:
        data = self._read_raw()
        if data is None:
            return [], True
        try:
            keys, last_seen = list(data["keys"]), float(data["last_seen"])
            ok = hmac.compare_digest(str(data["seal"]), self._seal(keys, last_seen))
        except (KeyError, TypeError, ValueError):
            return [], False
        return (keys, True) if ok else ([], False)

    def _last_seen(self) -> Optional[float]:
        data = self._read_raw()
        try:
            return float(data["last_seen"]) if data else None
        except (KeyError, TypeError, ValueError):
            return None

    def _save_state(self, keys: List[str], now: datetime) -> None:
        last_seen = max(now.timestamp(), self._last_seen() or 0.0)
        data = {"keys": keys, "last_seen": last_seen, "seal": self._seal(keys, last_seen)}
        tmp = self.license_file.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
        os.replace(tmp, self.license_file)
