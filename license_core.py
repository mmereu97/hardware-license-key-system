"""Signed, hardware-bound licenses (Ed25519).

Pure logic: no Qt, no Windows, no file I/O, so every rule here is unit-tested.

The vendor keeps the PRIVATE key and signs licenses with it (keygen.py).
The application ships only the PUBLIC key and can verify licenses, but never
create them. Reading the application's code or binary does not help anyone
generate a key.

License key format (one line, safe to paste):

    <payload>.<signature>        both base64url, without padding

    payload = {"v":1,"hw":"1A2B3C4D-...","iss":"2026-10-29","exp":"2026-11-28","id":"9f3c2a1b"}

Hardware ID format: four 8-character hashes, one per component, e.g.
    1A2B3C4D-5E6F7A8B-9C0D1E2F-3A4B5C6D   (cpu - bios - board - disk)
Keeping the components separate lets the application tolerate one changed
part (e.g. a new disk) without a new license.
"""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
from dataclasses import dataclass
from datetime import date, timedelta
from typing import Dict, List, Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

FORMAT_VERSION = 1
COMPONENTS = ("cpu", "bios", "board", "disk")
MIN_MATCHING_COMPONENTS = 3     # out of 4: one hardware change is tolerated
MIN_READABLE_COMPONENTS = 2     # a hardware ID with fewer readable parts is refused
MAX_DAYS = 3650
EMPTY_COMPONENT = "00000000"

# Values that firmware vendors leave in unused fields: they identify nothing.
_PLACEHOLDERS = {
    "", "0", "none", "null", "n/a", "na", "default string", "to be filled by o.e.m",
    "to be filled by oem", "system serial number", "system product name",
    "base board serial number", "not applicable", "not specified", "0123456789",
}


class LicenseError(Exception):
    """A license or hardware ID that cannot be accepted. The message is user-facing."""


# --------------------------------------------------------------------------- encoding

def _b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


# --------------------------------------------------------------------------- hardware ID

def is_placeholder(value: Optional[str]) -> bool:
    return (value or "").strip().rstrip(".").lower() in _PLACEHOLDERS


def component_hash(value: Optional[str]) -> str:
    """8 hex characters identifying one component, or EMPTY_COMPONENT if unreadable."""
    if is_placeholder(value):
        return EMPTY_COMPONENT
    return hashlib.sha256(value.strip().encode("utf-8")).hexdigest()[:8].upper()


def format_hardware_id(components: Dict[str, str]) -> str:
    """Build the hardware ID from raw component strings (see hardware_id.py)."""
    return "-".join(component_hash(components.get(name)) for name in COMPONENTS)


def parse_hardware_id(hardware_id: str) -> List[str]:
    """Validate a hardware ID and return its four component hashes."""
    parts = "".join(hardware_id.split()).upper().split("-")
    if len(parts) != len(COMPONENTS) or not all(
        len(p) == 8 and all(c in "0123456789ABCDEF" for c in p) for p in parts
    ):
        raise LicenseError("Invalid hardware ID: expected 4 groups of 8 characters, e.g. 1A2B3C4D-5E6F7A8B-9C0D1E2F-3A4B5C6D")
    if sum(p != EMPTY_COMPONENT for p in parts) < MIN_READABLE_COMPONENTS:
        raise LicenseError("This hardware ID has too few readable components to be licensed safely")
    return parts


def normalize_hardware_id(hardware_id: str) -> str:
    return "-".join(parse_hardware_id(hardware_id))


def matching_components(licensed: str, current: str) -> int:
    """How many readable components the two hardware IDs have in common."""
    a, b = parse_hardware_id(licensed), parse_hardware_id(current)
    return sum(1 for x, y in zip(a, b) if x == y and x != EMPTY_COMPONENT)


def hardware_matches(licensed: str, current: str) -> bool:
    try:
        readable = sum(p != EMPTY_COMPONENT for p in parse_hardware_id(licensed))
        return matching_components(licensed, current) >= min(MIN_MATCHING_COMPONENTS, readable)
    except LicenseError:
        return False


# --------------------------------------------------------------------------- keys

def generate_keypair(passphrase: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    """(private_key_pem, public_key_pem). The private key is encrypted if a passphrase is given."""
    private_key = Ed25519PrivateKey.generate()
    encryption = (
        serialization.BestAvailableEncryption(passphrase)
        if passphrase else serialization.NoEncryption()
    )
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption
    )
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_pem, public_pem


def load_private_key(pem: bytes, passphrase: Optional[bytes] = None) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(pem, password=passphrase)
    if not isinstance(key, Ed25519PrivateKey):
        raise LicenseError("The private key is not an Ed25519 key")
    return key


def load_public_key(pem: bytes) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(pem)
    if not isinstance(key, Ed25519PublicKey):
        raise LicenseError("The public key is not an Ed25519 key")
    return key


# --------------------------------------------------------------------------- licenses

@dataclass(frozen=True)
class License:
    hardware_id: str
    issued: date
    expires: date          # first day on which the license is NO LONGER valid
    license_id: str
    key: str               # the original license key text

    def days_left(self, today: date) -> int:
        return max(0, (self.expires - today).days)


def issue_license(
    private_key: Ed25519PrivateKey,
    hardware_id: str,
    days: int,
    start: Optional[date] = None,
    today: Optional[date] = None,
) -> str:
    """Sign a license for `hardware_id`, valid `days` days from `start` (default: today).

    `start` later than today extends an existing license: pass the current
    expiry date shown in the application, and the new days are added after it.
    """
    if not 1 <= days <= MAX_DAYS:
        raise LicenseError(f"Days must be between 1 and {MAX_DAYS}")
    today = today or date.today()
    begin = max(start or today, today)
    payload = {
        "v": FORMAT_VERSION,
        "hw": normalize_hardware_id(hardware_id),
        "iss": today.isoformat(),
        "exp": (begin + timedelta(days=days)).isoformat(),
        "id": secrets.token_hex(4),
    }
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return f"{_b64encode(raw)}.{_b64encode(private_key.sign(raw))}"


def read_license(key: str, public_key: Ed25519PublicKey) -> License:
    """Check the signature and decode the license. Does NOT check hardware or dates."""
    text = "".join(key.split())
    try:
        payload_part, signature_part = text.split(".")
        raw, signature = _b64decode(payload_part), _b64decode(signature_part)
    except ValueError:
        raise LicenseError("Malformed license key: copy the whole key, it contains a dot") from None
    try:
        public_key.verify(signature, raw)
    except InvalidSignature:
        raise LicenseError("Invalid license key: it was not issued for this application") from None
    try:
        data = json.loads(raw)
        if data["v"] != FORMAT_VERSION:
            raise LicenseError(f"Unsupported license format version {data['v']}")
        return License(
            hardware_id=normalize_hardware_id(data["hw"]),
            issued=date.fromisoformat(data["iss"]),
            expires=date.fromisoformat(data["exp"]),
            license_id=str(data["id"]),
            key=text,
        )
    except LicenseError:
        raise
    except (KeyError, TypeError, ValueError) as exc:
        raise LicenseError(f"Corrupted license data: {exc}") from None


def check_license(lic: License, current_hardware_id: str, today: date) -> None:
    """Raise LicenseError if the license cannot be used on this machine today."""
    if not hardware_matches(lic.hardware_id, current_hardware_id):
        raise LicenseError("This license belongs to a different computer")
    if today < lic.issued:
        raise LicenseError("The system date is earlier than the license issue date: check the computer's clock")
    if today >= lic.expires:
        raise LicenseError(f"License expired on {lic.expires.isoformat()}")
