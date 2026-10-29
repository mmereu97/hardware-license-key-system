# 🔐 Hardware-Bound License Keys

**Offline software licensing in Python with Ed25519 signatures.**
The vendor signs licenses with a private key; the application verifies them with an embedded public key. Licenses are bound to the customer's hardware, expire on a fixed date, can be extended without reinstalling, and survive restarts, Windows updates and a replaced disk.

Reading the application's code or unpacking its `.exe` does **not** let anyone generate keys: the private key never leaves the vendor.

**Tech:** Python · cryptography (Ed25519) · PyQt5 · WMI · NTP · unittest

---

## How it works

```
 Customer's PC                                    Vendor
 ─────────────                                    ──────
 Application shows the Hardware ID   ──────────►  keygen.py
   7520B5A1-3F09C2D4-37C20EDF-A81B6E50              signs {hardware ID, issue date, expiry}
                                                    with the PRIVATE key
 Customer pastes the license key     ◄──────────  eyJleHAiOiIyMDI2LTEy....Zk3Nq
   application verifies it with the
   embedded PUBLIC key, checks the
   hardware and the date
```

A license key is `<payload>.<signature>` in base64url. The payload is small, readable JSON:

```json
{"v":1,"hw":"7520B5A1-3F09C2D4-37C20EDF-A81B6E50","iss":"2026-10-29","exp":"2026-12-13","id":"21baa3be"}
```

Change a single character and the Ed25519 signature no longer matches.

### Hardware ID

Four 8-character hashes, one per component: **CPU · BIOS · motherboard · system disk** (read through WMI on Windows).

- **One component may change** (e.g. a new disk): at least 3 of 4 must still match.
- Components with placeholder serials (`To be filled by O.E.M.`, `Default string`) count as unreadable and never as a match.
- Deliberately **not** used because they change while the computer stays the same: MAC address (VPNs, docks), Windows build number (updates), computer name, BIOS version (firmware updates).

### Protection against clock tampering

- A license is refused if the system date is **earlier than its issue date**.
- The application remembers the last time it saw the clock (in a sealed state file) and refuses to run if the clock **moves back** more than 10 minutes.
- When online, the clock is compared with NTP servers (5-minute tolerance, checked at most once per hour). Offline use keeps working.

### Extending a license

The vendor ticks *Extend from the current expiry date* in the generator, so the new days are added after the old expiry. The application keeps every valid key and uses the one that lasts longest.

---

## Project structure

| File | Role | Ships to customers? |
|---|---|---|
| `license_core.py` | Pure logic: hardware ID format, signing, verification, rules. No Qt, no Windows, no I/O | ✅ |
| `hardware_id.py` | Reads the hardware components (WMI on Windows, fallback elsewhere) | ✅ |
| `security_system.py` | `SecureLicenseManager`: what the application calls | ✅ |
| `public_key.py` | The vendor's public key, embedded in the code | ✅ |
| `word_replacer.py` | Example protected application (replaces a word in `.docx` files) | ✅ |
| `generate_keys.py` | One-time setup: creates the key pair | ❌ vendor only |
| `keygen.py` | GUI license generator | ❌ vendor only |
| `vendor_private_key.pem` | The private key (git-ignored, optionally passphrase-encrypted) | ❌ **never** |
| `test_license.py` | 27 unit tests | ❌ |

---

## Getting started

```bash
pip install -r requirements.txt

python generate_keys.py      # 1. once: creates vendor_private_key.pem and public_key.py
python word_replacer.py      # 2. the app shows its Hardware ID and asks for a key
python keygen.py             # 3. paste the Hardware ID, choose the days, copy the key
python -m unittest -v test_license
```

### Integrating into your own application

```python
from security_system import SecureLicenseManager

license_manager = SecureLicenseManager()

status = license_manager.status()        # LicenseStatus(valid, message, days_left, expires)
if not status.valid:
    print(status.message)                # e.g. "License expired on 2026-12-13"
    print(license_manager.get_hardware_id())
    ok, message = license_manager.save_license(input("License key: "))
```

---

## Tests

`test_license.py` runs anywhere (no Windows, no Qt, no network): keys, hardware IDs and the clock are injected.

It covers: signature round-trip, keys from another vendor, edited payloads, malformed keys, hardware tolerance (1 change accepted, 2 rejected), placeholder serials, expiry, clock earlier than issue date, clock moved back, small clock adjustments, extension, **surviving an application restart**, tampering with the state file, and encrypted private keys.

---

## Why version 2: what I found in my own v1

Version 1 ([tag `v1-legacy`](https://github.com/mmereu97/hardware-license-key-system/tree/v1-legacy)) looked secure on paper (RSA-2048, AES-256, SHA-256, NTP) but a review showed the cryptography was protecting the wrong things:

| v1 | Problem | v2 |
|---|---|---|
| Key = `sha256(hardware ID : date : days : secret)` | The secret had to be inside the application, so anyone who unpacked the `.exe` could generate licenses | Ed25519 signatures: the application only has the public key |
| RSA key generated at each start (later saved in `rsa_key.dat` next to `license.dat`) | First the license did not survive a restart; then the decryption key sat next to the encrypted file, so the license could be decrypted, edited and re-encrypted | Nothing secret is stored on the client; the license itself is signed and cannot be edited |
| `eval()` on the decrypted license data | Arbitrary code execution from a data file | Plain JSON |
| Device key from computer name and Windows version | A Windows update or renaming the PC broke the license | Stable components only, 3 of 4 must match |
| A key was valid only on the day it was generated | A customer activating the next day got "invalid key" | Explicit issue and expiry dates in the signed payload |
| NTP required | No internet = no application | NTP when available, plus local clock rollback detection |

---

## Security model, honestly

This makes **forging a license** infeasible without the private key. It does not, and no offline scheme can, stop a determined attacker from **patching the license check out of the binary**. For that, add code obfuscation or compilation (e.g. Nuitka instead of PyInstaller), or move value to a server the application needs.

Keep `vendor_private_key.pem` backed up and offline, protect it with a passphrase, and never commit it (`.gitignore` already excludes `*.pem`).

---

## Author

Mihai Mereu · [GitHub](https://github.com/mmereu97)
