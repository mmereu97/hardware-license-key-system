"""One-time vendor setup: create the Ed25519 key pair.

    python generate_keys.py

Writes:
  vendor_private_key.pem   KEEP SECRET, never commit, never ship (git-ignored).
                           Optionally encrypted with a passphrase.
  public_key.py            the public key, embedded in the application.

Running it again creates a NEW pair: licenses signed with the old private key
stop working in builds that embed the new public key.
"""
from __future__ import annotations

import getpass
import sys
from pathlib import Path

from license_core import generate_keypair

HERE = Path(__file__).resolve().parent
PRIVATE_KEY_FILE = HERE / "vendor_private_key.pem"
PUBLIC_KEY_MODULE = HERE / "public_key.py"

TEMPLATE = '''"""The vendor's PUBLIC key, embedded in the application.

`python generate_keys.py` rewrites this file. The public key can only VERIFY
licenses; publishing it is safe. It is compiled into the application instead of
being read from a file next to it, so a user cannot simply swap in their own key.
"""

PUBLIC_KEY_PEM = b"""{pem}"""
'''


def main() -> int:
    if PRIVATE_KEY_FILE.exists():
        answer = input(f"{PRIVATE_KEY_FILE.name} already exists. Replace it and invalidate all issued licenses? [y/N] ")
        if answer.strip().lower() != "y":
            print("Nothing changed.")
            return 1

    passphrase = getpass.getpass("Passphrase for the private key (Enter for none): ")
    if passphrase and passphrase != getpass.getpass("Repeat passphrase: "):
        print("Passphrases do not match. Nothing changed.")
        return 1

    private_pem, public_pem = generate_keypair(passphrase.encode() if passphrase else None)
    PRIVATE_KEY_FILE.write_bytes(private_pem)
    PUBLIC_KEY_MODULE.write_text(TEMPLATE.format(pem=public_pem.decode().strip()), encoding="utf-8")

    print(f"Private key: {PRIVATE_KEY_FILE}  (back it up somewhere safe, do not commit it)")
    print(f"Public key:  {PUBLIC_KEY_MODULE}  (rebuild the application to embed it)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
