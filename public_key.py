"""The vendor's PUBLIC key, embedded in the application.

`python generate_keys.py` rewrites this file. The public key can only VERIFY
licenses; publishing it is safe. It is compiled into the application instead of
being read from a file next to it, so a user cannot simply swap in their own key.
"""

PUBLIC_KEY_PEM = None  # run: python generate_keys.py
