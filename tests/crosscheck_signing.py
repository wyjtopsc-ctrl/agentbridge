#!/usr/bin/env python3
"""Cross-check the pure-Python Ed25519 implementation against the official `cryptography` package.

    python3.11 -m venv .venv
    .venv/bin/pip install cryptography
    PYTHONPATH=src .venv/bin/python tests/crosscheck_signing.py

Byte-for-byte agreement is the goal: same seed -> same public key -> same deterministic signature.
"""
from __future__ import annotations

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(os.path.dirname(HERE), "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

from agentbridge import signing  # noqa: E402

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey, Ed25519PublicKey)
except ImportError:  # pragma: no cover - optional dependency
    sys.stderr.write("crosscheck: the 'cryptography' package is not installed in this interpreter\n"
                     "  python3.11 -m venv .venv && .venv/bin/pip install cryptography\n")
    sys.exit(2)


def raw_public(key) -> bytes:
    try:
        return key.public_bytes_raw()
    except AttributeError:                       # older cryptography
        from cryptography.hazmat.primitives import serialization
        return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def main() -> int:
    failures = []
    checks = 0
    for i in range(64):
        seed = os.urandom(32)
        message = os.urandom(i * 3)
        ref_key = Ed25519PrivateKey.from_private_bytes(seed)
        ref_pub = raw_public(ref_key.public_key())

        ours_pub = signing.public_key(seed)
        checks += 1
        if ours_pub != ref_pub:
            failures.append(f"seed {i}: public key mismatch")

        ref_sig = ref_key.sign(message)
        our_sig = signing.sign(seed, message)
        checks += 1
        if our_sig != ref_sig:
            failures.append(f"seed {i}: signature mismatch (deterministic Ed25519 should agree)")

        checks += 1
        if not signing.verify(ref_pub, message, ref_sig):
            failures.append(f"seed {i}: we reject a signature made by cryptography")

        checks += 1
        try:
            Ed25519PublicKey.from_public_bytes(ours_pub).verify(our_sig, message)
        except InvalidSignature:
            failures.append(f"seed {i}: cryptography rejects our signature")

        checks += 1
        if signing.verify(ref_pub, message + b"x", ref_sig):
            failures.append(f"seed {i}: we accepted a signature for a different message")

    # malformed inputs must not raise
    checks += 1
    try:
        assert not signing.verify(b"\x00" * 32, b"m", b"\x00" * 64)
        assert not signing.verify(b"\x00" * 31, b"m", b"\x00" * 64)
        assert not signing.verify(b"\x00" * 32, b"m", b"\x00" * 63)
        assert not signing.verify(os.urandom(32), b"m", os.urandom(64))
    except Exception as exc:                     # noqa: BLE001
        failures.append(f"malformed input raised: {exc}")

    for f in failures:
        print(f"FAIL  {f}")
    print(f"\n{checks} comparison(s), {len(failures)} failure(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
