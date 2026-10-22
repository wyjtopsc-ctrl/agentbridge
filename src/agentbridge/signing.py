"""Ed25519 signatures, implemented in pure Python so the package stays dependency-free.

This is the reference algorithm from RFC 8032, not a fast implementation. Signing and
verification take a few milliseconds, which is irrelevant for a commitment ledger and
avoids a dependency that would break the "pip install pulls in nothing" property.

Correctness is checked two ways:
  * tests/run_identity_tests.py — deterministic vectors and end-to-end flows
  * tests/crosscheck_signing.py — byte-for-byte agreement with the official `cryptography`
    package (run it under a venv that has it installed)

Security note: pure-Python signing is not constant-time. For a filesystem-local ledger whose
threat model is "a local user who can already read the files", this is not the weak link.
Do not lift this module into a network-facing service without replacing it with libsodium.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets

ALG = "ed25519"

Q = 2 ** 255 - 19
L = 2 ** 252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, Q - 2, Q)) % Q
I = pow(2, (Q - 1) // 4, Q)


# ── field / point arithmetic ─────────────────────────────────────────────────

def _inv(x: int) -> int:
    return pow(x, Q - 2, Q)


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * _inv(D * y * y + 1) % Q
    x = pow(xx, (Q + 3) // 8, Q)
    if (x * x - xx) % Q != 0:
        x = (x * I) % Q
    if x % 2 != 0:
        x = Q - x
    return x


_BY = 4 * _inv(5) % Q
_BX = _xrecover(_BY)
_B = (_BX % Q, _BY % Q, 1, (_BX * _BY) % Q)


def _add(p, q):
    (x1, y1, z1, t1), (x2, y2, z2, t2) = p, q
    a = (y1 - x1) * (y2 - x2) % Q
    b = (y1 + x1) * (y2 + x2) % Q
    c = t1 * 2 * D * t2 % Q
    d = z1 * 2 * z2 % Q
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % Q, g * h % Q, f * g % Q, e * h % Q)


def _double(p):
    x1, y1, z1, t1 = p
    a = x1 * x1 % Q
    b = y1 * y1 % Q
    c = 2 * z1 * z1 % Q
    h = a + b
    e = h - pow(x1 + y1, 2, Q)
    g = a - b
    f = c + g
    return (e * f % Q, g * h % Q, f * g % Q, e * h % Q)


def _scalarmult(p, e: int):
    result = (0, 1, 1, 0)                      # neutral element
    addend = p
    while e > 0:
        if e & 1:
            result = _add(result, addend)
        addend = _double(addend)
        e >>= 1
    return result


def _encode_point(p) -> bytes:
    x, y, z, _ = p
    zi = _inv(z)
    x, y = x * zi % Q, y * zi % Q
    bits = (y & ((1 << 255) - 1)) | ((x & 1) << 255)
    return bits.to_bytes(32, "little")


def _decode_point(s: bytes):
    if len(s) != 32:
        raise ValueError("point must be 32 bytes")
    bits = int.from_bytes(s, "little")
    y = bits & ((1 << 255) - 1)
    sign = (bits >> 255) & 1
    if y >= Q:
        raise ValueError("non-canonical point")
    x = _xrecover(y)
    if (x & 1) != sign:
        x = Q - x
    p = (x, y, 1, x * y % Q)
    zi = _inv(p[2])
    xr, yr = p[0] * zi % Q, p[1] * zi % Q
    if (-xr * xr + yr * yr - 1 - D * xr * xr * yr * yr) % Q != 0:
        raise ValueError("point not on curve")
    return p


def _clamp(h32: bytes) -> int:
    a = int.from_bytes(h32, "little")
    a &= (1 << 254) - 8
    a |= (1 << 254)
    return a


# ── key operations ───────────────────────────────────────────────────────────

def generate_seed() -> bytes:
    return secrets.token_bytes(32)


def public_key(seed: bytes) -> bytes:
    if len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    h = hashlib.sha512(seed).digest()
    return _encode_point(_scalarmult(_B, _clamp(h[:32])))


def sign(seed: bytes, message: bytes) -> bytes:
    h = hashlib.sha512(seed).digest()
    a = _clamp(h[:32])
    prefix = h[32:]
    pub = _encode_point(_scalarmult(_B, a))
    r = int.from_bytes(hashlib.sha512(prefix + message).digest(), "little") % L
    r_point = _encode_point(_scalarmult(_B, r))
    k = int.from_bytes(hashlib.sha512(r_point + pub + message).digest(), "little") % L
    s = (r + k * a) % L
    return r_point + s.to_bytes(32, "little")


def verify(pub: bytes, message: bytes, signature: bytes) -> bool:
    if len(pub) != 32 or len(signature) != 64:
        return False
    try:
        a_point = _decode_point(pub)
        r_point = _decode_point(signature[:32])
    except ValueError:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= L:
        return False
    k = int.from_bytes(hashlib.sha512(signature[:32] + pub + message).digest(), "little") % L
    return _encode_point(_scalarmult(_B, s)) == _encode_point(_add(r_point, _scalarmult(a_point, k)))


# ── signer identity ──────────────────────────────────────────────────────────

class Signer:
    """An actor's key material. The private seed never leaves this object."""

    def __init__(self, actor: str, seed: bytes, pub: bytes | None = None):
        if len(seed) != 32:
            raise ValueError("seed must be 32 bytes")
        self.actor = actor
        self._seed = seed
        self.pub = pub or public_key(seed)
        if public_key(seed) != self.pub:
            raise ValueError("public key does not match the seed")

    @property
    def pub_hex(self) -> str:
        return self.pub.hex()

    def sign_hex(self, message: bytes) -> str:
        return sign(self._seed, message).hex()

    def to_dict(self) -> dict:
        """Key material for a key file. Treat the result as a secret."""
        return {"alg": ALG, "actor": self.actor,
                "seed_hex": self._seed.hex(), "pub_hex": self.pub_hex}

    def __repr__(self) -> str:
        return f"Signer(actor={self.actor!r}, pub={self.pub_hex[:12]}…)"


def new_signer(actor: str) -> Signer:
    return Signer(actor, generate_seed())


def signer_from_dict(data: dict) -> Signer:
    if data.get("alg") != ALG:
        raise ValueError(f"unsupported key algorithm: {data.get('alg')!r}")
    return Signer(actor=data["actor"], seed=bytes.fromhex(data["seed_hex"]),
                  pub=bytes.fromhex(data["pub_hex"]) if data.get("pub_hex") else None)


def save_keyfile(signer: Signer, path: str, force: bool = False) -> None:
    if os.path.exists(path) and not force:
        raise FileExistsError(f"refusing to overwrite existing key file: {path}")
    payload = json.dumps(signer.to_dict(), indent=2) + "\n"
    fd = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_EXCL if not force else os.O_CREAT | os.O_WRONLY,
                 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(payload)
        f.flush()
        os.fsync(f.fileno())


def load_keyfile(path: str) -> Signer:
    with open(path, encoding="utf-8") as f:
        return signer_from_dict(json.load(f))


def fingerprint(pub_hex: str) -> str:
    """Short, stable identifier for a public key; what a human can compare out loud."""
    try:
        raw = bytes.fromhex(pub_hex)
    except (ValueError, TypeError):
        raise ValueError("public key is not hex")
    return "sha256:" + hashlib.sha256(raw).hexdigest()[:16]


def verify_hex(pub_hex: str, message: bytes, sig_hex: str) -> bool:
    try:
        return verify(bytes.fromhex(pub_hex), message, bytes.fromhex(sig_hex))
    except (ValueError, TypeError):
        return False
