"""Minimal JCS-style canonicalization shared by the reference verifier and fixture generator.

Scope (documented in docs/evidence-pack-freeze-blockers.md): UTF-8, object keys sorted by UTF-16
code units, no floats (safe integers only), no duplicate keys on input, strings emitted as JSON
without normalization. This is deliberately narrow: full RFC 8785 number/string coverage is not
claimed for v0.
"""
from __future__ import annotations

import json


def _encode(value) -> bytes:
    if value is True:
        return b"true"
    if value is False:
        return b"false"
    if value is None:
        return b"null"
    if isinstance(value, int):
        if abs(value) > 2 ** 53 - 1:
            raise ValueError("integer outside safe range")
        return str(value).encode("ascii")
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if isinstance(value, list):
        return b"[" + b",".join(_encode(v) for v in value) + b"]"
    if isinstance(value, dict):
        items = sorted(value.items(), key=lambda kv: kv[0].encode("utf-16-be"))
        return b"{" + b",".join(_encode(k) + b":" + _encode(v) for k, v in items) + b"}"
    raise TypeError(f"unsupported canonical type: {type(value).__name__}")


def canonical_bytes(value) -> bytes:
    return _encode(value)


def loads_strict(text: str):
    """JSON load that rejects duplicate keys, floats and non-finite numbers."""
    def no_dup(pairs):
        out = {}
        for k, v in pairs:
            if k in out:
                raise ValueError(f"duplicate key: {k!r}")
            out[k] = v
        return out

    def reject_float(token):
        raise ValueError(f"non-integer number: {token}")

    def reject_constant(token):
        raise ValueError(f"non-finite number: {token}")

    return json.loads(text, object_pairs_hook=no_dup,
                      parse_float=reject_float, parse_constant=reject_constant)
