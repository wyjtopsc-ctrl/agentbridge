"""JCS-style canonical JSON for new evidence-protocol objects (v0.1).

Deliberately narrow: UTF-8, object keys sorted by UTF-16 code units, safe integers only, no
duplicate keys. Strings are emitted without Unicode normalization; new records are checked for
NFC at creation time instead.
"""
from __future__ import annotations

import json
import unicodedata


def canonical_bytes(value) -> bytes:
    if value is None:
        return b"null"
    if value is True:
        return b"true"
    if value is False:
        return b"false"
    if isinstance(value, int):
        if abs(value) > 2 ** 53 - 1:
            raise ValueError("integer outside safe range")
        return str(value).encode("ascii")
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if isinstance(value, list):
        return b"[" + b",".join(canonical_bytes(v) for v in value) + b"]"
    if isinstance(value, dict):
        items = sorted(value.items(), key=lambda kv: kv[0].encode("utf-16-be"))
        return b"{" + b",".join(canonical_bytes(k) + b":" + canonical_bytes(v) for k, v in items) + b"}"
    raise TypeError(f"unsupported canonical type: {type(value).__name__}")


def loads_strict(text: str):
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

    return json.loads(text, object_pairs_hook=no_dup, parse_float=reject_float,
                      parse_constant=reject_constant)


def is_nfc(value) -> bool:
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value) == value
    if isinstance(value, list):
        return all(is_nfc(v) for v in value)
    if isinstance(value, dict):
        return all(is_nfc(k) and is_nfc(v) for k, v in value.items())
    return True
