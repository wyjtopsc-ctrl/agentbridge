#!/usr/bin/env python3
"""Independent cross-check of the fixed vectors.

Deliberately does NOT import packjcs or agentbridge.signing: uses its own canonicalizer and
cryptography's Ed25519 implementation, so a shared bug in generator+verifier cannot hide here.
Run with the venv that has cryptography installed: .venv/bin/python tools/crosscheck_vectors.py
"""
from __future__ import annotations

import hashlib
import json
import os
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FIX = os.path.join(ROOT, "docs", "fixtures", "evidence-pack-v0")
DOMAIN = b"agentbridge-evidence/0.1\n"


def canon(value) -> bytes:
    if value is None:
        return b"null"
    if value is True:
        return b"true"
    if value is False:
        return b"false"
    if isinstance(value, int):
        return str(value).encode()
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()
    if isinstance(value, list):
        return b"[" + b",".join(canon(v) for v in value) + b"]"
    if isinstance(value, dict):
        items = sorted(value.items(), key=lambda kv: kv[0].encode("utf-16-be"))
        return b"{" + b",".join(canon(k) + b":" + canon(v) for k, v in items) + b"}"
    raise TypeError(type(value))


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify(pub_hex: str, sig_hex: str, message: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex)).verify(
            bytes.fromhex(sig_hex), message)
        return True
    except InvalidSignature:
        return False


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def check(name: str):
    pack = os.path.join(FIX, name)
    manifest = load(os.path.join(pack, "manifest.json"))
    res = {"files": True, "manifest_sig": True, "chain": True, "entry_sigs": True,
           "envelope_sigs": True, "acceptance_sig": True, "status_sig": True,
           "receipt_sig": True, "binding": True}

    for item in manifest["signed_files"]:
        path = os.path.join(pack, item["path"])
        if not os.path.isfile(path) or sha(open(path, "rb").read()) != item["sha256"]:
            res["files"] = False

    sig = manifest["signatures"]["exporter"]
    body = {k: v for k, v in manifest.items() if k != "signatures"}
    res["manifest_sig"] = verify(sig["pub"], sig["sig"], DOMAIN + b"manifest\n" + canon(body))

    entries = [json.loads(line) for line in
               open(os.path.join(pack, manifest["ledger"]["path"]), encoding="utf-8")
               if line.strip()]
    prev = "GENESIS"
    for i, e in enumerate(entries):
        body = {k: v for k, v in e.items() if k not in ("digest", "sig", "sig_pub")}
        if sha(canon(body)) != e.get("digest"):
            res["chain"] = False
        if e.get("type") != "genesis":
            if e.get("seq") != i or e.get("prev") != prev:
                res["chain"] = False
        prev = e.get("digest")
        if e.get("sig") and not verify(e["sig_pub"], e["sig"], str(e["digest"]).encode()):
            res["entry_sigs"] = False

    for env_ref in manifest["envelopes"]:
        env = load(os.path.join(pack, env_ref["path"]))
        sig = env["signature"]
        body = {k: v for k, v in env.items() if k != "signature"}
        if not verify(sig["pub"], sig["sig"], canon(body)):
            res["envelope_sigs"] = False

    for acc in manifest.get("acceptances", []):
        rec = load(os.path.join(pack, acc["record_path"]))
        sig = rec["signature"]
        body = {k: v for k, v in rec.items() if k != "signature"}
        if not verify(sig["pub"], sig["sig"], DOMAIN + b"acceptance-record\n" + canon(body)):
            res["acceptance_sig"] = False

    st = load(os.path.join(pack, manifest["identity"]["status"]["path"]))
    body = {k: v for k, v in st.items() if k != "signature"}
    if not verify(st["publisher_pub"], st["signature"]["sig"], DOMAIN + b"status\n" + canon(body)):
        res["status_sig"] = False

    for anchor in manifest.get("anchors", []):
        receipt = load(os.path.join(pack, anchor["path"]))
        body = {k: v for k, v in receipt.items() if k != "service_sig"}
        if not verify(receipt["service_pub"], receipt["service_sig"], canon(body)):
            res["receipt_sig"] = False

    # binding: ledger entry hash must equal the envelope file hash
    for delivery in manifest["deliveries"]:
        entry = entries[delivery["ledger_seq"]]
        env_path = os.path.join(pack, delivery["envelope_path"])
        if entry.get("envelope_sha256") != sha(open(env_path, "rb").read()):
            res["binding"] = False
    return res


EXPECTED = {
    "normal": {"files": True, "manifest_sig": True, "chain": True, "entry_sigs": True,
               "envelope_sigs": True, "acceptance_sig": True, "status_sig": True,
               "receipt_sig": True, "binding": True},
    "tampered-sig": {"files": True, "manifest_sig": True, "chain": True, "entry_sigs": True,
                     "envelope_sigs": False, "acceptance_sig": True, "status_sig": True,
                     "receipt_sig": True, "binding": False},
    "tampered-binding": {"files": True, "manifest_sig": True, "chain": True, "entry_sigs": True,
                         "envelope_sigs": True, "acceptance_sig": True, "status_sig": True,
                         "receipt_sig": True, "binding": False},
    "missing-evidence": {"files": True, "manifest_sig": True, "chain": True, "entry_sigs": True,
                         "envelope_sigs": True, "acceptance_sig": True, "status_sig": True,
                         "receipt_sig": True, "binding": True},
    "forged-selfconsistent": {"files": True, "manifest_sig": True, "chain": True,
                              "entry_sigs": True, "envelope_sigs": True,
                              "acceptance_sig": True, "status_sig": True,
                              "receipt_sig": True, "binding": True},
}


def main() -> int:
    cases = [n for n in sorted(os.listdir(FIX)) if os.path.isdir(os.path.join(FIX, n))
             and n not in ("trust", "schema-invalid")]
    failures = 0
    for name in cases:
        got = check(name)
        expected = EXPECTED.get(name)
        if expected is None:
            expected = {k: True for k in got}
        bad = {k: (got[k], expected.get(k)) for k in got if got[k] != expected.get(k)}
        ok = not bad
        failures += 0 if ok else 1
        print(("PASS  " if ok else "FAIL  ") + name)
        for key, (g, e) in bad.items():
            print(f"   {key}: independent={g} expected={e}")
    print(f"\n{len(cases) - failures}/{len(cases)} vectors cross-checked independently")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
