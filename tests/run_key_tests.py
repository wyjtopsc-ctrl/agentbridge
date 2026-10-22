#!/usr/bin/env python3
"""Key lifecycle tests (K1): rotation, revocation, active-key enforcement, history preservation."""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "src"))

from agentbridge import signing  # noqa: E402
from agentbridge.core import Bridge, Refused  # noqa: E402

CASES = []


def case(fn):
    CASES.append(fn)
    return fn


def setup():
    d = tempfile.mkdtemp(prefix="agentbridge-key.")
    old = signing.Signer("client", b"\x22" * 32)
    b = Bridge(d, old)
    b.init(actor="client")
    b.register_actor("client", old.pub_hex)
    return d, b, old


@case
def K1_rotation_switches_the_active_key():
    d, b, old = setup()
    try:
        new = signing.Signer("client", b"\x66" * 32)
        entry = b.rotate_key(new, reason="routine rotation")
        assert entry["type"] == "rotate"
        assert entry["old_pub"] == old.pub_hex and entry["new_pub"] == new.pub_hex
        assert entry.get("new_sig")
        report = b.verify()
        assert report.ok, report.problems
        status = b.key_status()
        assert status["current"]["client"] == new.pub_hex
        assert len(status["rotations"]) == 1
    finally:
        shutil.rmtree(d)


@case
def K2_new_key_can_write_old_key_cannot():
    d, b, old = setup()
    try:
        new = signing.Signer("client", b"\x66" * 32)
        b.rotate_key(new, reason="rotate")
        b2 = Bridge(d, new)
        b2.send(actor="client", to="worker", body="after rotation")
        assert b2.verify().ok
        try:
            b.send(actor="client", to="worker", body="stale key")
            raise AssertionError("old key must not be able to write after rotation")
        except Refused:
            pass
    finally:
        shutil.rmtree(d)


@case
def K3_rotation_requires_the_new_key_proof():
    d, b, old = setup()
    try:
        new = signing.Signer("client", b"\x66" * 32)
        entry = b.build_entry({"type": "rotate", "actor": "client",
                               "old_pub": old.pub_hex, "new_pub": new.pub_hex,
                               "reason": "no proof", "protocol_version": "0.1"})
        try:
            b.append_entry(entry)              # no new_sig
            raise AssertionError("rotation without the new key's proof must be refused")
        except Refused:
            pass
        entry["new_sig"] = new.sign_hex(entry["digest"].encode())
        b.append_entry(entry)
        assert b.verify().ok
    finally:
        shutil.rmtree(d)


@case
def K4_revocation_keeps_history_valid_and_blocks_writes():
    d, b, old = setup()
    try:
        before = len(b.entries())
        entry = b.revoke_key("normal_retirement", evidence="employee departure")
        assert entry["kind"] == "normal_retirement"
        report = b.verify()
        assert report.ok, report.problems
        assert len(b.entries()) == before + 1
        assert report.key_status and report.key_status[0]["kind"] == "normal_retirement"
        try:
            b.send(actor="client", to="worker", body="after revoke")
            raise AssertionError("revoked key must not write")
        except Refused:
            pass
    finally:
        shutil.rmtree(d)


@case
def K5_suspected_compromise_is_reported_but_history_stays():
    d, b, old = setup()
    try:
        b.revoke_key("suspected_compromise", effective_at="2026-10-21T12:00:00+08:00",
                     suspected_leak_at="2026-10-21T11:00:00+08:00", evidence="ticket 42")
        report = b.verify()
        assert report.ok, report.problems
        status = b.key_status()
        rev = status["revocations"][0]
        assert rev["kind"] == "suspected_compromise"
        assert rev["suspected_leak_at"] == "2026-10-21T11:00:00+08:00"
    finally:
        shutil.rmtree(d)


@case
def K6_rotation_tampering_is_detected():
    d, b, old = setup()
    try:
        new = signing.Signer("client", b"\x66" * 32)
        b.rotate_key(new, reason="rotate")
        ledger = os.path.join(d, "ledger.jsonl")
        lines = open(ledger).read().splitlines()
        entry = json.loads(lines[-1])
        entry["new_pub"] = signing.Signer("client", b"\x77" * 32).pub_hex
        lines[-1] = json.dumps(entry, ensure_ascii=False, sort_keys=True)
        open(ledger, "w").write("\n".join(lines) + "\n")
        report = b.verify()
        assert not report.ok
        assert any("digest mismatch" in p or "proof" in p for p in report.problems), report.problems
    finally:
        shutil.rmtree(d)


@case
def K8_revoked_key_cannot_rotate():
    d, b, old = setup()
    try:
        b.revoke_key("normal_retirement")
        try:
            b.rotate_key(signing.Signer("client", b"\x66" * 32), reason="after revoke")
            raise AssertionError("a revoked key must not authorize a rotation")
        except Refused:
            pass
    finally:
        shutil.rmtree(d)


@case
def K7_revoke_rejects_unknown_kind():
    d, b, old = setup()
    try:
        try:
            b.revoke_key("whatever")
            raise AssertionError("unknown revocation kind must be refused")
        except Refused:
            pass
    finally:
        shutil.rmtree(d)


def main() -> int:
    failed = 0
    for fn in CASES:
        try:
            fn()
            print(f"PASS  {fn.__name__}")
        except AssertionError as exc:
            failed += 1
            print(f"FAIL  {fn.__name__}: {exc}")
        except Exception as exc:  # noqa: BLE001
            failed += 1
            print(f"ERROR {fn.__name__}: {type(exc).__name__}: {exc}")
    print(f"\n{len(CASES) - failed}/{len(CASES)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
