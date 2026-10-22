#!/usr/bin/env python3
"""Identity-layer tests: Ed25519 keys, signed entries, signed envelopes, actor registry.

  PYTHONPATH=src python3 tests/run_identity_tests.py [-v]
"""
from __future__ import annotations

import json
import os
import secrets
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(os.path.dirname(HERE), "src")
VERBOSE = "-v" in sys.argv
if SRC not in sys.path:
    sys.path.insert(0, SRC)

from agentbridge import signing  # noqa: E402

CASES = []


def case(fn):
    CASES.append(fn)
    return fn


def run(root, *args, key=None, expect=0):
    env = dict(os.environ, PYTHONPATH=SRC)
    cmd = [sys.executable, "-m", "agentbridge", "--root", root]
    if key:
        cmd += ["--key", key]
    cmd += list(args)
    p = subprocess.run(cmd, capture_output=True, text=True, env=env)
    out = (p.stdout or "") + (p.stderr or "")
    if VERBOSE:
        print(f"    $ {' '.join(cmd[3:])} -> {p.returncode}\n{out.strip()[:400]}")
    if expect is not None and p.returncode != expect:
        raise AssertionError(f"expected rc={expect}, got {p.returncode}\n{out}")
    return p.returncode, out


def setup():
    d = tempfile.mkdtemp(prefix="agentbridge-id.")
    root = os.path.join(d, "bridge")
    run(root, "keygen", "--actor", "planner", "--out", d)
    run(root, "keygen", "--actor", "worker", "--out", d)
    run(root, "init", "--actor", "planner")
    return d, root, os.path.join(d, "planner.key"), os.path.join(d, "worker.key")


@case
def I1_keypair_roundtrip_and_vectors():
    seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    pub = signing.public_key(seed)
    sig = signing.sign(seed, b"")
    # RFC 8032 §7.1 test vector 1 (empty message)
    assert pub.hex() == "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", pub.hex()
    assert sig.hex() == ("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
                         "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"), sig.hex()
    assert signing.verify(pub, b"", sig)

    d, _, kp, _ = setup()
    s = signing.load_keyfile(kp)
    assert s.pub_hex == signing.public_key(s._seed).hex()
    assert signing.verify(s.pub, b"hello", signing.sign(s._seed, b"hello"))


@case
def I2_signature_rejects_tampering():
    s = signing.new_signer("alice")
    msg, sig = b"payload", signing.sign(s._seed, b"payload")
    assert signing.verify(s.pub, msg, sig)
    assert not signing.verify(s.pub, b"payloaX", sig)
    assert not signing.verify(s.pub, msg, b"\x00" * 64)
    assert not signing.verify(s.pub, msg, sig[:63])
    other = signing.new_signer("mallory")
    assert not signing.verify(other.pub, msg, sig)


@case
def I3_signed_bridge_verifies():
    d, root, kp, kw = setup()
    run(root, "--key", kp, "register") if False else run(root, "register", key=kp)
    art = os.path.join(d, "a.txt")
    open(art, "w").write("hello\n")
    _, out = run(root, "send", "--to", "worker", "--body", "review", "--attach", art, key=kp)
    req = json.loads(out[out.index("{"):])["id"]
    run(root, "register", key=kw)
    run(root, "deliver", "--to", "planner", "--in-reply-to", req, "--body", "done", key=kw)
    code, out = run(root, "verify")
    assert code == 0, out
    assert "0 failing" in out


@case
def I4_unsigned_write_after_registration_fails():
    d, root, kp, kw = setup()
    run(root, "register", key=kp)
    run(root, "send", "--actor", "planner", "--to", "worker", "--body", "unsigned")  # no --key
    code, out = run(root, "verify", expect=1)
    assert "unsigned ledger entry" in out, out


@case
def I5_unregistered_actor_is_rejected():
    d, root, kp, kw = setup()
    run(root, "register", key=kp)
    run(root, "send", "--actor", "mallory", "--to", "worker", "--body", "x")
    code, out = run(root, "verify", expect=1)
    assert "not registered" in out, out


@case
def I6_key_rotation_is_detected():
    d, root, kp, kw = setup()
    run(root, "register", key=kp)
    # a second key claiming the same actor is refused; rotation must go through `rotate`
    run(root, "keygen", "--actor", "planner", "--out", os.path.join(d, "second"))
    code, out = run(root, "register", key=os.path.join(d, "second", "planner.key"), expect=1)
    assert "already registered" in out and "rotate" in out, out
    run(root, "verify", expect=0)


@case
def I7_forged_signing_key_is_detected():
    d, root, kp, kw = setup()
    run(root, "register", key=kp)
    run(root, "keygen", "--actor", "planner", "--out", os.path.join(d, "other"))
    other_pub = signing.load_keyfile(os.path.join(d, "other", "planner.key")).pub_hex
    run(root, "send", "--to", "worker", "--body", "signed", key=kp)
    # swap sig_pub for a valid key that is not in the registry: digest excludes sig_pub,
    # so only the signature check can catch this
    ledger = os.path.join(root, "ledger.jsonl")
    lines = open(ledger).read().splitlines()
    entry = json.loads(lines[-1])
    entry["sig_pub"] = other_pub
    lines[-1] = json.dumps(entry, ensure_ascii=False, sort_keys=True)
    open(ledger, "w").write("\n".join(lines) + "\n")
    code, out = run(root, "verify", expect=1)
    assert "active key" in out or "does not match" in out, out


@case
def I8_envelope_signature_is_checked():
    d, root, kp, kw = setup()
    run(root, "register", key=kp)
    art = os.path.join(d, "a.txt")
    open(art, "w").write("x\n")
    _, out = run(root, "send", "--to", "worker", "--body", "review", "--attach", art, key=kp)
    req = json.loads(out[out.index("{"):])["id"]
    env_path = os.path.join(root, "wire", "outbox", f"{req}.json")
    env = json.load(open(env_path))
    # rewrite the signature only: envelope bytes still hash to the recorded envelope_sha256?
    # no — the envelope digest covers the signature, so this must fail the envelope hash first.
    env["signature"]["sig"] = "00" * 64
    json.dump(env, open(env_path, "w"), ensure_ascii=False)
    code, out = run(root, "verify", expect=1)
    assert "envelope content changed" in out, out


@case
def I9_pre_registration_history_is_exempt():
    d, root, kp, kw = setup()
    run(root, "send", "--to", "worker", "--body", "before keys")   # unsigned, before registration
    run(root, "register", key=kp)
    run(root, "send", "--to", "worker", "--body", "after keys", key=kp)
    code, out = run(root, "verify")
    assert code == 0, out


@case
def I10_unsigned_bridge_still_works():
    d = tempfile.mkdtemp(prefix="agentbridge-id.")
    root = os.path.join(d, "bridge")
    run(root, "init", "--actor", "planner")
    run(root, "send", "--to", "worker", "--body", "no keys at all")
    code, out = run(root, "verify")
    assert code == 0, out


@case
def I11_actors_listing_and_verification_report():
    d, root, kp, kw = setup()
    run(root, "register", key=kp)
    run(root, "register", key=kw)
    _, out = run(root, "actors", "--json", expect=0)
    actors = json.loads(out[out.index("["):])
    assert [a["actor"] for a in actors] == ["planner", "worker"], actors
    assert all(a["fingerprint"].startswith("sha256:") for a in actors), actors
    assert actors[0]["registered_seq"] < actors[1]["registered_seq"], actors

    from agentbridge import Bridge
    report = Bridge(root).verify()
    assert report.actors == ["planner", "worker"], report.actors
    assert report.anchor_level == "local_only", report.anchor_level


def main() -> int:
    failed = 0
    for fn in CASES:
        try:
            fn()
            print(f"PASS  {fn.__name__}")
        except AssertionError as exc:
            failed += 1
            print(f"FAIL  {fn.__name__}: {exc}")
        except Exception as exc:  # noqa: BLE001 - report, don't mask
            failed += 1
            print(f"ERROR {fn.__name__}: {type(exc).__name__}: {exc}")
    print(f"\n{len(CASES) - failed}/{len(CASES)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
