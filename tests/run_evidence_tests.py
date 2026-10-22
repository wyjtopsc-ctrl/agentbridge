#!/usr/bin/env python3
"""Evidence-pack tests: acceptance records, export from a real bridge, offline verification."""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "src"))

from agentbridge import evidence, signing  # noqa: E402
from agentbridge.core import Bridge, NotFound, Refused, bridge_id_of  # noqa: E402
from agentbridge.jcs import canonical_bytes  # noqa: E402

DOMAIN = b"agentbridge-evidence/0.1\n"
CASES = []


def case(fn):
    CASES.append(fn)
    return fn


def fresh():
    d = tempfile.mkdtemp(prefix="agentbridge-evidence.")
    client = signing.Signer("client", b"\x22" * 32)
    worker = signing.Signer("worker", b"\x11" * 32)
    b = Bridge(d, client)
    b.init(actor="client")
    b.register_actor("client", client.pub_hex)
    wb = Bridge(d, worker)
    wb.register_actor("worker", worker.pub_hex)
    req = os.path.join(d, "request.md")
    rep = os.path.join(d, "report.md")
    open(req, "w").write("request\n")
    open(rep, "w").write("report v1\n")
    sent = b.send(actor="client", to="worker", body="do it", intent="review", attach=[req])
    delivered = wb.deliver(actor="worker", to="client", in_reply_to=sent["id"],
                           body="done", attach=[rep])
    return d, b, wb, client, worker, delivered["id"]


def signed_status(seed, published, valid_until, revocations=None):
    st = {"protocol_version": "0.1", "published_at": published,
          "valid_until": valid_until, "publisher_pub": signing.public_key(seed).hex(),
          "revocations": revocations or []}
    st["signature"] = evidence.sign_domain(signing.Signer("status", seed), "status", st)
    return st


def signed_receipt(seed, bridge_id, seq, digest, received_at):
    rc = {"v": 1, "bridge_id": bridge_id, "seq": seq, "digest": digest, "log_index": 0,
          "received_at": received_at, "client_pub": signing.public_key(b"\x22" * 32).hex(),
          "service_pub": signing.public_key(seed).hex(), "prev": ""}
    rc["service_sig"] = signing.sign(seed, canonical_bytes(rc)).hex()
    return rc


def write_json(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)
        f.write("\n")


def make_trust(root, entries, exporter_pub, status_seed, service_seed, delivery_id):
    actors = {e["actor"]: signing.fingerprint(e["pub"]) for e in entries
              if e.get("type") == "actor_register"}
    tip = entries[-1]
    return {
        "expected_bridge_id": bridge_id_of(entries),
        "expected_actors": [{"actor": a, "fingerprint": f} for a, f in actors.items()],
        "expected_exporter": {"actor": "exporter",
                              "fingerprint": signing.fingerprint(exporter_pub)},
        "anchor_service_pubs": [signing.public_key(service_seed).hex()],
        "status_publisher_pub": signing.public_key(status_seed).hex(),
        "max_status_age_hours": 24 * 365 * 50,
        "max_future_skew_seconds": 300,
        "minimum_checkpoint_seq": tip["seq"],
        "known_checkpoint": {"bridge_id": bridge_id_of(entries), "seq": tip["seq"],
                             "digest": tip["digest"]},
        "expected_versions": {delivery_id: "v1"},
    }


@case
def E1_acceptance_record_and_entry():
    d, b, _wb, client, _worker, delivery_id = fresh()
    try:
        out = b.accept_delivery("client", delivery_id, version="v1")
        record = json.load(open(out["record"], encoding="utf-8"))
        assert record["protocol_version"] == "0.2"
        assert record["decision"] == "accepted"
        body = {k: v for k, v in record.items() if k != "signature"}
        payload = DOMAIN + b"acceptance-record\n" + canonical_bytes(body)
        assert signing.verify_hex(record["signature"]["pub"], payload,
                                  record["signature"]["sig"]), "record signature"
        entry = [e for e in b.entries() if e.get("type") == "accept"][0]
        assert entry["record_sha256"] == evidence.sha_file(out["record"])
        assert entry["delivery_id"] == delivery_id
    finally:
        shutil.rmtree(d)


@case
def E2_reject_stores_reason():
    d, b, _wb, _client, _worker, delivery_id = fresh()
    try:
        out = b.accept_delivery("client", delivery_id, decision="rejected",
                                reason="missing tests", version="v1")
        record = json.load(open(out["record"], encoding="utf-8"))
        assert record["decision"] == "rejected" and record["reason"] == "missing tests"
        types = [e.get("type") for e in b.entries()]
        assert "reject" in types
    finally:
        shutil.rmtree(d)


@case
def E3_wrong_actor_refused():
    d, b, wb, _client, _worker, delivery_id = fresh()
    try:
        try:
            wb.accept_delivery("client", delivery_id)
            raise AssertionError("worker must not accept as client")
        except Refused:
            pass
        try:
            b.accept_delivery("client", "no-such-delivery")
            raise AssertionError("unknown delivery must be refused")
        except NotFound:
            pass
    finally:
        shutil.rmtree(d)


@case
def E4_export_and_verify_real_bridge():
    d, b, _wb, _client, _worker, delivery_id = fresh()
    try:
        b.accept_delivery("client", delivery_id, version="v1")
        entries = b.entries()
        status_seed, service_seed = b"\x44" * 32, b"\x33" * 32
        status = signed_status(status_seed, "2026-10-21T12:00:00+08:00",
                               "2099-01-01T00:00:00+08:00")
        receipt = signed_receipt(service_seed, bridge_id_of(entries), entries[-1]["seq"],
                                 entries[-1]["digest"], "2026-10-21T12:00:00+08:00")
        work = tempfile.mkdtemp(prefix="agentbridge-pack.")
        status_path = os.path.join(work, "status.json")
        receipt_path = os.path.join(work, "receipt.json")
        write_json(status_path, status)
        write_json(receipt_path, receipt)
        exporter = signing.Signer("exporter", b"\x55" * 32)
        pack = os.path.join(work, "pack")
        evidence.export_pack(b, pack, task_ref={"system": "test", "id": "T-1"},
                             delivery_id=delivery_id, exporter=exporter,
                             status_file=status_path, receipt_files=[receipt_path])
        trust = make_trust(work, entries, exporter.pub_hex, status_seed, service_seed, delivery_id)
        trust_path = os.path.join(work, "trust.json")
        write_json(trust_path, trust)
        result = evidence.verify_pack(pack, trust_path).to_dict(pack)
        assert result["exit_code"] == 2, result["exit_code"]
        for axis in ("integrity", "identity", "acceptance", "coverage", "anchoring"):
            assert result["axes"][axis]["status"] == "pass", (axis, result["axes"][axis])
        assert result["axes"]["content"]["status"] == "not_executed"
        # tamper: flip one byte in the delivered envelope, manifest untouched -> file mismatch
        env = os.path.join(pack, "originals/envelopes", delivery_id + ".json")
        data = bytearray(open(env, "rb").read())
        data[0] ^= 0x01
        open(env, "wb").write(bytes(data))
        bad = evidence.verify_pack(pack, trust_path).to_dict(pack)
        assert bad["axes"]["integrity"]["status"] == "fail", bad["axes"]["integrity"]
        assert bad["exit_code"] == 1
    finally:
        shutil.rmtree(d)


@case
def E5_legacy_verify_still_ok():
    d, b, _wb, _client, _worker, delivery_id = fresh()
    try:
        b.accept_delivery("client", delivery_id, version="v1")
        report = b.verify()
        assert report.ok, report.problems
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
