#!/usr/bin/env python3
"""Two-minute dispute demo: send -> deliver v1 -> reject -> revise v2 -> accept -> export -> verify -> tamper.

Run from the repo root:  PYTHONPATH=src python3 demo/run_demo.py
"""
from __future__ import annotations

import json
import os
import shutil
import tempfile

from agentbridge import Bridge, evidence, signing

STEP = 0


def step(title: str) -> None:
    global STEP
    STEP += 1
    print(f"\n[{STEP}] {title}")
    print("-" * 64)


def json_file(path: str, obj: dict) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)
        f.write("\n")


def main() -> int:
    work = tempfile.mkdtemp(prefix="agentbridge-demo.")
    root = os.path.join(work, "bridge")
    client = signing.Signer("client", b"\x22" * 32)
    worker = signing.Signer("worker", b"\x11" * 32)
    exporter = signing.Signer("exporter", b"\x55" * 32)
    service_seed, status_seed = b"\x33" * 32, b"\x44" * 32

    step("Setup: bridge + two identities")
    b = Bridge(root, client)
    b.init(actor="client")
    b.register_actor("client", client.pub_hex)
    wb = Bridge(root, worker)
    wb.register_actor("worker", worker.pub_hex)
    print("client and worker registered; ledger at", os.path.join(root, "ledger.jsonl"))

    req = os.path.join(work, "request.md")
    v1 = os.path.join(work, "report-v1.md")
    v2 = os.path.join(work, "report-v2.md")
    open(req, "w").write("review this module\n")
    open(v1, "w").write("report v1 (scope incomplete)\n")
    open(v2, "w").write("report v2 (scope fixed)\n")

    step("Client sends a request")
    sent = b.send(actor="client", to="worker", body="review this module", attach=[req])
    print("request id:", sent["id"])

    step("Worker delivers v1")
    d1 = wb.deliver(actor="worker", to="client", in_reply_to=sent["id"],
                    body="delivered v1", attach=[v1])
    print("delivery:", d1["id"], "version:", d1["version"])

    step("Client rejects v1 (reason bound to that version)")
    b.accept_delivery("client", d1["id"], decision="rejected",
                      reason="scope incomplete; revise and resubmit")
    print("rejection recorded; v1 stays in the ledger")

    step("Worker delivers v2 as a revision")
    d2 = wb.deliver(actor="worker", to="client", in_reply_to=sent["id"],
                    body="delivered v2", attach=[v2], version="v2", revises=d1["id"])
    print("delivery:", d2["id"], "version:", d2["version"], "revises:", d1["id"])

    step("Client accepts v2 (v1 is not inherited)")
    b.accept_delivery("client", d2["id"], decision="accepted", reason="")
    print("acceptance recorded for v2 only")

    step("Export an evidence pack")
    entries = b.entries()
    status = {"protocol_version": "0.1", "published_at": "2026-10-22T12:00:00+08:00",
              "valid_until": "2099-01-01T00:00:00+08:00",
              "publisher_pub": signing.public_key(status_seed).hex(), "revocations": []}
    status["signature"] = evidence.sign_domain(signing.Signer("status", status_seed), "status", status)
    status_path = os.path.join(work, "status.json")
    json_file(status_path, status)
    trust = {
        "expected_bridge_id": evidence.bridge_id_of(b, entries),
        "expected_actors": [
            {"actor": "client", "fingerprint": signing.fingerprint(client.pub_hex)},
            {"actor": "worker", "fingerprint": signing.fingerprint(worker.pub_hex)},
        ],
        "expected_exporter": {"actor": "exporter",
                              "fingerprint": signing.fingerprint(exporter.pub_hex)},
        "anchor_service_pubs": [signing.public_key(service_seed).hex()],
        "status_publisher_pub": signing.public_key(status_seed).hex(),
        "max_status_age_hours": 24 * 365 * 50,
        "max_future_skew_seconds": 300,
        "minimum_checkpoint_seq": 0,
        "expected_versions": {d1["delivery_id"]: "v2"},
    }
    trust_path = os.path.join(work, "trust.json")
    json_file(trust_path, trust)
    pack = os.path.join(work, "pack")
    evidence.export_pack(b, pack, task_ref={"system": "demo", "id": "DEMO-1"},
                         delivery_id=d2["id"], exporter=exporter, status_file=status_path)
    print("pack:", pack)

    step("Receiver verifies offline")
    result = evidence.verify_pack(pack, trust_path).to_dict(pack)
    for axis, payload in result["axes"].items():
        print(f"  {axis:11} {payload['status']}")
    print("  exit_code:", result["exit_code"], "(2 = unknown/not-executed, expected for hashes_only)")
    print("  disclosure:", result["disclosure"][0])

    step("Tamper: replace one byte of the delivered envelope")
    env_path = os.path.join(pack, "originals/envelopes", d2["id"] + ".json")
    data = bytearray(open(env_path, "rb").read())
    data[0] ^= 0x01
    open(env_path, "wb").write(bytes(data))
    bad = evidence.verify_pack(pack, trust_path).to_dict(pack)
    print("  integrity:", bad["axes"]["integrity"]["status"], bad["axes"]["integrity"]["codes"])
    print("  exit_code:", bad["exit_code"], "(1 = fail)")

    step("What this does and does not prove")
    print("  proves: which version was delivered, who accepted it, and that the record was not altered")
    print("  does not prove: file content was reviewed (hashes_only), business quality, or latest history offline")
    shutil.rmtree(work)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
