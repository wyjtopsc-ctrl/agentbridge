#!/usr/bin/env python3
"""Generate the fixed evidence-pack v0.2 fixture from a REAL bridge flow.

Flow: deliver v1 -> reject -> rotate worker key -> revise v2 -> accept v2 -> export.
The pack is saved under docs/fixtures/evidence-pack-v0.2/revision-rotation/.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, "src"))

from agentbridge import evidence, signing  # noqa: E402
from agentbridge.core import Bridge, bridge_id_of  # noqa: E402

OUT = os.path.join(ROOT, "docs", "fixtures", "evidence-pack-v0.2", "revision-rotation")
TRUST_PATH = os.path.join(ROOT, "docs", "fixtures", "evidence-pack-v0.2", "trust", "revision-rotation.json")
STATUS_SEED = b"\x44" * 32
SERVICE_SEED = b"\x33" * 32
EXPORTER_SEED = b"\x55" * 32


def write_json(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)
        f.write("\n")


def main() -> int:
    work = tempfile.mkdtemp(prefix="agentbridge-v2fixture.")
    root = os.path.join(work, "bridge")
    client = signing.Signer("client", b"\x22" * 32)
    worker = signing.Signer("worker", b"\x11" * 32)
    new_worker = signing.Signer("worker", b"\x66" * 32)
    b = Bridge(root, client)
    b.init(actor="client")
    b.register_actor("client", client.pub_hex)
    wb = Bridge(root, worker)
    wb.register_actor("worker", worker.pub_hex)

    req = os.path.join(work, "request.md")
    rep1 = os.path.join(work, "report-v1.md")
    rep2 = os.path.join(work, "report-v2.md")
    open(req, "w").write("request\n")
    open(rep1, "w").write("report v1\n")
    open(rep2, "w").write("report v2, fixed\n")
    sent = b.send(actor="client", to="worker", body="do it", attach=[req])
    v1 = wb.deliver(actor="worker", to="client", in_reply_to=sent["id"],
                    body="v1", attach=[rep1])
    b.accept_delivery("client", v1["id"], decision="rejected", reason="missing tests")
    wb.rotate_key(new_worker, reason="routine rotation")
    wb2 = Bridge(root, new_worker)
    v2 = wb2.deliver(actor="worker", to="client", in_reply_to=sent["id"],
                     body="v2", attach=[rep2], version="v2", revises=v1["id"])
    b.accept_delivery("client", v2["id"], decision="accepted")

    entries = b.entries()
    status = {"protocol_version": "0.1", "published_at": "2026-10-21T12:00:00+08:00",
              "valid_until": "2099-01-01T00:00:00+08:00",
              "publisher_pub": signing.public_key(STATUS_SEED).hex(), "revocations": []}
    status["signature"] = evidence.sign_domain(signing.Signer("status", STATUS_SEED), "status", status)
    receipt = {"v": 1, "bridge_id": bridge_id_of(entries), "seq": entries[-1]["seq"],
               "digest": entries[-1]["digest"], "log_index": 0,
               "received_at": "2026-10-21T12:00:00+08:00",
               "client_pub": signing.public_key(b"\x22" * 32).hex(),
               "service_pub": signing.public_key(SERVICE_SEED).hex(), "prev": ""}
    receipt["service_sig"] = signing.sign(SERVICE_SEED,
                                          evidence.canonical_bytes(receipt)).hex()
    status_path = os.path.join(work, "status.json")
    receipt_path = os.path.join(work, "receipt.json")
    write_json(status_path, status)
    write_json(receipt_path, receipt)
    exporter = signing.Signer("exporter", EXPORTER_SEED)
    if os.path.isdir(OUT):
        shutil.rmtree(OUT)
    evidence.export_pack(b, OUT, task_ref={"system": "fixture", "id": "T-REV-1"},
                         delivery_id=v2["id"], exporter=exporter,
                         status_file=status_path, receipt_files=[receipt_path])

    actors = {e["actor"]: signing.fingerprint(e["pub"]) for e in entries
              if e.get("type") == "actor_register"}
    trust = {
        "expected_bridge_id": bridge_id_of(entries),
        "expected_actors": [{"actor": a, "fingerprint": f} for a, f in actors.items()],
        "expected_exporter": {"actor": "exporter",
                              "fingerprint": signing.fingerprint(exporter.pub_hex)},
        "anchor_service_pubs": [signing.public_key(SERVICE_SEED).hex()],
        "status_publisher_pub": signing.public_key(STATUS_SEED).hex(),
        "max_status_age_hours": 24 * 365 * 50,
        "max_future_skew_seconds": 300,
        "minimum_checkpoint_seq": entries[-1]["seq"],
        "known_checkpoint": {"bridge_id": bridge_id_of(entries), "seq": entries[-1]["seq"],
                             "digest": entries[-1]["digest"]},
        "expected_versions": {v1["id"]: "v2"},
    }
    write_json(TRUST_PATH, trust)
    write_json(os.path.join(OUT, "expected.json"), {
        "axes": {"integrity": "pass", "identity": "pass", "acceptance": "pass",
                 "coverage": "pass", "anchoring": "pass", "content": "not_executed"},
        "exit_code": 2,
        "checks": {"integrity.history": "pass", "acceptance.expectation": "pass"},
    })
    print("wrote", os.path.relpath(OUT, ROOT))
    shutil.rmtree(work, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
