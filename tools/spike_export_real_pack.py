#!/usr/bin/env python3
"""Spike: export a real 0.6.1 bridge into the v0 evidence-pack layout and verify it.

Not product code. Proves the D4 mapping (real ledger/envelopes/receipts/status -> pack) can be
implemented without touching the bridge, and that the reference verifier accepts real data.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, "src"))

from agentbridge import signing  # noqa: E402
from agentbridge.core import Bridge, bridge_id_of  # noqa: E402
from packjcs import canonical_bytes  # noqa: E402

BASE = "/tmp/ab-spike"
PACK = os.path.join(BASE, "pack")
TRUST = os.path.join(BASE, "trust.json")
SEEDS = {"worker": b"\x11" * 32, "client": b"\x22" * 32, "service": b"\x33" * 32,
         "status": b"\x44" * 32, "exporter": b"\x55" * 32}
STAMP = time.strftime("%Y-%m-%dT%H:%M:%S+08:00")


def pub(seed):
    return signing.public_key(seed).hex()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def write(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)


def dump(path, obj):
    write(path, (json.dumps(obj, ensure_ascii=False, indent=2) + "\n").encode())


def sign_domain(seed, domain, obj):
    payload = f"agentbridge-evidence/0.1\n{domain}\n".encode() + canonical_bytes(obj)
    return {"alg": "ed25519", "pub": pub(seed), "sig": signing.sign(seed, payload).hex()}


def main() -> int:
    if os.path.isdir(BASE):
        shutil.rmtree(BASE)
    os.makedirs(os.path.join(BASE, "files"), exist_ok=True)
    request = os.path.join(BASE, "files", "request.md")
    report = os.path.join(BASE, "files", "report.md")
    write(request, "请核验这份交付请求\n".encode())
    write(report, "交付报告 v1\n".encode())

    root = os.path.join(BASE, "bridge")
    client = signing.Signer("client", SEEDS["client"])
    worker = signing.Signer("worker", SEEDS["worker"])
    bridge = Bridge(root, client)
    bridge.init(actor="client")
    bridge.register_actor("client", client.pub_hex)
    worker_bridge = Bridge(root, worker)
    worker_bridge.register_actor("worker", worker.pub_hex)

    sent = bridge.send(actor="client", to="worker", body="review request", intent="review",
                       attach=[request])
    delivered = worker_bridge.deliver(actor="worker", to="client", in_reply_to=sent["id"],
                                      body="delivered v1", attach=[report])
    entries = bridge.entries()
    deliver_entry = next(e for e in entries if e.get("id") == delivered["id"])
    deliver_env = json.load(open(delivered["envelope"], encoding="utf-8"))

    acceptance = {
        "protocol_version": "0.1",
        "acceptance_id": "acc-" + delivered["id"],
        "delivery_id": delivered["id"],
        "version": "v1",
        "artifacts_sha256": sorted(a["sha256"] for a in deliver_env["artifacts"]),
        "decision": "accepted", "reason": "", "requires_anchoring": True,
        "actor": "client", "signed_at": STAMP,
    }
    acceptance["signature"] = sign_domain(SEEDS["client"], "acceptance-record", acceptance)
    acc_bytes = (json.dumps(acceptance, ensure_ascii=False) + "\n").encode()

    accept_entry = bridge._append({
        "type": "accept", "acceptance_id": acceptance["acceptance_id"], "actor": "client",
        "delivery_id": delivered["id"], "version": "v1",
        "record_sha256": sha(acc_bytes),
    })
    entries = bridge.entries()
    tip = entries[-1]
    bridge_id = bridge_id_of(entries)

    status = {"protocol_version": "0.1", "published_at": STAMP,
              "valid_until": "2099-01-01T00:00:00+08:00",
              "publisher_pub": pub(SEEDS["status"]), "revocations": []}
    status["signature"] = sign_domain(SEEDS["status"], "status", status)
    receipt = {"v": 1, "bridge_id": bridge_id, "seq": tip["seq"], "digest": tip["digest"],
               "log_index": 0, "received_at": STAMP, "client_pub": pub(SEEDS["client"]),
               "service_pub": pub(SEEDS["service"]), "prev": ""}
    receipt["service_sig"] = signing.sign(SEEDS["service"], canonical_bytes(receipt)).hex()

    ledger_bytes = open(bridge.ledger, "rb").read()
    send_env_bytes = open(sent["envelope"], "rb").read()
    deliver_env_bytes = open(delivered["envelope"], "rb").read()
    originals = {
        "originals/ledger.jsonl": ledger_bytes,
        "originals/envelopes/" + sent["id"] + ".json": send_env_bytes,
        "originals/envelopes/" + delivered["id"] + ".json": deliver_env_bytes,
        "originals/acceptances/" + acceptance["acceptance_id"] + ".json": acc_bytes,
        "originals/status.json": (json.dumps(status, ensure_ascii=False) + "\n").encode(),
        "originals/receipts/0.json": (json.dumps(receipt, ensure_ascii=False) + "\n").encode(),
    }
    for rel, data in originals.items():
        write(os.path.join(PACK, rel), data)

    manifest = {
        "pack_version": "agentbridge-evidence/0.1",
        "created_at": STAMP,
        "as_of": {"key_status": STAMP, "anchors": STAMP},
        "bridge_id": bridge_id,
        "task": {"external_ref": {"system": "spike", "id": "TASK-1"}, "title": "real bridge export"},
        "deliveries": [{
            "delivery_id": delivered["id"], "version": "v1", "previous_version": None,
            "artifacts": [{"role": a["role"], "name": os.path.basename(a["path"]),
                           "sha256": a["sha256"], "bytes": a["bytes"]}
                          for a in deliver_env["artifacts"]],
            "submitted_at": deliver_env["created_at"], "sender": "worker",
            "ledger_seq": deliver_entry["seq"], "envelope_id": deliver_env["id"],
            "envelope_path": "originals/envelopes/" + delivered["id"] + ".json",
            "envelope_sha256": sha(deliver_env_bytes),
        }],
        "acceptances": [{
            "acceptance_id": acceptance["acceptance_id"],
            "delivery_id": delivered["id"], "version": "v1",
            "artifacts_sha256": acceptance["artifacts_sha256"],
            "decision": "accepted", "reason": "", "requires_anchoring": True,
            "actor": "client", "signed_at": STAMP, "ledger_seq": accept_entry["seq"],
            "record_path": "originals/acceptances/" + acceptance["acceptance_id"] + ".json",
            "record_sha256": sha(acc_bytes),
        }],
        "identity": {
            "actors": [{"actor": e["actor"], "pub": e["pub"],
                        "fingerprint": signing.fingerprint(e["pub"]),
                        "registered_seq": e["seq"]}
                       for e in entries if e.get("type") == "actor_register"],
            "status": {"path": "originals/status.json",
                       "sha256": sha(originals["originals/status.json"]),
                       "publisher_pub": pub(SEEDS["status"]),
                       "published_at": STAMP,
                       "valid_until": "2099-01-01T00:00:00+08:00", "revocations": []},
        },
        "ledger": {"path": "originals/ledger.jsonl", "sha256": sha(ledger_bytes),
                   "base": "genesis", "tip_seq": tip["seq"], "tip_digest": tip["digest"]},
        "envelopes": [
            {"id": sent["id"], "path": "originals/envelopes/" + sent["id"] + ".json",
             "sha256": sha(send_env_bytes)},
            {"id": delivered["id"], "path": "originals/envelopes/" + delivered["id"] + ".json",
             "sha256": sha(deliver_env_bytes)},
        ],
        "anchors": [{"path": "originals/receipts/0.json",
                     "sha256": sha(originals["originals/receipts/0.json"]),
                     "service_pub": pub(SEEDS["service"]), "covers_seq": receipt["seq"],
                     "covers_digest": receipt["digest"], "log_index": 0,
                     "received_at": STAMP}],
        "coverage": {"expected_events": ["send", "deliver", "accept"],
                     "recorded_events": ["send", "deliver", "accept"], "gaps": []},
        "content_mode": "hashes_only",
        "limits": ["附件内容未包含在包内，内容复核未执行",
                   "离线无法确认是否为最新历史",
                   "未锚定尾部回滚不可发现"],
        "signed_files": [],
    }
    manifest["signed_files"] = [{"path": rel, "sha256": sha(data)} for rel, data in originals.items()]
    manifest["signatures"] = {"exporter": sign_domain(SEEDS["exporter"], "manifest", manifest)}
    dump(os.path.join(PACK, "manifest.json"), manifest)

    actors = {e["actor"]: signing.fingerprint(e["pub"]) for e in entries
              if e.get("type") == "actor_register"}
    trust = {
        "expected_bridge_id": bridge_id,
        "expected_actors": [{"actor": a, "fingerprint": f} for a, f in actors.items()],
        "expected_exporter": {"actor": "exporter",
                              "fingerprint": signing.fingerprint(pub(SEEDS["exporter"]))},
        "anchor_service_pubs": [pub(SEEDS["service"])],
        "status_publisher_pub": pub(SEEDS["status"]),
        "max_status_age_hours": 24 * 365 * 50, "max_future_skew_seconds": 300,
        "minimum_checkpoint_seq": tip["seq"],
        "known_checkpoint": {"bridge_id": bridge_id, "seq": tip["seq"], "digest": tip["digest"]},
        "expected_versions": {delivered["id"]: "v1"},
    }
    dump(TRUST, trust)

    proc = subprocess.run([sys.executable, os.path.join(HERE, "verify_pack.py"),
                           "--pack", PACK, "--trust", TRUST], capture_output=True, text=True)
    print(proc.stdout)
    print("verifier exit:", proc.returncode)
    return proc.returncode


if __name__ == "__main__":
    sys.exit(main())
