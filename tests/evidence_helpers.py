"""Shared helpers for evidence tests (kept out of the test files themselves)."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile

from agentbridge import evidence, signing
from agentbridge.core import Bridge, bridge_id_of
from agentbridge.jcs import canonical_bytes

STATUS_SEED = b"\x44" * 32
SERVICE_SEED = b"\x33" * 32
EXPORTER_SEED = b"\x55" * 32


def sha_file(path):
    return hashlib.sha256(open(path, "rb").read()).hexdigest()


def tree_snapshot(root):
    out = {}
    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            path = os.path.join(dirpath, name)
            out[os.path.relpath(path, root)] = sha_file(path)
    return out


def fresh(client_seed=b"\x22" * 32, worker_seed=b"\x11" * 32):
    root = tempfile.mkdtemp(prefix="agentbridge-evidence.")
    client = signing.Signer("client", client_seed)
    worker = signing.Signer("worker", worker_seed)
    b = Bridge(root, client)
    b.init(actor="client")
    b.register_actor("client", client.pub_hex)
    wb = Bridge(root, worker)
    wb.register_actor("worker", worker.pub_hex)
    req = os.path.join(root, "request.md")
    rep = os.path.join(root, "report.md")
    open(req, "w").write("request\n")
    open(rep, "w").write("report v1\n")
    sent = b.send(actor="client", to="worker", body="do it", intent="review", attach=[req])
    delivered = wb.deliver(actor="worker", to="client", in_reply_to=sent["id"],
                           body="done", attach=[rep])
    return {"root": root, "bridge": b, "worker_bridge": wb, "client": client,
            "worker": worker, "delivery_id": delivered["id"], "request_id": sent["id"]}


def write_json(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)
        f.write("\n")


def signed_status(seed=STATUS_SEED, published="2026-10-21T12:00:00+08:00",
                  valid_until="2099-01-01T00:00:00+08:00", revocations=None):
    st = {"protocol_version": "0.1", "published_at": published, "valid_until": valid_until,
          "publisher_pub": signing.public_key(seed).hex(), "revocations": revocations or []}
    st["signature"] = evidence.sign_domain(signing.Signer("status", seed), "status", st)
    return st


def signed_receipt(seed=SERVICE_SEED, bridge_id="", seq=0, digest="", received_at=""):
    rc = {"v": 1, "bridge_id": bridge_id, "seq": seq, "digest": digest, "log_index": 0,
          "received_at": received_at, "client_pub": signing.public_key(b"\x22" * 32).hex(),
          "service_pub": signing.public_key(seed).hex(), "prev": ""}
    rc["service_sig"] = signing.sign(seed, canonical_bytes(rc)).hex()
    return rc


def trust_for(entries, exporter_pub, delivery_id, status_seed=STATUS_SEED,
              service_seed=SERVICE_SEED):
    actors = {e["actor"]: signing.fingerprint(e["pub"]) for e in entries
              if e.get("type") == "actor_register"}
    return {
        "expected_bridge_id": bridge_id_of(entries),
        "expected_actors": [{"actor": a, "fingerprint": f} for a, f in actors.items()],
        "expected_exporter": {"actor": "exporter",
                              "fingerprint": signing.fingerprint(exporter_pub)},
        "anchor_service_pubs": [signing.public_key(service_seed).hex()],
        "status_publisher_pub": signing.public_key(status_seed).hex(),
        "max_status_age_hours": 24 * 365 * 50,
        "max_future_skew_seconds": 300,
        "minimum_checkpoint_seq": entries[-1]["seq"],
        "known_checkpoint": {"bridge_id": bridge_id_of(entries), "seq": entries[-1]["seq"],
                             "digest": entries[-1]["digest"]},
        "expected_versions": {delivery_id: "v1"},
    }


def prepare_pack(requires_anchoring=False, accept=True):
    """Build a bridge, optionally accept, export a pack, and write the external trust file."""
    sc = fresh()
    if accept:
        sc["bridge"].accept_delivery("client", sc["delivery_id"], version="v1",
                                     requires_anchoring=requires_anchoring)
    entries = sc["bridge"].entries()
    work = tempfile.mkdtemp(prefix="agentbridge-pack.")
    status = signed_status()
    receipt = signed_receipt(bridge_id=bridge_id_of(entries), seq=entries[-1]["seq"],
                             digest=entries[-1]["digest"],
                             received_at="2026-10-21T12:00:00+08:00")
    status_path = os.path.join(work, "status.json")
    receipt_path = os.path.join(work, "receipt.json")
    write_json(status_path, status)
    write_json(receipt_path, receipt)
    exporter = signing.Signer("exporter", EXPORTER_SEED)
    pack = os.path.join(work, "pack")
    evidence.export_pack(sc["bridge"], pack, task_ref={"system": "test", "id": "T-1"},
                         delivery_id=sc["delivery_id"], exporter=exporter,
                         status_file=status_path, receipt_files=[receipt_path])
    trust = trust_for(entries, exporter.pub_hex, sc["delivery_id"])
    trust_path = os.path.join(work, "trust.json")
    write_json(trust_path, trust)
    return {**sc, "work": work, "pack": pack, "trust": trust_path,
            "exporter": exporter, "entries": entries, "receipt_path": receipt_path}


def resign_manifest(pack, exporter):
    path = os.path.join(pack, "manifest.json")
    manifest = json.load(open(path, encoding="utf-8"))
    manifest.pop("signatures", None)
    manifest["signatures"] = {"exporter": evidence.sign_domain(exporter, "manifest", manifest)}
    write_json(path, manifest)
    return manifest


def rewrite_ledger(pack, exporter, lines):
    data = "".join(line if line.endswith("\n") else line + "\n" for line in lines).encode()
    with open(os.path.join(pack, "originals/ledger.jsonl"), "wb") as f:
        f.write(data)
    manifest = json.load(open(os.path.join(pack, "manifest.json"), encoding="utf-8"))
    tip = json.loads(lines[-1])
    manifest["ledger"]["sha256"] = hashlib.sha256(data).hexdigest()
    manifest["ledger"]["tip_seq"] = tip["seq"]
    manifest["ledger"]["tip_digest"] = tip["digest"]
    for item in manifest["signed_files"]:
        if item["path"] == "originals/ledger.jsonl":
            item["sha256"] = hashlib.sha256(data).hexdigest()
    write_json(os.path.join(pack, "manifest.json"), manifest)
    resign_manifest(pack, exporter)


def cleanup(*dirs):
    for d in dirs:
        shutil.rmtree(d, ignore_errors=True)
