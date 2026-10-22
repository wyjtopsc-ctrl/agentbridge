#!/usr/bin/env python3
"""Generate deterministic evidence-pack v0 test vectors.

Vector set: normal, tampered-sig, tampered-binding, missing-evidence, retired-key,
compromised-no-anchor, compromised-with-anchor, forged-selfconsistent.
Trust files are external to the packs (docs/fixtures/evidence-pack-v0/trust/).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, "src"))

from agentbridge import signing  # noqa: E402
from packjcs import canonical_bytes  # noqa: E402

FIX = os.path.join(ROOT, "docs", "fixtures", "evidence-pack-v0")
TRUST = os.path.join(FIX, "trust")
KEYS = {
    "normal": {"worker": b"\x11" * 32, "client": b"\x22" * 32, "service": b"\x33" * 32,
               "status": b"\x44" * 32, "exporter": b"\x55" * 32},
    "attacker": {"worker": b"\x66" * 32, "client": b"\x77" * 32, "service": b"\x88" * 32,
                 "status": b"\x99" * 32, "exporter": b"\xaa" * 32},
}
TS = "2026-10-21T12:00:0{}+08:00"
PUBLISHED = "2026-10-21T11:00:00+08:00"
VALID_UNTIL = "2026-10-22T11:00:00+08:00"
EXPECTED = {
    "normal": {"axes": {"integrity": "pass", "identity": "pass", "acceptance": "pass",
                        "coverage": "pass", "anchoring": "pass", "content": "not_executed"},
               "exit_code": 2,
               "checks": {"integrity.envelope_signature": "pass",
                          "integrity.envelope_binding": "pass",
                          "identity.records_signed": "pass", "identity.trust_set": "pass",
                          "acceptance.binding": "pass", "anchoring.checkpoint": "pass"}},
    "tampered-sig": {"axes": {"integrity": "fail", "identity": "unknown", "acceptance": "pass",
                              "coverage": "pass", "anchoring": "pass", "content": "not_executed"},
                     "exit_code": 1,
                     "codes": ["E-SIG-INVALID", "E-ENVELOPE-MISMATCH"],
                     "checks": {"integrity.envelope_signature": "fail",
                                "integrity.envelope_binding": "fail",
                                "identity.records_signed": "unknown"}},
    "tampered-binding": {"axes": {"integrity": "fail", "identity": "pass", "acceptance": "pass",
                                  "coverage": "pass", "anchoring": "pass", "content": "not_executed"},
                         "exit_code": 1, "codes": ["E-ENVELOPE-MISMATCH"],
                         "checks": {"integrity.envelope_signature": "pass",
                                    "integrity.envelope_binding": "fail",
                                    "identity.records_signed": "pass"}},
    "missing-evidence": {"axes": {"integrity": "pass", "identity": "pass", "acceptance": "fail",
                                  "coverage": "pass", "anchoring": "unknown", "content": "not_executed"},
                         "exit_code": 1,
                         "codes": ["E-ANCHOR-MISSING", "E-ACC-REQUIRES-ANCHOR"],
                         "checks": {"acceptance.anchoring_requirement": "fail",
                                    "anchoring.coverage": "unknown"}},
    "retired-key": {"axes": {"integrity": "pass", "identity": "pass", "acceptance": "pass",
                             "coverage": "pass", "anchoring": "pass", "content": "not_executed"},
                    "exit_code": 2, "checks": {"identity.revocation": "pass"}},
    "compromised-no-anchor": {"axes": {"integrity": "pass", "identity": "unknown",
                                       "acceptance": "pass", "coverage": "pass",
                                       "anchoring": "unknown", "content": "not_executed"},
                              "exit_code": 2, "codes": ["E-KEY-COMPROMISE-SUSPECTED"],
                              "checks": {"identity.revocation": "unknown"}},
    "compromised-with-anchor": {"axes": {"integrity": "pass", "identity": "pass",
                                         "acceptance": "pass", "coverage": "pass",
                                         "anchoring": "pass", "content": "not_executed"},
                                "exit_code": 2, "checks": {"identity.revocation": "pass"}},
    "compromised-start-unknown": {"axes": {"integrity": "pass", "identity": "unknown",
                                           "acceptance": "pass", "coverage": "pass",
                                           "anchoring": "pass", "content": "not_executed"},
                                  "exit_code": 2, "codes": ["E-KEY-COMPROMISE-START-UNKNOWN"],
                                  "checks": {"identity.revocation": "unknown"}},
    "compromise-boundary-equal": {"axes": {"integrity": "pass", "identity": "unknown",
                                           "acceptance": "pass", "coverage": "pass",
                                           "anchoring": "pass", "content": "not_executed"},
                                  "exit_code": 2, "codes": ["E-KEY-COMPROMISE-SUSPECTED"],
                                  "checks": {"identity.revocation": "unknown"}},
    "retirement-boundary-equal": {"axes": {"integrity": "pass", "identity": "pass",
                                           "acceptance": "pass", "coverage": "pass",
                                           "anchoring": "pass", "content": "not_executed"},
                                  "exit_code": 2, "checks": {"identity.revocation": "pass"}},
    "forged-selfconsistent": {"axes": {"integrity": "pass", "identity": "unknown",
                                       "acceptance": "pass", "coverage": "pass",
                                       "anchoring": "unknown", "content": "not_executed"},
                              "exit_code": 2,
                              "codes": ["E-TRUST-NOT-ESTABLISHED", "E-SIG-UNTRUSTED-KEY",
                                        "E-ANCHOR-UNTRUSTED"],
                              "checks": {"identity.trust_set": "unknown",
                                         "identity.records_signed": "unknown"}},
}

CONFIGS = {
    "normal": {},
    "tampered-sig": {"tamper": "keep-sig"},
    "tampered-binding": {"tamper": "resign"},
    "missing-evidence": {"anchors": False, "requires_anchoring": True},
    "retired-key": {"revocation": ("normal_retirement", TS.format(0), None)},
    "compromised-no-anchor": {"anchors": False,
                              "revocation": ("suspected_compromise", TS.format(4), TS.format(3))},
    "compromised-with-anchor": {"revocation": ("suspected_compromise", TS.format(4), TS.format(3)),
                                "anchor_at": TS.format(2)},
    "compromised-start-unknown": {"revocation": ("suspected_compromise", TS.format(4), None),
                                  "anchor_at": TS.format(2)},
    "compromise-boundary-equal": {"revocation": ("suspected_compromise", TS.format(4), TS.format(2)),
                                  "anchor_at": TS.format(2)},
    "retirement-boundary-equal": {"revocation": ("normal_retirement", TS.format(3), None),
                                  "anchor_at": TS.format(3)},
    "forged-selfconsistent": {"keys": "attacker"},
}


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


def sign_plain(seed, obj):
    return {"alg": "ed25519", "pub": pub(seed),
            "sig": signing.sign(seed, canonical_bytes(obj)).hex()}


def sign_domain(seed, domain, obj):
    payload = f"agentbridge-evidence/0.1\n{domain}\n".encode() + canonical_bytes(obj)
    return {"alg": "ed25519", "pub": pub(seed), "sig": signing.sign(seed, payload).hex()}


def entry(keys, actor, fields, seq, prev, sign=True):
    e = {**fields, "seq": seq, "ts": TS.format(seq % 10), "prev": prev}
    e["digest"] = sha(canonical_bytes(e))
    if sign:
        e["sig_pub"] = pub(keys[actor])
        e["sig"] = signing.sign(keys[actor], e["digest"].encode()).hex()
    return e


def build(name, out_root):
    cfg = CONFIGS[name]
    keys = KEYS[cfg.get("keys", "normal")]
    out = os.path.join(out_root, name)
    if os.path.isdir(out):
        shutil.rmtree(out)
    artifacts = [
        {"role": "deliverable", "name": "report.pdf", "sha256": sha(b"report v1 content"), "bytes": 19},
        {"role": "deliverable", "name": "module.py", "sha256": sha(b"print('hi')\n"), "bytes": 13},
    ]
    hashes = sorted(a["sha256"] for a in artifacts)

    env_send = {"v": 2, "id": "env-send", "from": "client", "to": "worker", "intent": "review",
                "in_reply_to": None, "created_at": TS.format(1), "body": "review report v1",
                "artifacts": artifacts, "reply_box": "wire/inbox"}
    env_send["signature"] = sign_plain(keys["client"], env_send)
    env_deliver = {"v": 2, "id": "env-deliver", "from": "worker", "to": "client",
                   "intent": "deliver", "in_reply_to": "env-send", "created_at": TS.format(2),
                   "body": "delivered v1", "artifacts": artifacts}
    env_deliver["signature"] = sign_plain(keys["worker"], env_deliver)

    acceptance = {"acceptance_id": "acc-1", "delivery_id": "dlv-1", "version": "v1",
                  "artifacts_sha256": hashes, "decision": "accepted", "reason": "",
                  "requires_anchoring": cfg.get("requires_anchoring", False), "actor": "client",
                  "signed_at": TS.format(3)}
    acceptance["signature"] = sign_domain(keys["client"], "acceptance-record", acceptance)

    revocations = []
    if cfg.get("revocation"):
        kind, effective, leak = cfg["revocation"]
        revocations.append({"actor": "worker", "fingerprint": signing.fingerprint(pub(keys["worker"])),
                            "kind": kind, "effective_at": effective,
                            "suspected_leak_at": leak, "evidence": "fixture"})
    status = {"published_at": PUBLISHED, "valid_until": VALID_UNTIL,
              "publisher_pub": pub(keys["status"]), "revocations": revocations}
    status["signature"] = sign_domain(keys["status"], "status", status)

    genesis = entry(keys, "worker", {"type": "genesis", "actor": "system", "note": "fixture"},
                    0, "GENESIS", sign=False)
    entries = [genesis]
    for seq, actor in ((1, "worker"), (2, "client")):
        entries.append(entry(keys, actor, {"type": "actor_register", "actor": actor,
                                           "pub": pub(keys[actor])}, seq, entries[-1]["digest"]))
    entries.append(entry(keys, "client", {"type": "send", "id": "env-send", "actor": "client",
                                          "from": "client", "to": "worker", "intent": "review",
                                          "in_reply_to": None, "envelope_sha256": "",
                                          "artifacts": artifacts}, 3, entries[-1]["digest"]))
    entries.append(entry(keys, "worker", {"type": "deliver", "id": "env-deliver", "actor": "worker",
                                          "from": "worker", "to": "client", "intent": "deliver",
                                          "in_reply_to": "env-send", "envelope_sha256": "",
                                          "artifacts": artifacts}, 4, entries[-1]["digest"]))
    entries.append(entry(keys, "client", {"type": "accept", "acceptance_id": "acc-1",
                                          "actor": "client", "delivery_id": "dlv-1",
                                          "version": "v1", "record_sha256": ""},
                         5, entries[-1]["digest"]))

    send_bytes = (json.dumps(env_send, ensure_ascii=False) + "\n").encode()
    deliver_bytes = (json.dumps(env_deliver, ensure_ascii=False) + "\n").encode()
    acceptance_bytes = (json.dumps(acceptance, ensure_ascii=False) + "\n").encode()
    status_bytes = (json.dumps(status, ensure_ascii=False) + "\n").encode()
    write(os.path.join(out, "originals/envelopes/env-send.json"), send_bytes)
    write(os.path.join(out, "originals/envelopes/env-deliver.json"), deliver_bytes)
    write(os.path.join(out, "originals/acceptances/acc-1.json"), acceptance_bytes)
    write(os.path.join(out, "originals/status.json"), status_bytes)

    entries[3]["envelope_sha256"] = sha(send_bytes)
    entries[4]["envelope_sha256"] = sha(deliver_bytes)
    entries[5]["record_sha256"] = sha(acceptance_bytes)
    for i in range(3, 6):
        entries[i]["prev"] = entries[i - 1]["digest"]
        body = {k: v for k, v in entries[i].items() if k not in ("digest", "sig", "sig_pub")}
        entries[i]["digest"] = sha(canonical_bytes(body))
        entries[i]["sig"] = signing.sign(keys[entries[i]["actor"]],
                                         entries[i]["digest"].encode()).hex()
    ledger_bytes = "".join(json.dumps(e, ensure_ascii=False, sort_keys=True) + "\n"
                           for e in entries).encode()
    write(os.path.join(out, "originals/ledger.jsonl"), ledger_bytes)
    tip = entries[-1]
    bridge_id = "br-" + sha(tip["digest"].encode())[:16]

    anchor_ok = cfg.get("anchors", True)
    receipt = None
    if anchor_ok:
        receipt = {"v": 1, "bridge_id": bridge_id, "seq": tip["seq"], "digest": tip["digest"],
                   "log_index": 0, "received_at": cfg.get("anchor_at", TS.format(4)),
                   "client_pub": pub(keys["client"]), "service_pub": pub(keys["service"]), "prev": ""}
        receipt["service_sig"] = signing.sign(keys["service"], canonical_bytes(receipt)).hex()
        write(os.path.join(out, "originals/receipts/0.json"),
              (json.dumps(receipt, ensure_ascii=False) + "\n").encode())

    manifest = {
        "pack_version": "agentbridge-evidence/0.1", "created_at": TS.format(5),
        "as_of": {"key_status": PUBLISHED, "anchors": TS.format(4)},
        "bridge_id": bridge_id,
        "task": {"external_ref": {"system": "fixture", "id": "TASK-1"}, "title": "fixture"},
        "deliveries": [{"delivery_id": "dlv-1", "version": "v1", "previous_version": None,
                        "artifacts": artifacts, "submitted_at": TS.format(2), "sender": "worker",
                        "ledger_seq": 4, "envelope_id": "env-deliver",
                        "envelope_path": "originals/envelopes/env-deliver.json",
                        "envelope_sha256": sha(deliver_bytes)}],
        "acceptances": [{"acceptance_id": "acc-1", "delivery_id": "dlv-1", "version": "v1",
                         "artifacts_sha256": hashes, "decision": "accepted", "reason": "",
                         "requires_anchoring": cfg.get("requires_anchoring", False),
                         "actor": "client", "signed_at": TS.format(3), "ledger_seq": 5,
                         "record_path": "originals/acceptances/acc-1.json",
                         "record_sha256": sha(acceptance_bytes)}],
        "identity": {
            "actors": [{"actor": a, "pub": pub(keys[a]),
                        "fingerprint": signing.fingerprint(pub(keys[a])),
                        "registered_seq": i} for i, a in ((1, "worker"), (2, "client"))],
            "status": {"path": "originals/status.json", "sha256": sha(status_bytes),
                       "publisher_pub": pub(keys["status"]),
                       "published_at": PUBLISHED, "valid_until": VALID_UNTIL,
                       "revocations": revocations}},
        "ledger": {"path": "originals/ledger.jsonl", "sha256": sha(ledger_bytes),
                   "base": "genesis", "tip_seq": tip["seq"], "tip_digest": tip["digest"]},
        "envelopes": [{"id": "env-send", "path": "originals/envelopes/env-send.json",
                       "sha256": sha(send_bytes)},
                      {"id": "env-deliver", "path": "originals/envelopes/env-deliver.json",
                       "sha256": sha(deliver_bytes)}],
        "anchors": [] if receipt is None else [{"path": "originals/receipts/0.json",
                                                "sha256": sha((json.dumps(receipt, ensure_ascii=False) + "\n").encode()),
                                                "service_pub": pub(keys["service"]),
                                                "covers_seq": receipt["seq"],
                                                "covers_digest": receipt["digest"],
                                                "log_index": 0, "received_at": receipt["received_at"]}],
        "coverage": {"expected_events": ["send", "deliver", "accept"],
                     "recorded_events": ["send", "deliver", "accept"], "gaps": []},
        "content_mode": "hashes_only",
        "limits": ["附件内容未包含在包内，内容复核未执行", "离线无法确认是否为最新历史",
                   "未锚定尾部回滚不可发现"],
        "signed_files": [],
    }
    signed = ["originals/ledger.jsonl", "originals/envelopes/env-send.json",
              "originals/envelopes/env-deliver.json", "originals/acceptances/acc-1.json",
              "originals/status.json"]
    if receipt is not None:
        signed.append("originals/receipts/0.json")
    manifest["signed_files"] = [{"path": p, "sha256": sha(open(os.path.join(out, p), "rb").read())}
                                for p in signed]
    manifest["signatures"] = {"exporter": sign_domain(keys["exporter"], "manifest", manifest)}

    if cfg.get("tamper") == "resign":
        forged_env = {k: v for k, v in env_deliver.items() if k != "signature"}
        forged_env["body"] = "delivered v2"
        forged_env["signature"] = sign_plain(keys["worker"], forged_env)
        forged_bytes = (json.dumps(forged_env, ensure_ascii=False) + "\n").encode()
    elif cfg.get("tamper") == "keep-sig":
        forged_bytes = deliver_bytes.replace(b"delivered v1", b"delivered v2")
    else:
        forged_bytes = None
    if forged_bytes is not None:
        write(os.path.join(out, "originals/envelopes/env-deliver.json"), forged_bytes)
        manifest["envelopes"][1]["sha256"] = sha(forged_bytes)
        manifest["deliveries"][0]["envelope_sha256"] = sha(forged_bytes)
        for item in manifest["signed_files"]:
            if item["path"] == "originals/envelopes/env-deliver.json":
                item["sha256"] = sha(forged_bytes)
        body = {k: v for k, v in manifest.items() if k != "signatures"}
        manifest["signatures"] = {"exporter": sign_domain(keys["exporter"], "manifest", body)}

    dump(os.path.join(out, "manifest.json"), manifest)
    dump(os.path.join(out, "expected.json"), EXPECTED[name])
    return out, manifest, entries


def write_trust(name, manifest, entries, overrides=None, trust_dir=None):
    trust = {
        "expected_bridge_id": manifest["bridge_id"],
        "expected_actors": [
            {"actor": "worker", "fingerprint": signing.fingerprint(pub(KEYS["normal"]["worker"]))},
            {"actor": "client", "fingerprint": signing.fingerprint(pub(KEYS["normal"]["client"]))},
        ],
        "expected_exporter": {"actor": "exporter",
                              "fingerprint": signing.fingerprint(pub(KEYS["normal"]["exporter"]))},
        "anchor_service_pubs": [pub(KEYS["normal"]["service"])],
        "status_publisher_pub": pub(KEYS["normal"]["status"]),
        "max_status_age_hours": 24, "max_future_skew_seconds": 300,
        "minimum_checkpoint_seq": 5,
        "known_checkpoint": {"bridge_id": manifest["bridge_id"], "seq": entries[-1]["seq"],
                             "digest": entries[-1]["digest"]},
        "expected_versions": {"dlv-1": "v1"},
    }
    if name == "forged-selfconsistent":
        trust.pop("expected_bridge_id", None)
        trust.pop("known_checkpoint", None)
    if overrides:
        trust.update(overrides)
    dump(os.path.join(trust_dir or TRUST, name + ".json"), trust)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=FIX)
    args = ap.parse_args()
    if os.path.isdir(args.out):
        shutil.rmtree(args.out)
    os.makedirs(args.out, exist_ok=True)
    trust_dir = os.path.join(args.out, "trust")
    os.makedirs(trust_dir, exist_ok=True)
    built = {name: build(name, args.out) for name in CONFIGS}
    for name, (out, manifest, entries) in built.items():
        write_trust(name, manifest, entries, trust_dir=trust_dir)
    normal = built["normal"][1]
    tip_digest = built["normal"][2][-1]["digest"]
    write_trust("checkpoint-mismatch", normal, built["normal"][2],
                overrides={"known_checkpoint": {"bridge_id": normal["bridge_id"], "seq": 5,
                                                "digest": "00" * 32}}, trust_dir=trust_dir)
    write_trust("checkpoint-wrong-bridge", normal, built["normal"][2],
                overrides={"known_checkpoint": {"bridge_id": "br-" + "00" * 8, "seq": 5,
                                                "digest": tip_digest}}, trust_dir=trust_dir)
    write_trust("checkpoint-out-of-range", normal, built["normal"][2],
                overrides={"known_checkpoint": {"bridge_id": normal["bridge_id"], "seq": 99,
                                                "digest": tip_digest}}, trust_dir=trust_dir)
    write_trust("minimum-too-high", normal, built["normal"][2],
                overrides={"minimum_checkpoint_seq": 6}, trust_dir=trust_dir)
    print("built:", ", ".join(CONFIGS))


if __name__ == "__main__":
    main()
