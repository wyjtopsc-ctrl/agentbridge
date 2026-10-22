#!/usr/bin/env python3
"""Adversarial tests for evidence packs: truncation, transplant, source integrity, fault injection."""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "src"))
sys.path.insert(0, HERE)

from agentbridge import evidence, signing  # noqa: E402
from agentbridge.core import Bridge, BridgeError  # noqa: E402
from agentbridge.jcs import canonical_bytes  # noqa: E402
import evidence_helpers as H  # noqa: E402

CASES = []


def case(fn):
    CASES.append(fn)
    return fn


def verify(pack, trust):
    return evidence.verify_pack(pack, trust).to_dict(pack)


@case
def H1_truncated_tail_with_receipt_fails():
    sc = H.prepare_pack()
    try:
        lines = open(os.path.join(sc["pack"], "originals/ledger.jsonl"), encoding="utf-8").read().splitlines()
        H.rewrite_ledger(sc["pack"], sc["exporter"], lines[:-1])
        result = verify(sc["pack"], sc["trust"])
        assert result["exit_code"] == 1, result["exit_code"]
        assert result["axes"]["anchoring"]["status"] == "fail", result["axes"]["anchoring"]
        assert "E-ANCHOR-MISMATCH" in result["axes"]["anchoring"]["codes"]
    finally:
        H.cleanup(sc["root"], sc["work"])


@case
def H2_truncation_without_receipt_is_unknown_not_pass():
    sc = H.prepare_pack()
    try:
        lines = open(os.path.join(sc["pack"], "originals/ledger.jsonl"), encoding="utf-8").read().splitlines()
        H.rewrite_ledger(sc["pack"], sc["exporter"], lines[:-1])
        manifest = json.load(open(os.path.join(sc["pack"], "manifest.json"), encoding="utf-8"))
        manifest["anchors"] = []
        manifest["signed_files"] = [i for i in manifest["signed_files"]
                                    if i["path"] != "originals/receipts/0.json"]
        H.write_json(os.path.join(sc["pack"], "manifest.json"), manifest)
        H.resign_manifest(sc["pack"], sc["exporter"])
        os.unlink(os.path.join(sc["pack"], "originals/receipts/0.json"))
        result = verify(sc["pack"], sc["trust"])
        assert result["exit_code"] == 2, result["exit_code"]
        assert result["axes"]["anchoring"]["status"] == "unknown", result["axes"]["anchoring"]
    finally:
        H.cleanup(sc["root"], sc["work"])


@case
def H3_export_does_not_write_the_source_bridge():
    sc = H.fresh()
    try:
        before = H.tree_snapshot(sc["root"])
        entries = sc["bridge"].entries()
        work = tempfile.mkdtemp(prefix="agentbridge-pack.")
        status_path = os.path.join(work, "status.json")
        receipt_path = os.path.join(work, "receipt.json")
        H.write_json(status_path, H.signed_status())
        H.write_json(receipt_path, H.signed_receipt(
            bridge_id=entries[-1].get("bridge_id", ""), seq=entries[-1]["seq"],
            digest=entries[-1]["digest"], received_at="2026-10-21T12:00:00+08:00"))
        exporter = signing.Signer("exporter", H.EXPORTER_SEED)
        pack = os.path.join(work, "pack")
        evidence.export_pack(sc["bridge"], pack, task_ref={"system": "t", "id": "1"},
                             delivery_id=sc["delivery_id"], exporter=exporter,
                             status_file=status_path, receipt_files=[receipt_path])
        after = H.tree_snapshot(sc["root"])
        assert before == after, "export modified the source bridge"
        exported = open(os.path.join(pack, "originals/ledger.jsonl"), "rb").read()
        source = open(os.path.join(sc["root"], "ledger.jsonl"), "rb").read()
        assert exported == source, "exported ledger is not a byte-for-byte prefix"
        H.cleanup(sc["root"], work)
    finally:
        shutil.rmtree(sc["root"], ignore_errors=True)


@case
def H4_acceptance_record_transplant_is_rejected():
    a = H.prepare_pack()
    b = H.prepare_pack()
    try:
        rec_a = open(os.path.join(a["pack"], "originals/acceptances",
                                  os.listdir(os.path.join(a["pack"], "originals/acceptances"))[0]), "rb").read()
        rel = os.path.join(b["pack"], "originals/acceptances",
                           os.listdir(os.path.join(b["pack"], "originals/acceptances"))[0])
        with open(rel, "wb") as f:
            f.write(rec_a)
        manifest = json.load(open(os.path.join(b["pack"], "manifest.json"), encoding="utf-8"))
        manifest["acceptances"][0]["record_sha256"] = evidence.sha_file(rel)
        for item in manifest["signed_files"]:
            if item["path"].startswith("originals/acceptances/"):
                item["sha256"] = evidence.sha_file(rel)
        H.write_json(os.path.join(b["pack"], "manifest.json"), manifest)
        H.resign_manifest(b["pack"], b["exporter"])
        result = verify(b["pack"], b["trust"])
        assert result["axes"]["acceptance"]["status"] == "fail", result["axes"]["acceptance"]
        assert "E-RECORD-MISMATCH" in result["axes"]["acceptance"]["codes"]
    finally:
        H.cleanup(a["root"], a["work"], b["root"], b["work"])


@case
def H5_foreign_acceptance_signer_is_not_trusted():
    sc = H.prepare_pack()
    try:
        manifest = json.load(open(os.path.join(sc["pack"], "manifest.json"), encoding="utf-8"))
        acc = manifest["acceptances"][0]
        attacker = signing.Signer("attacker", b"\x99" * 32)
        record = {"protocol_version": "0.1", "acceptance_id": acc["acceptance_id"],
                  "delivery_id": acc["delivery_id"], "version": acc["version"],
                  "artifacts_sha256": acc["artifacts_sha256"], "decision": acc["decision"],
                  "reason": "", "requires_anchoring": acc["requires_anchoring"],
                  "actor": acc["actor"], "signed_at": acc["signed_at"]}
        payload = b"agentbridge-evidence/0.1\nacceptance-record\n" + canonical_bytes(record)
        record["signature"] = {"alg": "ed25519", "pub": attacker.pub_hex,
                               "sig": attacker.sign_hex(payload)}
        rel = os.path.join(sc["pack"], acc["record_path"])
        H.write_json(rel, record)
        acc["record_sha256"] = evidence.sha_file(rel)
        for item in manifest["signed_files"]:
            if item["path"] == acc["record_path"]:
                item["sha256"] = evidence.sha_file(rel)
        H.write_json(os.path.join(sc["pack"], "manifest.json"), manifest)
        H.resign_manifest(sc["pack"], sc["exporter"])
        result = verify(sc["pack"], sc["trust"])
        assert result["axes"]["identity"]["status"] == "unknown", result["axes"]["identity"]
        assert "E-SIG-UNTRUSTED-KEY" in result["axes"]["identity"]["codes"], result["axes"]["identity"]
        assert result["axes"]["acceptance"]["status"] == "pass", result["axes"]["acceptance"]
    finally:
        H.cleanup(sc["root"], sc["work"])


@case
def H6_exit_code_aggregation_is_total():
    combos = [
        (["pass"] * 6, 0),
        (["pass", "pass", "fail", "pass", "pass", "pass"], 1),
        (["pass", "unknown", "pass", "pass", "pass", "pass"], 2),
        (["pass", "pass", "pass", "pass", "pass", "not_executed"], 2),
        (["pass", "not_evaluated", "pass", "pass", "pass", "pass"], 2),
        (["not_applicable"] * 6, 0),
        (["fail", "unknown", "pass", "pass", "pass", "pass"], 1),
    ]
    for statuses, expected in combos:
        r = evidence.Result()
        for axis, status in zip(evidence.AXES, statuses):
            r.ck(axis, "t", status)
        assert r.exit_code() == expected, (statuses, r.exit_code(), expected)
    bad = evidence.Result()
    bad.protocol("x")
    assert bad.exit_code() == 3


@case
def H7_acceptance_rollback_on_ledger_failure():
    sc = H.fresh()
    b = sc["bridge"]
    try:
        record = os.path.join(b.wire, "acceptances", "acc-" + sc["delivery_id"] + ".json")

        def boom(*_a, **_k):
            raise BridgeError("injected ledger failure")

        original = b._append
        b._append = boom
        try:
            b.accept_delivery("client", sc["delivery_id"], version="v1")
            raise AssertionError("accept_delivery should have raised")
        except BridgeError:
            pass
        finally:
            b._append = original
        assert not os.path.exists(record), "orphan acceptance record left after failed append"
        assert not [e for e in b.entries() if e.get("type") == "accept"]
    finally:
        shutil.rmtree(sc["root"], ignore_errors=True)


@case
def H8_snapshot_never_returns_partial_lines():
    sc = H.fresh()
    b = sc["bridge"]
    base = len(b.entries())
    stop = threading.Event()

    def writer():
        for i in range(40):
            b._append({"type": "note", "actor": "client", "i": i})
        stop.set()

    t = threading.Thread(target=writer)
    t.start()
    counts = []
    while not stop.is_set():
        entries, bad = b.snapshot()
        assert not bad, f"partial/corrupt lines: {bad}"
        counts.append(len(entries))
    t.join()
    assert counts == sorted(counts), "snapshot count went backwards"
    assert len(b.entries()) == base + 40
    shutil.rmtree(sc["root"], ignore_errors=True)


@case
def H9_default_deny_for_malformed_packs():
    def mutate(pack, mutate_fn):
        sc = H.prepare_pack()
        try:
            mutate_fn(sc)
            H.resign_manifest(sc["pack"], sc["exporter"])
            result = verify(sc["pack"], sc["trust"])
            assert result["exit_code"] in (1, 3), result["exit_code"]
            assert result["axes"]["integrity"]["status"] != "pass", result["axes"]["integrity"]
        finally:
            H.cleanup(sc["root"], sc["work"])

    def empty_ledger(sc):
        open(os.path.join(sc["pack"], "originals/ledger.jsonl"), "w").close()
        manifest = json.load(open(os.path.join(sc["pack"], "manifest.json"), encoding="utf-8"))
        manifest["signed_files"] = [i for i in manifest["signed_files"]
                                    if i["path"] != "originals/ledger.jsonl"]
        manifest["ledger"]["sha256"] = H.sha_file(os.path.join(sc["pack"], "originals/ledger.jsonl"))
        H.write_json(os.path.join(sc["pack"], "manifest.json"), manifest)

    def half_line(sc):
        path = os.path.join(sc["pack"], "originals/ledger.jsonl")
        with open(path, "a", encoding="utf-8") as f:
            f.write('{"type":')
        manifest = json.load(open(os.path.join(sc["pack"], "manifest.json"), encoding="utf-8"))
        manifest["ledger"]["sha256"] = H.sha_file(path)
        for item in manifest["signed_files"]:
            if item["path"] == "originals/ledger.jsonl":
                item["sha256"] = H.sha_file(path)
        H.write_json(os.path.join(sc["pack"], "manifest.json"), manifest)

    def bad_content_mode(sc):
        manifest = json.load(open(os.path.join(sc["pack"], "manifest.json"), encoding="utf-8"))
        manifest["content_mode"] = "full"
        H.write_json(os.path.join(sc["pack"], "manifest.json"), manifest)

    def missing_field(sc):
        manifest = json.load(open(os.path.join(sc["pack"], "manifest.json"), encoding="utf-8"))
        del manifest["ledger"]
        H.write_json(os.path.join(sc["pack"], "manifest.json"), manifest)

    for fn in (empty_ledger, half_line, bad_content_mode, missing_field):
        mutate(None, fn)


@case
def H10_golden_061_artifacts_still_verify():
    src = os.path.join(ROOT, "tests", "golden", "0.6.1", "bridge")
    tmp = tempfile.mkdtemp(prefix="agentbridge-golden.")
    dst = os.path.join(tmp, "bridge")
    shutil.copytree(src, dst)
    try:
        report = Bridge(dst).verify()
        assert report.ok, report.problems
        assert len(Bridge(dst).entries()) >= 5
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


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
