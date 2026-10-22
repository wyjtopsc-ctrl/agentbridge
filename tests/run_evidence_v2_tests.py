#!/usr/bin/env python3
"""End-to-end v0.2 tests: real bridge, reject -> rotate -> revise -> accept -> export -> verify."""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "src"))
sys.path.insert(0, HERE)

from agentbridge import evidence, signing  # noqa: E402
from agentbridge.core import Bridge, bridge_id_of  # noqa: E402
import evidence_helpers as H  # noqa: E402

CASES = []


def case(fn):
    CASES.append(fn)
    return fn


def build_flow(revoke_kind=None):
    root = tempfile.mkdtemp(prefix="agentbridge-v2.")
    client = signing.Signer("client", b"\x22" * 32)
    worker = signing.Signer("worker", b"\x11" * 32)
    new_worker = signing.Signer("worker", b"\x66" * 32)
    b = Bridge(root, client)
    b.init(actor="client")
    b.register_actor("client", client.pub_hex)
    wb = Bridge(root, worker)
    wb.register_actor("worker", worker.pub_hex)

    req = os.path.join(root, "request.md")
    rep1 = os.path.join(root, "report-v1.md")
    rep2 = os.path.join(root, "report-v2.md")
    open(req, "w").write("request\n")
    open(rep1, "w").write("report v1\n")
    open(rep2, "w").write("report v2, fixed\n")
    sent = b.send(actor="client", to="worker", body="do it", attach=[req])
    v1 = wb.deliver(actor="worker", to="client", in_reply_to=sent["id"],
                    body="v1", attach=[rep1])
    b.accept_delivery("client", v1["id"], decision="rejected", reason="missing tests")
    wb.rotate_key(new_worker, reason="routine")
    wb2 = Bridge(root, new_worker)
    v2 = wb2.deliver(actor="worker", to="client", in_reply_to=sent["id"],
                     body="v2", attach=[rep2], version="v2", revises=v1["id"])
    b.accept_delivery("client", v2["id"], decision="accepted")
    if revoke_kind:
        b.revoke_key(revoke_kind)

    entries = b.entries()
    status_seed, service_seed = b"\x44" * 32, b"\x33" * 32
    work = tempfile.mkdtemp(prefix="agentbridge-v2pack.")
    status_path = os.path.join(work, "status.json")
    receipt_path = os.path.join(work, "receipt.json")
    H.write_json(status_path, H.signed_status(status_seed))
    H.write_json(receipt_path, H.signed_receipt(
        seed=service_seed, bridge_id=bridge_id_of(entries), seq=entries[-1]["seq"],
        digest=entries[-1]["digest"], received_at="2026-10-21T12:00:00+08:00"))
    exporter = signing.Signer("exporter", H.EXPORTER_SEED)
    pack = os.path.join(work, "pack")
    evidence.export_pack(b, pack, task_ref={"system": "test", "id": "T-2"},
                         delivery_id=v2["id"], exporter=exporter,
                         status_file=status_path, receipt_files=[receipt_path])
    trust = H.trust_for(entries, exporter.pub_hex, v1["id"], status_seed, service_seed)
    trust["expected_versions"] = {v1["id"]: "v2"}
    trust_path = os.path.join(work, "trust.json")
    H.write_json(trust_path, trust)
    return {"root": root, "work": work, "pack": pack, "trust": trust_path,
            "bridge": b, "new_worker": new_worker, "status": status_path,
            "receipt": receipt_path, "exporter": exporter,
            "v1": v1, "v2": v2, "manifest": json.load(
                open(os.path.join(pack, "manifest.json"), encoding="utf-8"))}


@case
def V1_revision_flow_exports_all_versions():
    sc = build_flow()
    try:
        manifest = sc["manifest"]
        versions = [(d["version"], d["previous_version"]) for d in manifest["deliveries"]]
        assert versions == [("v1", None), ("v2", "v1")], versions
        kinds = [h["kind"] for h in manifest["identity"]["history"]]
        assert "rotate" in kinds, kinds
        assert manifest["pack_version"] == "agentbridge-evidence/0.2"
        result = evidence.verify_pack(sc["pack"], sc["trust"]).to_dict(sc["pack"])
        assert result["exit_code"] == 2, result
        for axis in ("integrity", "identity", "acceptance", "coverage", "anchoring"):
            assert result["axes"][axis]["status"] == "pass", (axis, result["axes"][axis])
        assert result["axes"]["content"]["status"] == "not_executed"
        assert result["axes"]["integrity"]["checks"]["history"]["status"] == "pass"
    finally:
        H.cleanup(sc["root"], sc["work"])


@case
def V2_rejection_of_superseded_version_is_flagged_not_failed():
    sc = build_flow()
    try:
        result = evidence.verify_pack(sc["pack"], sc["trust"]).to_dict(sc["pack"])
        superseded = result["axes"]["acceptance"]["details"].get("superseded", [])
        assert any(item["version"] == "v1" for item in superseded), superseded
        assert result["axes"]["acceptance"]["status"] == "pass"
    finally:
        H.cleanup(sc["root"], sc["work"])


@case
def V3_normal_retirement_keeps_history_valid():
    sc = build_flow(revoke_kind="normal_retirement")
    try:
        result = evidence.verify_pack(sc["pack"], sc["trust"]).to_dict(sc["pack"])
        assert result["axes"]["identity"]["status"] == "pass", result["axes"]["identity"]
    finally:
        H.cleanup(sc["root"], sc["work"])


@case
def V4_suspected_compromise_reports_uncertainty():
    sc = build_flow(revoke_kind="suspected_compromise")
    try:
        result = evidence.verify_pack(sc["pack"], sc["trust"]).to_dict(sc["pack"])
        assert result["axes"]["identity"]["status"] == "unknown", result["axes"]["identity"]
        assert "E-KEY-COMPROMISE-SUSPECTED" in result["axes"]["identity"]["codes"]
    finally:
        H.cleanup(sc["root"], sc["work"])


def resign(pack):
    path = os.path.join(pack, "manifest.json")
    manifest = json.load(open(path, encoding="utf-8"))
    manifest.pop("signatures", None)
    manifest["signatures"] = {"exporter": evidence.sign_domain(
        signing.Signer("exporter", H.EXPORTER_SEED), "manifest", manifest)}
    H.write_json(path, manifest)


@case
def V6_duplicate_version_is_rejected():
    sc = build_flow()
    try:
        path = os.path.join(sc["pack"], "manifest.json")
        manifest = json.load(open(path, encoding="utf-8"))
        manifest["deliveries"][1]["version"] = manifest["deliveries"][0]["version"]
        H.write_json(path, manifest)
        resign(sc["pack"])
        result = evidence.verify_pack(sc["pack"], sc["trust"]).to_dict(sc["pack"])
        assert result["axes"]["integrity"]["status"] == "fail", result["axes"]["integrity"]
        assert "E-DUPLICATE-VERSION" in result["axes"]["integrity"]["codes"]
    finally:
        H.cleanup(sc["root"], sc["work"])


@case
def V7_broken_previous_version_is_rejected():
    sc = build_flow()
    try:
        path = os.path.join(sc["pack"], "manifest.json")
        manifest = json.load(open(path, encoding="utf-8"))
        manifest["deliveries"][1]["previous_version"] = "vX"
        H.write_json(path, manifest)
        resign(sc["pack"])
        result = evidence.verify_pack(sc["pack"], sc["trust"]).to_dict(sc["pack"])
        assert result["axes"]["integrity"]["status"] == "fail", result["axes"]["integrity"]
        assert "E-REVISION-CHAIN" in result["axes"]["integrity"]["codes"]
    finally:
        H.cleanup(sc["root"], sc["work"])


@case
def V8_tampered_superseded_acceptance_still_fails():
    sc = build_flow()
    try:
        manifest = json.load(open(os.path.join(sc["pack"], "manifest.json"), encoding="utf-8"))
        rejection = [a for a in manifest["acceptances"] if a["version"] == "v1"][0]
        path = os.path.join(sc["pack"], rejection["record_path"])
        record = json.load(open(path, encoding="utf-8"))
        record["artifacts_sha256"] = ["00" * 32]
        H.write_json(path, record)
        rejection["record_sha256"] = evidence.sha_file(path)
        for item in manifest["signed_files"]:
            if item["path"] == rejection["record_path"]:
                item["sha256"] = evidence.sha_file(path)
        H.write_json(os.path.join(sc["pack"], "manifest.json"), manifest)
        resign(sc["pack"])
        result = evidence.verify_pack(sc["pack"], sc["trust"]).to_dict(sc["pack"])
        assert result["axes"]["acceptance"]["status"] == "fail", result["axes"]["acceptance"]
    finally:
        H.cleanup(sc["root"], sc["work"])


@case
def V9_hashes_only_disclosure_is_reported():
    sc = build_flow()
    try:
        result = evidence.verify_pack(sc["pack"], sc["trust"]).to_dict(sc["pack"])
        assert any("hashes_only" in line for line in result["disclosure"]), result["disclosure"]
        assert any("未复核文件内容" in line for line in result["disclosure"])
    finally:
        H.cleanup(sc["root"], sc["work"])


@case
def V10_manifest_revision_binding_must_match_ledger():
    sc = build_flow()
    try:
        manifest = json.load(open(os.path.join(sc["pack"], "manifest.json"), encoding="utf-8"))
        manifest["deliveries"][1]["previous_version"] = None
        H.write_json(os.path.join(sc["pack"], "manifest.json"), manifest)
        resign(sc["pack"])
        result = evidence.verify_pack(sc["pack"], sc["trust"]).to_dict(sc["pack"])
        assert result["axes"]["integrity"]["status"] == "fail", result["axes"]["integrity"]
        assert "E-DELIVERY-BINDING" in result["axes"]["integrity"]["codes"]
    finally:
        H.cleanup(sc["root"], sc["work"])


@case
def V11_rotation_after_compromise_does_not_restore_trust():
    sc = build_flow()
    try:
        # worker rotated earlier; now record a compromise whose leak predates that rotation
        sc["new_worker_bridge"] = Bridge(sc["root"], sc["new_worker"])
        sc["new_worker_bridge"].revoke_key(
            "suspected_compromise", suspected_leak_at="2026-10-21T00:00:00+08:00",
            evidence="leak predates rotation")
        entries = sc["new_worker_bridge"].entries()
        status_path = os.path.join(sc["work"], "status2.json")
        receipt_path = os.path.join(sc["work"], "receipt2.json")
        H.write_json(status_path, H.signed_status())
        H.write_json(receipt_path, H.signed_receipt(
            bridge_id=bridge_id_of(entries), seq=entries[-1]["seq"],
            digest=entries[-1]["digest"], received_at="2026-10-21T12:00:00+08:00"))
        pack2 = os.path.join(sc["work"], "pack2")
        evidence.export_pack(sc["new_worker_bridge"], pack2,
                             task_ref={"system": "test", "id": "T-3"},
                             delivery_id=sc["v2"]["id"], exporter=sc["exporter"],
                             status_file=status_path, receipt_files=[receipt_path])
        trust2 = os.path.join(sc["work"], "trust2.json")
        H.write_json(trust2, H.trust_for(entries, sc["exporter"].pub_hex, sc["v1"]["id"]))
        result = evidence.verify_pack(pack2, trust2).to_dict(pack2)
        assert result["axes"]["integrity"]["status"] == "fail", result["axes"]["integrity"]
        assert "E-ROTATE-AFTER-COMPROMISE" in result["axes"]["integrity"]["codes"]
        assert result["axes"]["identity"]["status"] == "unknown"
    finally:
        H.cleanup(sc["root"], sc["work"])


@case
def V12_concurrent_export_uses_a_consistent_snapshot():
    import threading
    sc = build_flow()
    try:
        out = os.path.join(sc["work"], "pack-concurrent")
        stop = threading.Event()

        def writer():
            b = Bridge(sc["root"])
            for i in range(25):
                b._append({"type": "note", "actor": "client", "i": i})
            stop.set()

        t = threading.Thread(target=writer)
        t.start()
        evidence.export_pack(sc["bridge"], out, task_ref={"system": "test", "id": "T-4"},
                             delivery_id=sc["v2"]["id"], exporter=sc["exporter"],
                             status_file=sc["status"], receipt_files=[sc["receipt"]])
        t.join()
        manifest = json.load(open(os.path.join(out, "manifest.json"), encoding="utf-8"))
        lines = open(os.path.join(out, "originals/ledger.jsonl"), encoding="utf-8").read().splitlines()
        assert manifest["ledger"]["tip_seq"] == len(lines) - 1
        assert json.loads(lines[-1])["digest"] == manifest["ledger"]["tip_digest"]
        result = evidence.verify_pack(out, sc["trust"]).to_dict(out)
        assert result["axes"]["integrity"]["status"] == "pass", result["axes"]["integrity"]
    finally:
        H.cleanup(sc["root"], sc["work"])


@case
def V5_rotated_key_is_used_for_acceptance():
    sc = build_flow()
    try:
        manifest = sc["manifest"]
        record = json.load(open(os.path.join(
            sc["pack"], manifest["acceptances"][0]["record_path"]), encoding="utf-8"))
        assert record["actor"] == "client"
        result = evidence.verify_pack(sc["pack"], sc["trust"]).to_dict(sc["pack"])
        assert result["axes"]["identity"]["checks"]["records_signed"]["status"] == "pass"
    finally:
        H.cleanup(sc["root"], sc["work"])


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
