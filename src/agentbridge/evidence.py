"""Evidence pack v0: export a bridge's delivery evidence and verify it offline.

This is product code (not the tools/ reference used for protocol fixtures). It keeps legacy
signature rules for old objects and domain-separated rules for new ones.
"""
from __future__ import annotations

import argparse
import datetime
import fcntl
import hashlib
import json
import os
import sys

from . import signing
from .jcs import canonical_bytes, loads_strict

PROTOCOL = "agentbridge-evidence/0.1"


def sha_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _ledger_timeline(entries):
    """Replay register/rotate/revoke from the original ledger slice."""
    current, history, initial, revocations = {}, {}, {}, []
    for e in entries:
        typ, actor = e.get("type"), e.get("actor")
        if typ == "actor_register" and actor and e.get("pub"):
            if actor not in current:
                current[actor] = e["pub"]
                initial[actor] = e["pub"]
                history[actor] = [(e["seq"], e["pub"])]
        elif typ == "rotate" and actor and current.get(actor) == e.get("old_pub"):
            current[actor] = e.get("new_pub")
            history.setdefault(actor, []).append((e["seq"], e.get("new_pub")))
        elif typ == "revoke" and actor:
            revocations.append(e)
    return current, history, initial, revocations


def _key_at(history, actor, seq):
    found = None
    for start, pub in history.get(actor, []):
        if start < seq:
            found = pub
        else:
            break
    return found

AXES = ("integrity", "identity", "acceptance", "coverage", "anchoring", "content")
PRIORITY = {"pass": 0, "not_applicable": 0, "not_executed": 1, "not_evaluated": 1,
            "unknown": 2, "fail": 3}


def sha_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def read_bytes(path):
    with open(path, "rb") as f:
        return f.read()


def parse_dt(value):
    return datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))


class Result:
    def __init__(self):
        self.axes = {a: {"status": "pass", "codes": [], "checks": {}, "details": {}} for a in AXES}
        self.flags = []
        self.protocol_error = None
        self.disclosure: list[str] = []

    def set_status(self, axis, status):
        slot = self.axes[axis]
        if PRIORITY[status] > PRIORITY[slot["status"]]:
            slot["status"] = status
        if status in ("not_executed", "not_evaluated") and status not in self.flags:
            self.flags.append(status)

    def ck(self, axis, name, status, code=None, **details):
        self.axes[axis]["checks"][name] = {"status": status}
        if status == "not_evaluated":
            self.flags.append("not_evaluated") if "not_evaluated" not in self.flags else None
        if status == "not_executed" and "not_executed" not in self.flags:
            self.flags.append("not_executed")
        if code:
            self.axes[axis]["codes"].append(code) if code not in self.axes[axis]["codes"] else None
        if details:
            self.axes[axis]["details"].update(details)
        self.set_status(axis, status)

    def protocol(self, message):
        self.protocol_error = message
        for axis in AXES:
            self.axes[axis]["status"] = "not_evaluated"
            self.axes[axis]["checks"] = {"protocol": {"status": "not_evaluated"}}

    def exit_code(self):
        if self.protocol_error:
            return 3
        if any(a["status"] == "fail" for a in self.axes.values()):
            return 1
        if self.flags or any(a["status"] == "unknown" for a in self.axes.values()):
            return 2
        return 0

    def to_dict(self, pack):
        return {"pack": pack, "axes": self.axes, "exit_code": self.exit_code(),
                "protocol_error": self.protocol_error, "disclosure": self.disclosure}


def _verify(pack_dir, trust_path):
    res = Result()
    pack_dir = os.path.realpath(pack_dir)
    trust_path = os.path.realpath(trust_path)
    if os.path.commonpath([pack_dir, trust_path]) == pack_dir:
        res.protocol("trust file must not be inside the pack (E-TRUST-INSIDE-PACK)")
        return res
    try:
        trust = loads_strict(read_bytes(trust_path).decode("utf-8"))
        manifest = loads_strict(read_bytes(os.path.join(pack_dir, "manifest.json")).decode("utf-8"))
    except Exception as exc:  # noqa: BLE001
        res.protocol(f"{type(exc).__name__}: {exc}")
        return res
    required = ["pack_version", "created_at", "as_of", "bridge_id", "task", "deliveries",
                "identity", "ledger", "envelopes", "anchors", "coverage", "content_mode",
                "limits", "signed_files", "signatures"]
    missing = [key for key in required if key not in manifest]
    if missing:
        res.protocol(f"manifest missing fields: {missing} (E-SCHEMA)")
        return res
    if manifest.get("content_mode") != "hashes_only":
        res.protocol("unsupported content_mode (E-CONTENT-MODE-UNSUPPORTED)")
        return res
    res.ck("content", "executed", "not_executed", "E-CONTENT-NOT-EXECUTED")
    res.disclosure = ["content_mode=hashes_only：核验的是交付摘要与签署记录，未复核文件内容。"]

    # pack signature
    try:
        sig = manifest["signatures"]["exporter"]
        body = {k: v for k, v in manifest.items() if k != "signatures"}
        payload = b"agentbridge-evidence/0.1\nmanifest\n" + canonical_bytes(body)
        if not signing.verify(bytes.fromhex(sig["pub"]), payload, bytes.fromhex(sig["sig"])):
            res.ck("integrity", "pack_signature", "fail", "E-PACK-SIG")
            res.ck("identity", "pack_signature", "unknown", "E-PACK-SIG")
        else:
            res.ck("integrity", "pack_signature", "pass")
    except Exception as exc:  # noqa: BLE001
        res.protocol(f"manifest signature: {exc}")
        return res
    expected_exporter = trust.get("expected_exporter", {}).get("fingerprint")
    if expected_exporter and signing.fingerprint(sig["pub"]) != expected_exporter:
        res.ck("identity", "pack_signature", "unknown", "E-TRUST-NOT-ESTABLISHED")
    else:
        res.ck("identity", "pack_signature", "pass")

    # signed files
    files_ok = True
    for item in manifest.get("signed_files", []):
        path = os.path.join(pack_dir, item["path"])
        if not os.path.isfile(path) or sha_file(path) != item["sha256"]:
            res.ck("integrity", "files", "fail", "E-PACK-FILE-MISMATCH", path=item["path"])
            files_ok = False
    if files_ok:
        res.ck("integrity", "files", "pass")

    # ledger
    try:
        lines = [ln for ln in read_bytes(os.path.join(pack_dir, manifest["ledger"]["path"]))
                 .decode().splitlines() if ln.strip()]
        entries = [loads_strict(ln) for ln in lines]
    except Exception as exc:  # noqa: BLE001
        res.protocol(f"ledger parse: {exc}")
        return res
    if not entries or entries[0].get("type") != "genesis":
        res.protocol("empty ledger or missing genesis (E-CHAIN-GAP)")
        return res
    chain_ok = True
    prev = "GENESIS"
    for i, e in enumerate(entries):
        body = {k: v for k, v in e.items()
                if k not in ("digest", "sig", "sig_pub", "new_sig")}
        if e.get("type") != "genesis" and (e.get("seq") != i or e.get("prev") != prev):
            chain_ok = False
            res.ck("integrity", "chain", "fail", "E-CHAIN-GAP", detail=f"seq/prev at {i}")
        if hashlib.sha256(canonical_bytes(body)).hexdigest() != e.get("digest"):
            chain_ok = False
            res.ck("integrity", "chain", "fail", "E-CHAIN-GAP", detail=f"digest at {i}")
        prev = e.get("digest", prev)
    if chain_ok:
        res.ck("integrity", "chain", "pass")
    tip = entries[-1] if entries else {}
    if tip.get("seq") == manifest["ledger"]["tip_seq"] and tip.get("digest") == manifest["ledger"]["tip_digest"]:
        res.ck("integrity", "tip", "pass")
    else:
        res.ck("integrity", "tip", "fail", "E-TIP-MISMATCH")

    # key timeline from the original ledger slice; manifest history is only a claim to check
    current_keys, key_history, initial_keys, revocations = _ledger_timeline(entries)
    expected_actors = {a["actor"]: a["fingerprint"] for a in trust.get("expected_actors", [])}
    revocations_by_actor = {}
    for e in entries:
        if e.get("type") == "revoke" and e.get("actor"):
            revocations_by_actor.setdefault(e["actor"], []).append(e)
    trusted = set()
    for e in entries:
        typ, actor = e.get("type"), e.get("actor")
        if typ == "actor_register" and actor and \
                expected_actors.get(actor) == signing.fingerprint(e.get("pub", "")):
            trusted.add(e.get("pub"))
        elif typ == "rotate":
            if e.get("old_pub") not in trusted:
                continue
            blocked = False
            for rev in revocations_by_actor.get(actor, []):
                kind = rev.get("kind")
                if kind == "suspected_compromise":
                    leak = rev.get("suspected_leak_at")
                    # unknown leak start: cannot prove the rotation came before the boundary
                    if not leak or str(e.get("ts", "")) >= str(leak):
                        blocked = True
                elif rev.get("effective_at") and str(e.get("ts", "")) >= str(rev["effective_at"]):
                    blocked = True
            if blocked:
                res.ck("integrity", "rotation_authorization", "fail",
                       "E-ROTATE-AFTER-COMPROMISE", seq=e.get("seq"))
            else:
                trusted.add(e.get("new_pub"))

    trust_ok = bool(expected_actors) and all(
        initial_keys.get(actor) and
        signing.fingerprint(initial_keys[actor]) == fp
        for actor, fp in expected_actors.items())
    if not expected_actors:
        res.ck("identity", "trust_set", "unknown", "E-TRUST-NOT-ESTABLISHED")
    elif trust_ok:
        res.ck("identity", "trust_set", "pass")
    else:
        res.ck("identity", "trust_set", "unknown", "E-TRUST-NOT-ESTABLISHED")

    if "history" in manifest["identity"]:
        by_seq = {e["seq"]: e for e in entries}
        kinds = {"register": "actor_register", "rotate": "rotate", "revoke": "revoke"}
        seen, ok = set(), True
        for item in manifest["identity"]["history"]:
            e = by_seq.get(item.get("ledger_seq"))
            if not e or e.get("type") != kinds.get(item.get("kind")) or \
                    e.get("digest") != item.get("digest"):
                ok = False
                break
            if item["kind"] == "register":
                good = e.get("actor") == item.get("actor") and e.get("pub") == item.get("pub")
            elif item["kind"] == "rotate":
                good = e.get("old_pub") == item.get("old_pub") and \
                       e.get("new_pub") == item.get("new_pub")
            else:
                good = e.get("fingerprint") == item.get("fingerprint") and \
                       e.get("kind") == item.get("revocation_kind")
            if not good:
                ok = False
                break
            seen.add(e["seq"])
        ledger_key_seqs = {e["seq"] for e in entries
                           if e.get("type") in ("actor_register", "rotate", "revoke")}
        if ok and seen == ledger_key_seqs:
            res.ck("integrity", "history", "pass")
        else:
            res.ck("integrity", "history", "fail", "E-HISTORY-MISMATCH")

    def verify_sig(pub_hex, message, sig_hex):
        return signing.verify(bytes.fromhex(pub_hex), message, bytes.fromhex(sig_hex))

    # ledger signatures against the key active at that position
    records_signed = True
    for e in entries:
        if not e.get("sig"):
            continue
        typ = e.get("type")
        if typ == "actor_register":
            expected_pub = e.get("pub")
        elif typ == "rotate":
            expected_pub = e.get("old_pub")
        else:
            expected_pub = _key_at(key_history, e.get("actor"), e.get("seq"))
        pub = e.get("sig_pub")
        if not verify_sig(pub or "", str(e.get("digest", "")).encode(), e["sig"]):
            res.ck("integrity", "ledger_signature", "fail", "E-SIG-INVALID", seq=e["seq"])
            res.ck("identity", "records_signed", "unknown", "E-SIG-INVALID")
            records_signed = False
        elif expected_pub and pub != expected_pub:
            res.ck("integrity", "ledger_signature", "fail", "E-SIG-KEY-MISMATCH", seq=e["seq"])
            records_signed = False
        if pub not in trusted:
            res.ck("identity", "records_signed", "unknown", "E-SIG-UNTRUSTED-KEY",
                   actor=e.get("actor"))
            records_signed = False
        if typ == "rotate":
            if not verify_sig(e.get("new_pub", ""), str(e.get("digest", "")).encode(),
                              e.get("new_sig", "")):
                res.ck("integrity", "ledger_signature", "fail", "E-ROTATE-PROOF", seq=e["seq"])
                records_signed = False
    if records_signed:
        res.ck("identity", "records_signed", "pass")
    for rev in revocations:
        kind = rev.get("kind")
        if kind == "normal_retirement":
            res.ck("identity", "revocation", "pass", actor=rev.get("actor"))
        elif kind == "suspected_compromise":
            res.ck("identity", "revocation", "unknown", "E-KEY-COMPROMISE-SUSPECTED",
                   actor=rev.get("actor"))
        else:
            res.ck("identity", "revocation", "unknown", "E-KEY-REVOKED", actor=rev.get("actor"))

    # deliveries / envelopes (v0.2: one logical delivery may have several versions)
    deliveries = {(d["delivery_id"], d["version"]): d for d in manifest["deliveries"]}
    by_logical = {}
    for d in manifest["deliveries"]:
        by_logical.setdefault(d["delivery_id"], []).append(d)
    for logical, rows in by_logical.items():
        versions = [r["version"] for r in rows]
        if len(versions) != len(set(versions)):
            res.ck("integrity", "revisions", "fail", "E-DUPLICATE-VERSION", delivery=logical)
            continue
        ordered = sorted(rows, key=lambda r: r["ledger_seq"])
        seen = set()
        for idx, row in enumerate(ordered):
            previous = row.get("previous_version")
            if idx == 0:
                if previous is not None:
                    res.ck("integrity", "revisions", "fail", "E-REVISION-CHAIN",
                           delivery=logical, version=row["version"])
            elif previous is None or previous not in seen:
                res.ck("integrity", "revisions", "fail", "E-REVISION-CHAIN",
                       delivery=logical, version=row["version"])
            seen.add(row["version"])
    for d in manifest["deliveries"]:
        env_path = os.path.join(pack_dir, d["envelope_path"])
        if not os.path.isfile(env_path) or sha_file(env_path) != d["envelope_sha256"]:
            res.ck("integrity", "envelope_binding", "fail", "E-ENVELOPE-MISMATCH", delivery=d["delivery_id"])
            res.ck("identity", "records_signed", "not_evaluated")
            continue
        env = loads_strict(read_bytes(env_path).decode())
        sig = env.get("signature", {})
        try:
            body = {k: v for k, v in env.items() if k != "signature"}
            sig_ok = verify_sig(sig["pub"], canonical_bytes(body), sig["sig"])
        except Exception:  # noqa: BLE001
            sig_ok = False
        if sig_ok:
            res.ck("integrity", "envelope_signature", "pass")
            key_expected = _key_at(key_history, d["sender"], d["ledger_seq"])
            if (key_expected and sig["pub"] != key_expected) or sig["pub"] not in trusted:
                res.ck("identity", "records_signed", "unknown", "E-SIG-UNTRUSTED-KEY")
        else:
            res.ck("integrity", "envelope_signature", "fail", "E-SIG-INVALID", delivery=d["delivery_id"])
            res.ck("identity", "records_signed", "unknown", "E-SIG-INVALID")
        entry = entries[d["ledger_seq"]]
        prev_row = next((r for r in by_logical.get(d["delivery_id"], [])
                         if r["version"] == d.get("previous_version")), None)
        expected_prev_ref = prev_row["envelope_id"] if prev_row else None
        if (entry.get("envelope_sha256") != sha_file(env_path)
                or entry.get("id") != d["envelope_id"]
                or entry.get("type") != "deliver"
                or entry.get("delivery_id") != d["delivery_id"]
                or entry.get("version") != d["version"]
                or entry.get("previous_delivery") != expected_prev_ref):
            res.ck("integrity", "envelope_binding", "fail", "E-ENVELOPE-MISMATCH", delivery=d["delivery_id"])
            res.ck("integrity", "delivery_binding", "fail", "E-DELIVERY-BINDING",
                   delivery=d["delivery_id"], version=d["version"])
        else:
            res.ck("integrity", "envelope_binding", "pass")

    # acceptances
    acceptance_by_delivery = {}
    accepted = manifest.get("acceptances", [])
    for acc in accepted:
        acceptance_by_delivery.setdefault((acc["delivery_id"], acc["version"]), []).append(acc)
        rec_path = os.path.join(pack_dir, acc["record_path"])
        if not os.path.isfile(rec_path) or sha_file(rec_path) != acc["record_sha256"]:
            res.ck("acceptance", "declaration", "fail", "E-RECORD-MISMATCH")
            continue
        record = loads_strict(read_bytes(rec_path).decode())
        try:
            body = {k: v for k, v in record.items() if k != "signature"}
            payload = b"agentbridge-evidence/0.1\nacceptance-record\n" + canonical_bytes(body)
            ok = verify_sig(record["signature"]["pub"], payload, record["signature"]["sig"])
        except Exception:  # noqa: BLE001
            ok = False
        superseded = False
        if ok:
            res.ck("acceptance", "declaration", "pass")
            mismatched = (record.get("delivery_id") != acc.get("delivery_id")
                          or record.get("version") != acc.get("version")
                          or sorted(record.get("artifacts_sha256", [])) != sorted(acc.get("artifacts_sha256", []))
                          or record.get("decision") != acc.get("decision")
                          or record.get("actor") != acc.get("actor"))
            if mismatched:
                res.ck("acceptance", "record_consistency", "fail", "E-RECORD-MISMATCH")
            key_expected = _key_at(key_history, acc["actor"], acc["ledger_seq"])
            if (key_expected and record["signature"]["pub"] != key_expected) or \
                    record["signature"]["pub"] not in trusted:
                res.ck("identity", "records_signed", "unknown", "E-SIG-UNTRUSTED-KEY")
            superseded = any(r["ledger_seq"] > acc["ledger_seq"]
                             for r in by_logical.get(acc["delivery_id"], []))
            if superseded:
                res.axes["acceptance"]["details"].setdefault("superseded", []).append(
                    {"acceptance_id": acc["acceptance_id"], "version": acc["version"]})
        else:
            res.ck("acceptance", "declaration", "fail", "E-SIG-INVALID")
            res.ck("identity", "records_signed", "unknown", "E-SIG-INVALID")
        d = deliveries.get((acc["delivery_id"], acc["version"]))
        if d is None:
            res.ck("acceptance", "binding", "fail", "E-ACC-DANGLING")
            continue
        if acc["version"] != d["version"] or sorted(acc["artifacts_sha256"]) != sorted(a["sha256"] for a in d["artifacts"]):
            res.ck("acceptance", "binding", "fail", "E-ACC-BINDING")
        else:
            res.ck("acceptance", "binding", "pass")
        expected = trust.get("expected_versions", {}).get(acc["delivery_id"])
        if superseded:
            res.ck("acceptance", "expectation", "not_applicable", "E-SUPERSEDED-VERSION")
        elif expected is None:
            res.ck("acceptance", "expectation", "not_evaluated", "E-EXPECTATION-NOT-PROVIDED")
        elif expected == d["version"]:
            res.ck("acceptance", "expectation", "pass")
        else:
            res.ck("acceptance", "expectation", "fail", "E-EXPECT-VERSION-MISMATCH")
    for group, items in acceptance_by_delivery.items():
        if len(items) > 1 and len({i["decision"] for i in items}) > 1:
            res.ck("acceptance", "conflict", "unknown", "E-ACC-CONFLICT",
                   delivery=group[0], version=group[1])

    # anchoring
    anchors = manifest.get("anchors", [])
    coverage = -1
    trusted_service = set(trust.get("anchor_service_pubs", []))
    if not anchors:
        res.ck("anchoring", "coverage", "unknown", "E-ANCHOR-MISSING")
    for anchor in anchors:
        path = os.path.join(pack_dir, anchor["path"])
        if not os.path.isfile(path) or sha_file(path) != anchor["sha256"]:
            res.ck("integrity", "receipt", "fail", "E-PACK-FILE-MISMATCH", path=anchor["path"])
            continue
        receipt = loads_strict(read_bytes(path).decode())
        if trust.get("expected_bridge_id") and receipt.get("bridge_id") != trust["expected_bridge_id"]:
            res.ck("anchoring", "bridge", "fail", "E-ANCHOR-BRIDGE-MISMATCH")
        if receipt.get("service_pub") not in trusted_service:
            res.ck("identity", "records_signed", "unknown", "E-ANCHOR-UNTRUSTED")
            res.ck("anchoring", "coverage", "unknown", "E-ANCHOR-UNTRUSTED")
            continue
        body = {k: v for k, v in receipt.items() if k != "service_sig"}
        if not verify_sig(receipt["service_pub"], canonical_bytes(body), receipt["service_sig"]):
            res.ck("integrity", "receipt", "fail", "E-ANCHOR-SIG")
            continue
        seq = receipt.get("seq", -1)
        if not (0 <= seq < len(entries)) or entries[seq].get("digest") != receipt.get("digest"):
            res.ck("anchoring", "covers", "fail", "E-ANCHOR-MISMATCH", seq=seq)
            continue
        res.ck("anchoring", "covers", "pass")
        coverage = max(coverage, seq)
    if anchors and coverage >= 0:
        minimum = trust.get("minimum_checkpoint_seq", 0)
        if coverage < minimum:
            res.ck("anchoring", "minimum", "fail", "E-ANCHOR-BELOW-MINIMUM",
                   coverage=coverage, minimum=minimum)
        else:
            res.ck("anchoring", "minimum", "pass")
        checkpoint = trust.get("known_checkpoint")
        if checkpoint:
            seq = checkpoint.get("seq", -1)
            if checkpoint.get("bridge_id") and checkpoint["bridge_id"] != manifest["bridge_id"]:
                res.ck("anchoring", "checkpoint", "fail", "E-CHECKPOINT-BRIDGE-MISMATCH")
            elif not (0 <= seq < len(entries)):
                res.ck("anchoring", "checkpoint", "fail", "E-CHECKPOINT-OUT-OF-RANGE")
            elif entries[seq].get("digest") != checkpoint.get("digest"):
                res.ck("anchoring", "checkpoint", "fail", "E-CHECKPOINT-MISMATCH")
            else:
                res.ck("anchoring", "checkpoint", "pass")
        res.axes["anchoring"]["details"]["latest"] = "unknown offline"
        for acc in accepted:
            if acc.get("requires_anchoring") and coverage < acc["ledger_seq"]:
                res.ck("acceptance", "anchoring_requirement", "fail", "E-ACC-REQUIRES-ANCHOR")
    else:
        for acc in accepted:
            if acc.get("requires_anchoring"):
                res.ck("acceptance", "anchoring_requirement", "fail", "E-ACC-REQUIRES-ANCHOR")

    # status / revocation
    status_ref = manifest["identity"]["status"]
    status_path = os.path.join(pack_dir, status_ref["path"])
    if not os.path.isfile(status_path) or sha_file(status_path) != status_ref["sha256"]:
        res.ck("identity", "status", "unknown", "E-KEY-STATUS-UNKNOWN")
    else:
        try:
            st = loads_strict(read_bytes(status_path).decode())
            body = {k: v for k, v in st.items() if k != "signature"}
            if st.get("publisher_pub") != trust.get("status_publisher_pub"):
                res.ck("identity", "status", "unknown", "E-TRUST-NOT-ESTABLISHED")
            elif not verify_sig(st["publisher_pub"],
                                b"agentbridge-evidence/0.1\nstatus\n" + canonical_bytes(body),
                                st["signature"]["sig"]):
                res.ck("identity", "status", "unknown", "E-KEY-STATUS-UNKNOWN")
            else:
                published = parse_dt(st["published_at"])
                valid_until = parse_dt(st["valid_until"])
                as_of = parse_dt(manifest["as_of"]["key_status"])
                if as_of > valid_until or (as_of - published).total_seconds() > trust.get("max_status_age_hours", 24) * 3600:
                    res.ck("identity", "status", "unknown", "E-KEY-STATUS-STALE")
                else:
                    res.ck("identity", "status", "pass")
                trusted_bounds = []
                for anchor in manifest.get("anchors", []):
                    p = os.path.join(pack_dir, anchor["path"])
                    if os.path.isfile(p):
                        r = loads_strict(read_bytes(p).decode())
                        trusted_bounds.append((r.get("seq", -1), parse_dt(r["received_at"])))
                for rev in st.get("revocations", []):
                    kind = rev.get("kind")
                    if kind == "normal_retirement":
                        res.ck("identity", "revocation", "pass")
                        continue
                    if kind == "revoked":
                        res.ck("identity", "revocation", "fail", "E-KEY-REVOKED", actor=rev["actor"])
                    elif kind == "suspected_compromise":
                        leak = rev.get("suspected_leak_at")
                        if not leak:
                            res.ck("identity", "revocation", "unknown",
                                   "E-KEY-COMPROMISE-START-UNKNOWN", actor=rev["actor"])
                        else:
                            leak_at = parse_dt(leak)
                            bounded = any(seq >= 4 and when < leak_at for seq, when in trusted_bounds)
                            if bounded:
                                res.ck("identity", "revocation", "pass")
                            else:
                                res.ck("identity", "revocation", "unknown",
                                       "E-KEY-COMPROMISE-SUSPECTED", actor=rev["actor"])
        except Exception as exc:  # noqa: BLE001
            res.ck("identity", "status", "unknown", "E-KEY-STATUS-UNKNOWN", detail=str(exc))

    # coverage axis
    cov = manifest.get("coverage", {})
    if cov.get("gaps"):
        res.ck("coverage", "gaps", "unknown", "E-COVERAGE-GAP", gaps=cov["gaps"])
    else:
        res.ck("coverage", "gaps", "pass")
    return res




def sign_domain(signer, record_type: str, body: dict) -> dict:
    payload = (PROTOCOL + "\n" + record_type + "\n").encode() + canonical_bytes(body)
    return {"alg": "ed25519", "pub": signer.pub_hex, "sig": signer.sign_hex(payload)}


def export_pack(bridge, out_dir: str, *, task_ref: dict, delivery_id: str,
                exporter, status_file: str, receipt_files=(), version: str | None = None) -> dict:
    """Export under a shared ledger lock, so concurrent writers are blocked for the whole read."""
    with open(bridge.ledger, "rb") as lockf:
        fcntl.flock(lockf, fcntl.LOCK_SH)
        try:
            return _export_pack_locked(bridge, out_dir, task_ref=task_ref,
                                       delivery_id=delivery_id, exporter=exporter,
                                       status_file=status_file, receipt_files=receipt_files,
                                       version=version)
        finally:
            fcntl.flock(lockf, fcntl.LOCK_UN)


def _export_pack_locked(bridge, out_dir: str, *, task_ref: dict, delivery_id: str,
                        exporter, status_file: str, receipt_files=(), version: str | None = None) -> dict:
    from .core import now

    entries = bridge.entries()
    target = next((e for e in entries if e.get("id") == delivery_id), None)
    if not target or target.get("type") != "deliver":
        raise ValueError(f"not a recorded delivery: {delivery_id}")
    logical = target.get("delivery_id") or target["id"]
    versions = sorted(
        [e for e in entries if e.get("type") == "deliver"
         and (e.get("delivery_id") or e["id"]) == logical],
        key=lambda e: e["seq"])
    by_ref = {e["id"]: e for e in versions}
    if version and target.get("version") != version:
        raise ValueError(f"delivery {delivery_id} is version {target.get('version')}, not {version}")

    env_cache = {}
    for e in versions:
        path = None
        for box in (bridge.inbox, bridge.outbox, bridge.archive):
            candidate = os.path.join(box, e["id"] + ".json")
            if os.path.isfile(candidate):
                path = candidate
                break
        if path is None:
            raise ValueError(f"envelope file not found for delivery {e['id']}")
        env_cache[e["id"]] = (path, loads_strict(open(path, encoding="utf-8").read()))

    request_ids = []
    for e in versions:
        ref = e.get("in_reply_to")
        if ref and ref not in request_ids:
            request_ids.append(ref)
    request_paths = {}
    for ref in request_ids:
        req = next((x for x in entries if x.get("type") == "send" and x.get("id") == ref), None)
        if req:
            candidate = os.path.join(bridge.outbox, ref + ".json")
            if os.path.isfile(candidate):
                request_paths[ref] = candidate

    acceptances = []
    for e in entries:
        if e.get("type") not in ("accept", "reject") or e.get("delivery_id") != logical:
            continue
        record_path = os.path.join(bridge.wire, "acceptances", e["acceptance_id"] + ".json")
        if not os.path.isfile(record_path):
            raise ValueError(f"acceptance record missing: {record_path}")
        acceptances.append({"entry": e, "path": record_path,
                            "record": loads_strict(open(record_path, encoding="utf-8").read())})

    status_bytes = open(status_file, "rb").read()
    status = loads_strict(status_bytes.decode("utf-8"))
    receipts = []
    for path in receipt_files:
        data = open(path, "rb").read()
        receipts.append({"path": path, "bytes": data,
                         "receipt": loads_strict(data.decode("utf-8"))})

    os.makedirs(out_dir, exist_ok=True)
    ledger_bytes = open(bridge.ledger, "rb").read()
    originals = {"originals/ledger.jsonl": ledger_bytes, "originals/status.json": status_bytes}
    for e in versions:
        path, _env = env_cache[e["id"]]
        originals["originals/envelopes/" + e["id"] + ".json"] = open(path, "rb").read()
    for ref, path in request_paths.items():
        originals["originals/envelopes/" + ref + ".json"] = open(path, "rb").read()
    for item in acceptances:
        originals["originals/acceptances/" + item["entry"]["acceptance_id"] + ".json"] = \
            open(item["path"], "rb").read()
    for i, item in enumerate(receipts):
        originals[f"originals/receipts/{i}.json"] = item["bytes"]
    for rel, data in originals.items():
        dest = os.path.join(out_dir, rel)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        with open(dest, "wb") as f:
            f.write(data)

    tip = entries[-1]
    version_rows = []
    for e in versions:
        _path, env = env_cache[e["id"]]
        previous_delivery = e.get("previous_delivery")
        if previous_delivery:
            prev = by_ref.get(previous_delivery)
            if prev is None:
                raise ValueError(f"revision {e['id']} points to missing delivery {previous_delivery}")
            previous_version = prev.get("version") or "v1"
        else:
            previous_version = None
        version_rows.append({
            "delivery_id": logical, "version": e.get("version") or "v1",
            "previous_version": previous_version,
            "artifacts": [{"role": a["role"], "name": os.path.basename(a["path"]),
                           "sha256": a["sha256"], "bytes": a["bytes"]}
                          for a in e.get("artifacts", [])],
            "submitted_at": env.get("created_at"), "sender": e.get("actor"),
            "ledger_seq": e["seq"], "envelope_id": e["id"],
            "envelope_path": "originals/envelopes/" + e["id"] + ".json",
            "envelope_sha256": sha_file(env_cache[e["id"]][0]),
        })

    # key history: every register/rotate/revoke is tied to its ledger position and digest
    current, initial, history = {}, {}, []
    for e in entries:
        typ, actor = e.get("type"), e.get("actor")
        if typ == "actor_register":
            if actor not in current:
                current[actor] = e.get("pub")
                initial[actor] = e.get("seq")
                history.append({"kind": "register", "actor": actor, "pub": e.get("pub"),
                                "ledger_seq": e.get("seq"), "digest": e.get("digest")})
        elif typ == "rotate":
            current[actor] = e.get("new_pub")
            history.append({"kind": "rotate", "actor": actor, "old_pub": e.get("old_pub"),
                            "new_pub": e.get("new_pub"), "reason": e.get("reason", ""),
                            "ledger_seq": e.get("seq"), "digest": e.get("digest")})
        elif typ == "revoke":
            history.append({"kind": "revoke", "actor": actor, "fingerprint": e.get("fingerprint"),
                            "revocation_kind": e.get("kind"),
                            "effective_at": e.get("effective_at"),
                            "suspected_leak_at": e.get("suspected_leak_at"),
                            "evidence": e.get("evidence", ""),
                            "ledger_seq": e.get("seq"), "digest": e.get("digest")})

    manifest = {
        "pack_version": "agentbridge-evidence/0.2",
        "created_at": now(),
        "as_of": {"key_status": status.get("published_at"),
                  "anchors": (receipts[-1]["receipt"]["received_at"] if receipts else now())},
        "bridge_id": bridge_id_of(bridge, entries),
        "task": {"external_ref": task_ref},
        "deliveries": version_rows,
        "acceptances": [{
            "acceptance_id": item["entry"]["acceptance_id"],
            "delivery_id": logical, "version": item["entry"].get("version") or "v1",
            "artifacts_sha256": item["record"]["artifacts_sha256"],
            "decision": item["record"]["decision"], "reason": item["record"].get("reason", ""),
            "requires_anchoring": item["record"].get("requires_anchoring", False),
            "actor": item["record"]["actor"], "signed_at": item["record"]["signed_at"],
            "ledger_seq": item["entry"]["seq"],
            "record_path": "originals/acceptances/" + item["entry"]["acceptance_id"] + ".json",
            "record_sha256": sha_file(item["path"]),
        } for item in acceptances],
        "identity": {
            "actors": [{"actor": actor, "pub": current.get(actor, ""),
                        "fingerprint": signing.fingerprint(current.get(actor, "")),
                        "registered_seq": initial.get(actor)}
                       for actor in initial],
            "history": history,
            "status": {"path": "originals/status.json",
                       "sha256": sha_file(os.path.join(out_dir, "originals/status.json")),
                       "publisher_pub": status["publisher_pub"],
                       "published_at": status["published_at"],
                       "valid_until": status["valid_until"],
                       "revocations": status.get("revocations", [])},
        },
        "ledger": {"path": "originals/ledger.jsonl",
                   "sha256": sha_file(os.path.join(out_dir, "originals/ledger.jsonl")),
                   "base": "genesis", "tip_seq": tip["seq"], "tip_digest": tip["digest"]},
        "envelopes": ([{"id": e["id"], "path": "originals/envelopes/" + e["id"] + ".json",
                        "sha256": sha_file(env_cache[e["id"]][0])} for e in versions]
                      + [{"id": ref, "path": "originals/envelopes/" + ref + ".json",
                          "sha256": sha_file(path)} for ref, path in request_paths.items()]),
        "anchors": [{"path": f"originals/receipts/{i}.json",
                     "sha256": sha_file(os.path.join(out_dir, f"originals/receipts/{i}.json")),
                     "service_pub": item["receipt"]["service_pub"],
                     "covers_seq": item["receipt"]["seq"],
                     "covers_digest": item["receipt"]["digest"],
                     "log_index": item["receipt"]["log_index"],
                     "received_at": item["receipt"]["received_at"]}
                    for i, item in enumerate(receipts)],
        "coverage": {"expected_events": ["send", "deliver", "accept"],
                     "recorded_events": [e["type"] for e in entries
                                         if e.get("type") in ("send", "deliver", "accept")],
                     "gaps": []},
        "content_mode": "hashes_only",
        "limits": ["附件内容未包含在包内，内容复核未执行",
                   "离线无法确认是否为最新历史",
                   "未锚定尾部回滚不可发现"],
        "signed_files": [{"path": rel, "sha256": sha_bytes(d)} for rel, d in originals.items()],
    }
    manifest["signatures"] = {"exporter": sign_domain(exporter, "manifest", manifest)}
    with open(os.path.join(out_dir, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)
        f.write("\n")
    return {"pack": out_dir, "manifest": os.path.join(out_dir, "manifest.json"),
            "manifest_sha256": sha_file(os.path.join(out_dir, "manifest.json"))}


def bridge_id_of(bridge, entries) -> str:
    from .core import bridge_id_of as _bridge_id_of
    return _bridge_id_of(entries)


def verify_pack(pack_dir: str, trust_path: str):
    return verify(pack_dir, trust_path)




def verify(pack_dir: str, trust_path: str):
    """Fail-closed wrapper: malformed input must become a protocol error, never an exception."""
    try:
        return _verify(pack_dir, trust_path)
    except Exception as exc:  # noqa: BLE001 - malformed input is not a crash
        result = Result()
        result.protocol(f"unhandled {type(exc).__name__}: {exc}")
        return result

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pack", required=True)
    ap.add_argument("--trust", required=True)
    args = ap.parse_args()
    result = verify(args.pack, args.trust).to_dict(args.pack)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return verify(args.pack, args.trust).exit_code()


if __name__ == "__main__":
    sys.exit(main())
