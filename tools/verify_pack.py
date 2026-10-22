#!/usr/bin/env python3
"""Reference verifier for evidence pack v0 (protocol reference, not product code)."""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, "src"))

from agentbridge import signing  # noqa: E402
from packjcs import canonical_bytes, loads_strict  # noqa: E402

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
                "protocol_error": self.protocol_error}


def verify(pack_dir, trust_path):
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
    if manifest.get("content_mode") != "hashes_only":
        res.protocol("unsupported content_mode (E-CONTENT-MODE-UNSUPPORTED)")
        return res
    res.ck("content", "executed", "not_executed", "E-CONTENT-NOT-EXECUTED")

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
    chain_ok = True
    prev = "GENESIS"
    for i, e in enumerate(entries):
        body = {k: v for k, v in e.items() if k not in ("digest", "sig", "sig_pub")}
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

    # identity map
    actors = {a["actor"]: a for a in manifest["identity"]["actors"]}
    expected_actors = {a["actor"]: a["fingerprint"] for a in trust.get("expected_actors", [])}
    trust_ok = True
    for actor, fp in expected_actors.items():
        if actor not in actors or actors[actor]["fingerprint"] != fp:
            trust_ok = False
    if not expected_actors:
        res.ck("identity", "trust_set", "unknown", "E-TRUST-NOT-ESTABLISHED")
    elif trust_ok:
        res.ck("identity", "trust_set", "pass")
    else:
        res.ck("identity", "trust_set", "unknown", "E-TRUST-NOT-ESTABLISHED")

    def verify_sig(pub_hex, message, sig_hex):
        return signing.verify(bytes.fromhex(pub_hex), message, bytes.fromhex(sig_hex))

    # ledger signatures
    records_signed = True
    for i, e in enumerate(entries):
        if not e.get("sig"):
            continue
        if not verify_sig(e.get("sig_pub") or actors.get(e.get("actor"), {}).get("pub", ""),
                          str(e["digest"]).encode(), e["sig"]):
            res.ck("integrity", "ledger_signature", "fail", "E-SIG-INVALID", seq=i)
            res.ck("identity", "records_signed", "unknown", "E-SIG-INVALID")
            records_signed = False
        actor = e.get("actor")
        if actor in expected_actors and signing.fingerprint(e.get("sig_pub", "")) != expected_actors[actor]:
            res.ck("identity", "records_signed", "unknown", "E-SIG-UNTRUSTED-KEY", actor=actor)
            records_signed = False
    if records_signed:
        res.ck("identity", "records_signed", "pass")

    # deliveries / envelopes
    deliveries = {d["delivery_id"]: d for d in manifest["deliveries"]}
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
            if d["sender"] in expected_actors and signing.fingerprint(sig["pub"]) != expected_actors[d["sender"]]:
                res.ck("identity", "records_signed", "unknown", "E-SIG-UNTRUSTED-KEY")
        else:
            res.ck("integrity", "envelope_signature", "fail", "E-SIG-INVALID", delivery=d["delivery_id"])
            res.ck("identity", "records_signed", "unknown", "E-SIG-INVALID")
        entry = entries[d["ledger_seq"]]
        if entry.get("envelope_sha256") != sha_file(env_path) or entry.get("id") != d["envelope_id"]:
            res.ck("integrity", "envelope_binding", "fail", "E-ENVELOPE-MISMATCH", delivery=d["delivery_id"])
        else:
            res.ck("integrity", "envelope_binding", "pass")

    # acceptances
    acceptance_by_delivery = {}
    accepted = manifest.get("acceptances", [])
    for acc in accepted:
        acceptance_by_delivery.setdefault(acc["delivery_id"], []).append(acc)
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
        if ok:
            res.ck("acceptance", "declaration", "pass")
            if acc["actor"] in expected_actors and \
                    signing.fingerprint(record["signature"]["pub"]) != expected_actors[acc["actor"]]:
                res.ck("identity", "records_signed", "unknown", "E-SIG-UNTRUSTED-KEY")
        else:
            res.ck("acceptance", "declaration", "fail", "E-SIG-INVALID")
            res.ck("identity", "records_signed", "unknown", "E-SIG-INVALID")
        d = deliveries.get(acc["delivery_id"])
        if d is None:
            res.ck("acceptance", "binding", "fail", "E-ACC-DANGLING")
            continue
        if acc["version"] != d["version"] or sorted(acc["artifacts_sha256"]) != sorted(a["sha256"] for a in d["artifacts"]):
            res.ck("acceptance", "binding", "fail", "E-ACC-BINDING")
        else:
            res.ck("acceptance", "binding", "pass")
        expected = trust.get("expected_versions", {}).get(acc["delivery_id"])
        if expected is None:
            res.ck("acceptance", "expectation", "not_evaluated", "E-EXPECTATION-NOT-PROVIDED")
        elif expected == d["version"]:
            res.ck("acceptance", "expectation", "pass")
        else:
            res.ck("acceptance", "expectation", "fail", "E-EXPECT-VERSION-MISMATCH")
    for delivery_id, items in acceptance_by_delivery.items():
        if len(items) > 1 and len({i["decision"] for i in items}) > 1:
            res.ck("acceptance", "conflict", "unknown", "E-ACC-CONFLICT", delivery=delivery_id)

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


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pack", required=True)
    ap.add_argument("--trust", required=True)
    args = ap.parse_args()
    res = verify(args.pack, args.trust)
    print(json.dumps(res.to_dict(args.pack), ensure_ascii=False, indent=2))
    return res.exit_code()


if __name__ == "__main__":
    sys.exit(main())
