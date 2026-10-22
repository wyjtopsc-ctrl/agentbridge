#!/usr/bin/env python3
"""Static consistency check between docs/evidence-pack-v0.1.md and its schema.

This is a protocol-consistency gate, not a product implementation: it asserts that the fields
the document tells implementers to rely on actually exist with the expected shape, and that
retired concepts (e.g. the `not_established` status) are gone.
"""
from __future__ import annotations

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SCHEMA = os.path.join(ROOT, "docs", "evidence-pack-v0.1.schema.json")
SCHEMA_V2 = os.path.join(ROOT, "docs", "evidence-pack-v0.2.schema.json")
DOC = os.path.join(ROOT, "docs", "evidence-pack-v0.1.md")

CHECKS = []


def check(label, condition):
    CHECKS.append((label, bool(condition)))


def props(schema, path):
    node = schema
    for part in path:
        node = node[part]
    return node


def main() -> int:
    schema = json.load(open(SCHEMA, encoding="utf-8"))
    text = open(DOC, encoding="utf-8").read() if os.path.exists(DOC) else ""

    check("schema parses", True)
    check("pack_version is v0.1", schema["properties"]["pack_version"]["const"] == "agentbridge-evidence/0.1")
    check("split layout: no root 'records' field", "records" not in schema["properties"])
    check("acceptances optional", "acceptances" not in schema["required"])
    check("allow additionalProperties=false at root", schema.get("additionalProperties") is False)

    check("root requires ledger", "ledger" in schema["required"])
    check("root requires envelopes", "envelopes" in schema["required"])
    check("root requires anchors", "anchors" in schema["required"])
    check("root requires signed_files", "signed_files" in schema["required"])
    check("root requires content_mode", "content_mode" in schema["required"])

    ledger = props(schema, ["properties", "ledger"])
    check("ledger: path/sha256/base/tip", set(ledger["required"]) == {"path", "sha256", "base", "tip_seq", "tip_digest"})
    check("ledger anchored at genesis", ledger["properties"]["base"]["const"] == "genesis")

    envelopes = props(schema, ["properties", "envelopes", "items"])
    check("envelopes: id/path/sha256", set(envelopes["required"]) == {"id", "path", "sha256"})

    anchors = props(schema, ["properties", "anchors", "items"])
    check("anchors: covers_seq/covers_digest",
          {"covers_seq", "covers_digest", "service_pub"} <= set(anchors["required"]))

    identity = props(schema, ["properties", "identity"])
    check("identity: actors + status", set(identity["required"]) == {"actors", "status"})
    status = props(schema, ["properties", "identity", "properties", "status"])
    check("status: publisher + validity window",
          {"publisher_pub", "published_at", "valid_until"} <= set(status["required"]))
    rev = props(schema, ["properties", "identity", "properties", "status", "properties", "revocations", "items", "properties"])
    check("revocation kinds are three-way",
          set(rev["kind"]["enum"]) == {"normal_retirement", "suspected_compromise", "revoked"})

    deliveries = props(schema, ["properties", "deliveries", "items"])
    check("delivery references original envelope bytes",
          {"ledger_seq", "envelope_path", "envelope_sha256"} <= set(deliveries["required"]))

    acceptances = props(schema, ["properties", "acceptances", "items"])
    check("acceptance references original record bytes",
          {"delivery_id", "version", "artifacts_sha256", "ledger_seq",
           "record_path", "record_sha256"} <= set(acceptances["required"]))
    check("acceptance has requires_anchoring flag", "requires_anchoring" in acceptances["properties"])
    check("acceptance decision enum", set(acceptances["properties"]["decision"]["enum"]) == {"accepted", "rejected"})

    check("content_mode is hashes_only only",
          schema["properties"]["content_mode"].get("const") == "hashes_only")
    check("signature fields alg/pub/sig",
          set(schema["$defs"]["signature"]["required"]) == {"alg", "pub", "sig"})
    check("signature alg is ed25519",
          schema["$defs"]["signature"]["properties"]["alg"]["const"] == "ed25519")

    v2 = json.load(open(SCHEMA_V2, encoding="utf-8"))
    check("v0.2 pack_version", v2["properties"]["pack_version"]["const"] == "agentbridge-evidence/0.2")
    check("v0.2 requires identity.history", "history" in v2["properties"]["identity"]["required"])
    kinds = set(v2["properties"]["identity"]["properties"]["history"]["items"]["properties"]["kind"]["enum"])
    check("v0.2 history kinds", kinds == {"register", "rotate", "revoke"})
    check("retired status 'not_established' absent from schema",
          "not_established" not in json.dumps(schema))
    if text:
        check("document uses unknown + E-TRUST-NOT-ESTABLISHED",
              "E-TRUST-NOT-ESTABLISHED" in text and "not_established" not in text)

    failures = [label for label, ok in CHECKS if not ok]
    for label, ok in CHECKS:
        print(("PASS  " if ok else "FAIL  ") + label)
    print(f"\n{len(CHECKS) - len(failures)}/{len(CHECKS)} checks passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
