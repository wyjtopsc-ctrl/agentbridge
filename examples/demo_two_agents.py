#!/usr/bin/env python3
"""Two agents, one shared directory: request -> review -> delivery -> verification.

    PYTHONPATH=src python3 examples/demo_two_agents.py
"""
from __future__ import annotations

import json
import os
import tempfile

from agentbridge import Bridge


def main() -> None:
    work = tempfile.mkdtemp(prefix="agentbridge-demo.")
    bridge_dir = os.path.join(work, "bridge")

    planner = Bridge(bridge_dir)
    print(planner.init(actor="planner"))

    # planner hands a file to a worker for review
    module = os.path.join(work, "module.py")
    with open(module, "w") as f:
        f.write("def add(a, b):\n    return a - b\n")
    req = planner.send(actor="planner", to="worker", intent="review",
                       body="review this module for correctness", attach=[module])
    print(f"request  {req['id']}  ({os.path.basename(module)} sha256={req['artifacts'][0]['sha256'][:12]}…)")

    # worker picks up the request (requests sit in wire/outbox until the other side reads them)
    worker = Bridge(bridge_dir)
    request_env = json.load(open(req["envelope"], encoding="utf-8"))
    print(f"worker   received: {request_env['body']!r}")

    findings = os.path.join(work, "findings.md")
    with open(findings, "w") as f:
        f.write("# findings\n- `add` subtracts; should add (line 2)\n")
    delivery = worker.deliver(actor="worker", to="planner", in_reply_to=req["id"],
                              body="one finding: add() subtracts", attach=[findings])
    print(f"delivery {delivery['id']}")

    # planner consumes it and verifies the whole record
    result = planner.poll(actor="planner", consume=True)
    for env in result.envelopes:
        state = "verified" if env["_verified"] else "UNVERIFIED"
        print(f"planner  got {env['id']}  [{state}]  {env['body']}")

    report = planner.verify()
    print(f"\nverify   chain_ok={report.chain_ok} entries={report.ledger_len} "
          f"envelopes={report.envelopes_checked} artifacts={report.artifacts_ok} ok={report.ok}")

    anchor = planner.anchor()
    print(f"anchor   {anchor['verify_with']}   <- copy this off the filesystem")

    # someone rewrites the conclusion in the request envelope
    envelope = json.load(open(req["envelope"], encoding="utf-8"))
    envelope["body"] = "TAMPERED: everything is fine, ship it."
    with open(req["envelope"], "w", encoding="utf-8") as f:
        json.dump(envelope, f, ensure_ascii=False)
    tampered = planner.verify()
    print(f"\ntamper   verify ok={tampered.ok}")
    for problem in tampered.problems:
        print(f"         ! {problem}")

    print(f"\nbridge left at {bridge_dir}")


if __name__ == "__main__":
    main()
