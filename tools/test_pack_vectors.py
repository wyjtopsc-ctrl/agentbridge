#!/usr/bin/env python3
"""Freeze matrix: run the reference verifier against saved vectors and compare expected.json."""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, "src"))

from verify_pack import verify  # noqa: E402
from agentbridge import evidence as product_evidence  # noqa: E402

FIX = os.path.join(ROOT, "docs", "fixtures", "evidence-pack-v0")
PACK_CASES = [
    "normal", "tampered-sig", "tampered-binding", "missing-evidence", "retired-key",
    "compromised-no-anchor", "compromised-with-anchor", "compromised-start-unknown",
    "compromise-boundary-equal", "retirement-boundary-equal", "forged-selfconsistent",
]
TRUST_CASES = {
    "checkpoint-mismatch": ("E-CHECKPOINT-MISMATCH", "checkpoint"),
    "checkpoint-wrong-bridge": ("E-CHECKPOINT-BRIDGE-MISMATCH", "checkpoint"),
    "checkpoint-out-of-range": ("E-CHECKPOINT-OUT-OF-RANGE", "checkpoint"),
    "minimum-too-high": ("E-ANCHOR-BELOW-MINIMUM", "minimum"),
}


def check_case(label, pack_name, trust_name, expected, codes=(), checks=None):
    pack = os.path.join(FIX, pack_name)
    result = verify(pack, os.path.join(FIX, "trust", trust_name + ".json")).to_dict(pack)
    problems = []
    for axis, status in expected.get("axes", {}).items():
        if result["axes"][axis]["status"] != status:
            problems.append(f"{axis}={result['axes'][axis]['status']} want {status}")
    got_codes = [c for axis in result["axes"].values() for c in axis["codes"]]
    for code in list(expected.get("codes", [])) + list(codes):
        if code not in got_codes:
            problems.append(f"missing code {code}")
    for path, status in (expected.get("checks") or {}).items():
        axis, name = path.split(".")
        got = result["axes"][axis]["checks"].get(name, {}).get("status", "absent")
        if got != status:
            problems.append(f"{path}={got} want {status}")
    if checks:
        for path, status in checks.items():
            axis, name = path.split(".")
            got = result["axes"][axis]["checks"].get(name, {}).get("status", "absent")
            if got != status:
                problems.append(f"{path}={got} want {status}")
    if result["exit_code"] != expected["exit_code"]:
        problems.append(f"exit={result['exit_code']} want {expected['exit_code']}")
    print(("PASS  " if not problems else "FAIL  ") + label)
    for p in problems:
        print("   ", p)
    return not problems


def check_v2_fixture():
    v2 = os.path.join(ROOT, "docs", "fixtures", "evidence-pack-v0.2", "revision-rotation")
    trust = os.path.join(ROOT, "docs", "fixtures", "evidence-pack-v0.2", "trust", "revision-rotation.json")
    expected = json.load(open(os.path.join(v2, "expected.json"), encoding="utf-8"))
    result = product_evidence.verify_pack(v2, trust).to_dict(v2)
    problems = []
    for axis, status in expected["axes"].items():
        if result["axes"][axis]["status"] != status:
            problems.append(f"{axis}={result['axes'][axis]['status']} want {status}")
    for path, status in expected.get("checks", {}).items():
        axis, name = path.split(".")
        got = result["axes"][axis]["checks"].get(name, {}).get("status", "absent")
        if got != status:
            problems.append(f"{path}={got} want {status}")
    if result["exit_code"] != expected["exit_code"]:
        problems.append(f"exit={result['exit_code']} want {expected['exit_code']}")
    print(("PASS  " if not problems else "FAIL  ") + "v0.2 revision-rotation fixture")
    for p in problems:
        print("   ", p)
    return not problems


def main() -> int:
    failures = 0
    for name in PACK_CASES:
        expected = json.load(open(os.path.join(FIX, name, "expected.json"), encoding="utf-8"))
        failures += 0 if check_case(name, name, name, expected) else 1

    normal_expected = json.load(open(os.path.join(FIX, "normal", "expected.json"), encoding="utf-8"))
    for name, (code, check_name) in TRUST_CASES.items():
        expected = {
            "axes": dict(normal_expected["axes"], anchoring="fail"),
            "exit_code": 1,
            "codes": [code],
            "checks": {f"anchoring.{check_name}": "fail"},
        }
        failures += 0 if check_case(name, "normal", name, expected) else 1

    failures += 0 if check_v2_fixture() else 1

    pack = os.path.join(FIX, "normal")
    res = verify(pack, os.path.join(pack, "manifest.json"))
    ok = res.exit_code() == 3 and "E-TRUST-INSIDE-PACK" in (res.protocol_error or "")
    print(("PASS  " if ok else "FAIL  ") + "trust-inside-pack")
    failures += 0 if ok else 1

    total = len(PACK_CASES) + len(TRUST_CASES) + 2
    print(f"\n{total - failures}/{total} freeze-matrix cases passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
