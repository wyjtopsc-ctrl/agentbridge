#!/usr/bin/env python3
"""One entry point for the full gate: product suites, protocol matrix, schema, fuzz, crosscheck.

  python3 tools/ci.py [--fast]

Missing optional toolchains (node+ajv, python+cryptography) are reported as SKIP, never PASS.
"""
from __future__ import annotations

import argparse
import importlib.util
import os
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SUITES = ["run_tests", "run_identity_tests", "run_mcp_tests", "run_transport_tests",
          "run_anchor_tests", "run_evidence_tests", "run_evidence_hardening", "run_key_tests", "run_evidence_v2_tests"]


def run(cmd, timeout=900):
    env = dict(os.environ)
    env["PYTHONPATH"] = os.path.join(ROOT, "src")
    started = time.time()
    try:
        proc = subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True,
                              timeout=timeout)
        return proc.returncode, (proc.stdout or "") + (proc.stderr or ""), time.time() - started
    except subprocess.TimeoutExpired:
        return 124, f"timeout after {timeout}s", time.time() - started


def python_with_crypto():
    candidates = [os.environ.get("CROSSCHECK_PYTHON"),
                  os.path.join(ROOT, ".venv", "bin", "python"),
                  sys.executable]
    for candidate in candidates:
        if not candidate or not os.path.exists(candidate):
            continue
        code = "import cryptography"
        proc = subprocess.run([candidate, "-c", code], capture_output=True, text=True)
        if proc.returncode == 0:
            return candidate
    return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--fast", action="store_true", help="fewer fuzz iterations")
    args = ap.parse_args()
    results = []

    def record(name, status, detail):
        results.append((name, status, detail))
        print(f"{status:5} {name:34} {detail}")

    for suite in SUITES:
        code, out, secs = run([sys.executable, os.path.join("tests", suite + ".py")])
        last = out.strip().splitlines()[-1] if out.strip() else "no output"
        record(suite, "PASS" if code == 0 else "FAIL", f"{last} ({secs:.1f}s)")
        if code:
            print(out[-2000:])

    for script, extra in (("test_pack_vectors.py", []),
                          ("check_vector_rebuild.py", []),
                          ("check_schema_consistency.py", []),
                          ("fuzz_pack.py", ["--iterations", "100" if args.fast else "300"])):
        code, out, secs = run([sys.executable, os.path.join("tools", script)] + extra)
        last = out.strip().splitlines()[-1] if out.strip() else "no output"
        record(script, "PASS" if code == 0 else "FAIL", f"{last} ({secs:.1f}s)")
        if code:
            print(out[-2000:])

    node = shutil.which("node")
    ajv = os.path.join(ROOT, "tools", "node_modules", "ajv", "package.json")
    if node and (os.path.exists(ajv) or os.path.exists("/tmp/ajv/node_modules/ajv/package.json")):
        code, out, secs = run([sys.executable, os.path.join("tools", "test_schema_validation.py")])
        last = out.strip().splitlines()[-1] if out.strip() else "no output"
        record("schema-validation (Ajv)", "PASS" if code == 0 else "FAIL", f"{last} ({secs:.1f}s)")
        if code:
            print(out[-2000:])
    else:
        record("schema-validation (Ajv)", "SKIP", "node/ajv not installed (npm install --prefix tools)")

    crypto = python_with_crypto()
    if crypto:
        code, out, secs = run([crypto, os.path.join("tools", "crosscheck_vectors.py")])
        last = out.strip().splitlines()[-1] if out.strip() else "no output"
        record("independent crosscheck", "PASS" if code == 0 else "FAIL", f"{last} ({secs:.1f}s)")
        if code:
            print(out[-2000:])
    else:
        record("independent crosscheck", "SKIP", "python with cryptography not found")

    failed = [name for name, status, _ in results if status == "FAIL"]
    skipped = [name for name, status, _ in results if status == "SKIP"]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed"
          + (f", {len(skipped)} skipped" if skipped else ""))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
