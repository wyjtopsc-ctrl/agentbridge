#!/usr/bin/env python3
"""Hosted anchor tests: submission, receipts, equivocation, log chain, restart persistence.

  PYTHONPATH=src python3 tests/run_anchor_tests.py [-v]
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(os.path.dirname(HERE), "src")
VERBOSE = "-v" in sys.argv
if SRC not in sys.path:
    sys.path.insert(0, SRC)

from agentbridge import anchor, signing  # noqa: E402
from agentbridge.core import Bridge, new_id  # noqa: E402

CASES = []


def case(fn):
    CASES.append(fn)
    return fn


def run(root, *args, key=None, expect=0, timeout=60):
    env = dict(os.environ, PYTHONPATH=SRC)
    cmd = [sys.executable, "-m", "agentbridge", "--root", root]
    if key:
        cmd += ["--key", key]
    cmd += list(args)
    p = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=timeout)
    out = (p.stdout or "") + (p.stderr or "")
    if VERBOSE:
        print(f"    $ {' '.join(cmd[3:])} -> {p.returncode}\n{out.strip()[:300]}")
    if expect is not None and p.returncode != expect:
        raise AssertionError(f"expected rc={expect}, got {p.returncode}\n{out}")
    return p.returncode, out


class Fixture:
    def __init__(self):
        self.dir = tempfile.mkdtemp(prefix="agentbridge-anchor.")
        self.root = os.path.join(self.dir, "bridge")
        self.service_dir = os.path.join(self.dir, "anchors")
        for actor in ("planner", "svc", "rogue"):
            run(self.root, "keygen", "--actor", actor, "--out", self.dir)
        run(self.root, "init", "--actor", "planner")
        run(self.root, "register", key=self.key("planner"))
        self.proc = self._start()

    def key(self, actor):
        return os.path.join(self.dir, f"{actor}.key")

    def _start(self):
        env = dict(os.environ, PYTHONPATH=SRC)
        proc = subprocess.Popen(
            [sys.executable, "-m", "agentbridge", "--key", self.key("svc"),
             "anchor-service", "--dir", self.service_dir, "--port", "0"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
        line = proc.stdout.readline()
        if not line:
            raise AssertionError("anchor service did not start: " + proc.stderr.read()[-800:])
        self.url = json.loads(line)["listening"]
        self.service_pub = json.loads(line)["service_pub"]
        return proc

    def restart(self):
        self.stop()
        self.proc = self._start()

    def stop(self):
        try:
            self.proc.terminate()
            self.proc.wait(timeout=10)
        except Exception:
            self.proc.kill()


@case
def A1_submit_and_verify_roundtrip():
    f = Fixture()
    try:
        out = run(f.root, "anchor-submit", "--url", f.url, key=f.key("planner"))[1]
        info = json.loads(out[out.index("{"):])
        receipt_path = info["receipt"]
        assert os.path.exists(receipt_path)
        receipt = json.load(open(receipt_path, encoding="utf-8"))
        assert receipt["service_pub"] == f.service_pub
        assert not anchor.verify_receipt(receipt)

        code, out = run(f.root, "anchor-verify", "--receipt", receipt_path, key=f.key("planner"))
        assert code == 0 and "OK" in out, out

        code, out = run(f.root, "verify", "--expect-anchor", receipt_path, key=f.key("planner"))
        assert code == 0 and "0 failing" in out, out
    finally:
        f.stop()


@case
def A2_duplicate_submission_is_idempotent():
    f = Fixture()
    try:
        bridge = Bridge(f.root, signer=signing.load_keyfile(f.key("planner")))
        head = bridge.head()
        bridge_id = bridge.bridge_id()
        signer = signing.load_keyfile(f.key("planner"))
        first = anchor.submit(f.url, signer, bridge_id, head["seq"], head["digest"])
        second = anchor.submit(f.url, signer, bridge_id, head["seq"], head["digest"])
        assert first["log_index"] == second["log_index"] == 0
        assert first["service_sig"] == second["service_sig"]
    finally:
        f.stop()


@case
def A3_equivocation_is_rejected():
    f = Fixture()
    try:
        bridge = Bridge(f.root, signer=signing.load_keyfile(f.key("planner")))
        head = bridge.head()
        bridge_id = bridge.bridge_id()
        signer = signing.load_keyfile(f.key("planner"))
        anchor.submit(f.url, signer, bridge_id, head["seq"], head["digest"])
        try:
            anchor.submit(f.url, signer, bridge_id, head["seq"], "0" * 64)
        except Exception as exc:  # noqa: BLE001
            assert "equivocation" in str(exc), exc
        else:
            raise AssertionError("the service accepted two digests for one seq")
    finally:
        f.stop()


@case
def A4_tampered_receipt_is_rejected():
    f = Fixture()
    try:
        out = run(f.root, "anchor-submit", "--url", f.url, key=f.key("planner"))[1]
        receipt_path = json.loads(out[out.index("{"):])["receipt"]
        receipt = json.load(open(receipt_path, encoding="utf-8"))
        receipt["digest"] = "1" * 64
        problems = anchor.verify_receipt(receipt)
        assert problems, "a tampered receipt was accepted"

        tampered_path = os.path.join(f.dir, "tampered.json")
        json.dump(receipt, open(tampered_path, "w"), ensure_ascii=False)
        code, out = run(f.root, "anchor-verify", "--receipt", tampered_path,
                        key=f.key("planner"), expect=1)
        assert "INVALID" in out, out
    finally:
        f.stop()


@case
def A5_wrong_service_key_is_rejected():
    f = Fixture()
    try:
        out = run(f.root, "anchor-submit", "--url", f.url, key=f.key("planner"))[1]
        receipt_path = json.loads(out[out.index("{"):])["receipt"]
        receipt = json.load(open(receipt_path, encoding="utf-8"))
        rogue = signing.load_keyfile(f.key("rogue"))
        receipt["service_pub"] = rogue.pub_hex
        problems = anchor.verify_receipt(receipt)
        assert any("signature" in p for p in problems), problems
    finally:
        f.stop()


@case
def A6_log_chain_detects_deletion():
    f = Fixture()
    try:
        signer = signing.load_keyfile(f.key("planner"))
        bridge = Bridge(f.root, signer=signer)
        bridge_id = bridge.bridge_id()
        for i in range(3):
            anchor.submit(f.url, signer, bridge_id, i, f"{i:064x}")
        log_path = os.path.join(f.service_dir, "log.jsonl")
        receipts = [json.loads(line) for line in open(log_path) if line.strip()]
        assert len(receipts) == 3
        assert not anchor.verify_log(receipts)

        open(log_path, "w").write("\n".join(json.dumps(r, ensure_ascii=False) for r in receipts[1:]) + "\n")
        remaining = [json.loads(line) for line in open(log_path) if line.strip()]
        assert anchor.verify_log(remaining), "deleting the first receipt broke nothing"
    finally:
        f.stop()


@case
def A7_restart_keeps_receipts_valid():
    f = Fixture()
    try:
        out = run(f.root, "anchor-submit", "--url", f.url, key=f.key("planner"))[1]
        receipt_path = json.loads(out[out.index("{"):])["receipt"]
        before = json.loads(urllib.request.urlopen(f.url + "/v1/head", timeout=10).read())
        f.restart()
        after = json.loads(urllib.request.urlopen(f.url + "/v1/head", timeout=10).read())
        assert before["log_len"] == after["log_len"] and before["service_sig"] == after["service_sig"]
        code, out = run(f.root, "anchor-verify", "--receipt", receipt_path, key=f.key("planner"))
        assert code == 0, out
    finally:
        f.stop()


@case
def A8_bridge_identity_is_bound_on_first_use():
    f = Fixture()
    try:
        bridge = Bridge(f.root, signer=signing.load_keyfile(f.key("planner")))
        head = bridge.head()
        bridge_id = bridge.bridge_id()
        anchor.submit(f.url, signing.load_keyfile(f.key("planner")),
                      bridge_id, head["seq"], head["digest"])
        try:
            anchor.submit(f.url, signing.load_keyfile(f.key("rogue")),
                          bridge_id, head["seq"] + 1, "2" * 64)
        except Exception as exc:  # noqa: BLE001
            assert "bound to a different key" in str(exc), exc
        else:
            raise AssertionError("the service accepted a second key for the same bridge")
    finally:
        f.stop()


@case
def A9_verify_flags_an_anchor_that_points_nowhere():
    f = Fixture()
    try:
        bridge = Bridge(f.root, signer=signing.load_keyfile(f.key("planner")))
        bridge._append({"type": "anchor", "id": new_id("planner"), "actor": "planner",
                        "bridge_id": bridge.bridge_id(), "anchor_seq": 999,
                        "anchor_digest": "3" * 64, "log_index": 0,
                        "service_url": "http://example.invalid", "receipt_sha256": "4" * 64})
        report = bridge.verify()
        assert not report.ok
        assert any("anchor points to a missing ledger seq" in p for p in report.problems), report.problems
    finally:
        f.stop()


@case
def A10_anchor_level_is_reported():
    f = Fixture()
    try:
        signer = signing.load_keyfile(f.key("planner"))
        bridge = Bridge(f.root, signer=signer)
        head = bridge.head()

        local = bridge.verify()
        assert local.anchor_level == "local_only" and local.anchor is None, local.anchor_level

        receipt = anchor.submit(f.url, signer, bridge.bridge_id(), head["seq"], head["digest"])
        anchored = bridge.verify(expect_receipt=receipt)
        assert anchored.ok, anchored.problems
        assert anchored.anchor_level == "anchored", anchored.anchor_level
        assert anchored.anchor["kind"] == "receipt" and anchored.anchor["log_index"] == 0

        tampered = bridge.verify(expect_receipt=dict(receipt, digest="9" * 64))
        assert not tampered.ok and tampered.anchor_level == "local_only", tampered.anchor_level
    finally:
        f.stop()


def main() -> int:
    failed = 0
    for fn in CASES:
        try:
            fn()
            print(f"PASS  {fn.__name__}")
        except AssertionError as exc:
            failed += 1
            print(f"FAIL  {fn.__name__}: {exc}")
        except Exception as exc:  # noqa: BLE001 - report, don't mask
            failed += 1
            print(f"ERROR {fn.__name__}: {type(exc).__name__}: {exc}")
    print(f"\n{len(CASES) - failed}/{len(CASES)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
