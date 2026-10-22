#!/usr/bin/env python3
"""HTTP transport tests: authentication, replay protection, sequencing, end-to-end delivery.

Spawns the real sequencer process and talks to it with the real client, so this covers the
transport, the signing path and the ledger together.

  PYTHONPATH=src python3 tests/run_transport_tests.py [-v]
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(os.path.dirname(HERE), "src")
VERBOSE = "-v" in sys.argv
if SRC not in sys.path:
    sys.path.insert(0, SRC)

from agentbridge import signing  # noqa: E402
from agentbridge.core import canon, new_id, now, sha_bytes  # noqa: E402
from agentbridge.transport import HttpBridge, envelope_bytes, sign_headers  # noqa: E402

CASES = []


def case(fn):
    CASES.append(fn)
    return fn


def run(root, *args, key=None, expect=0):
    env = dict(os.environ, PYTHONPATH=SRC)
    cmd = [sys.executable, "-m", "agentbridge", "--root", root]
    if key:
        cmd += ["--key", key]
    cmd += list(args)
    p = subprocess.run(cmd, capture_output=True, text=True, env=env)
    out = (p.stdout or "") + (p.stderr or "")
    if VERBOSE:
        print(f"    $ {' '.join(cmd[3:])} -> {p.returncode}\n{out.strip()[:300]}")
    if expect is not None and p.returncode != expect:
        raise AssertionError(f"expected rc={expect}, got {p.returncode}\n{out}")
    return p.returncode, out


class Fixture:
    def __init__(self):
        self.dir = tempfile.mkdtemp(prefix="agentbridge-transport.")
        self.root = os.path.join(self.dir, "bridge")
        for actor in ("planner", "worker", "mallory"):
            run(self.root, "keygen", "--actor", actor, "--out", self.dir)
        run(self.root, "init", "--actor", "planner")
        run(self.root, "register", key=self.key("planner"))
        run(self.root, "register", key=self.key("worker"))
        env = dict(os.environ, PYTHONPATH=SRC)
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "agentbridge", "--root", self.root, "serve",
             "--host", "127.0.0.1", "--port", "0"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
        line = self.proc.stdout.readline()
        if not line:
            raise AssertionError("server did not start: " + self.proc.stderr.read()[-1000:])
        self.url = json.loads(line)["listening"]
        self.planner = HttpBridge(self.url, signing.load_keyfile(self.key("planner")))
        self.worker = HttpBridge(self.url, signing.load_keyfile(self.key("worker")))
        self.mallory = HttpBridge(self.url, signing.load_keyfile(self.key("mallory")))

    def key(self, actor):
        return os.path.join(self.dir, f"{actor}.key")

    def close(self):
        try:
            self.proc.terminate()
            self.proc.wait(timeout=10)
        except Exception:
            self.proc.kill()


def raw(method, url, path, body=b"", headers=None):
    req = urllib.request.Request(url + path, data=body or None, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, json.loads(exc.read().decode())
        except json.JSONDecodeError:
            return exc.code, {}


@case
def T1_unauthenticated_requests_are_rejected():
    f = Fixture()
    try:
        status, body = raw("GET", f.url, "/api/head")
        assert status >= 400 and body.get("code") in ("refused", "transport"), (status, body)
    finally:
        f.close()


@case
def T2_signed_reads_work():
    f = Fixture()
    try:
        head = f.planner.head()
        assert head["seq"] >= 2, head
        anchor = f.planner.anchor()
        assert anchor["seq"] == head["seq"]
        report = f.planner.verify()
        assert report.ok, report.problems
        assert f.planner.doctor()["ledger_entries"] >= 2
    finally:
        f.close()


@case
def T3_end_to_end_delivery():
    f = Fixture()
    try:
        artifact = os.path.join(f.dir, "module.py")
        open(artifact, "w").write("x = 1\n")
        sent = f.planner.send(to="worker", intent="review", body="review this", attach=[artifact])
        assert sent["id"] and sent["artifacts"][0]["sha256"]

        pending = f.worker.requests(actor="worker")
        assert len(pending) == 1 and pending[0]["id"] == sent["id"], pending
        assert pending[0]["verified"] is True

        delivered = f.worker.deliver(to="planner", in_reply_to=sent["id"], body="one finding")
        assert delivered["ledger_seq"] > sent["ledger_seq"]

        polled = f.planner.poll(actor="planner", consume=True)
        assert polled.consumed == [delivered["id"]], polled.consumed
        assert not polled.refused

        report = f.planner.verify()
        assert report.ok, report.problems
        assert report.artifacts_ok >= 1
    finally:
        f.close()


@case
def T4_replayed_request_is_rejected():
    f = Fixture()
    try:
        signer = signing.load_keyfile(f.key("planner"))
        path = "/api/head"
        headers = sign_headers(signer, "GET", path, b"")
        first_status, first = raw("GET", f.url, path, headers=headers)
        assert first_status == 200, first
        second_status, second = raw("GET", f.url, path, headers=headers)
        assert second_status >= 400 and "replay" in second.get("message", ""), second
    finally:
        f.close()


@case
def T5_unregistered_actor_is_refused():
    f = Fixture()
    try:
        try:
            f.mallory.head()
        except Exception as exc:  # noqa: BLE001
            assert "not registered" in str(exc), exc
        else:
            raise AssertionError("an unregistered key was accepted")
    finally:
        f.close()


@case
def T6_tampered_entry_is_refused():
    f = Fixture()
    try:
        signer = signing.load_keyfile(f.key("planner"))
        head = f.planner.head()
        entry = {"type": "commit", "id": new_id("planner"), "actor": "planner",
                 "ref": None, "promise": "honest", "accept": "",
                 "seq": head["seq"] + 1, "ts": now(), "prev": head["digest"]}
        entry["digest"] = sha_bytes(canon(entry))
        entry["sig_pub"] = signer.pub_hex
        entry["sig"] = signer.sign_hex(entry["digest"].encode())
        entry["promise"] = "tampered"                       # digest no longer matches
        body = json.dumps({"entry": entry}).encode()
        headers = sign_headers(signer, "POST", "/api/entry", body)
        headers["Content-Type"] = "application/json"
        status, payload = raw("POST", f.url, "/api/entry", body, headers)
        assert status >= 400 and "digest" in payload.get("message", ""), payload
    finally:
        f.close()


@case
def T7_stale_entry_loses_the_race():
    f = Fixture()
    try:
        signer = signing.load_keyfile(f.key("planner"))
        head = f.planner.head()
        f.planner.commit(promise="advances the ledger")       # someone else writes first
        entry = {"type": "commit", "id": new_id("planner"), "actor": "planner",
                 "ref": None, "promise": "stale", "accept": "",
                 "seq": head["seq"] + 1, "ts": now(), "prev": head["digest"]}
        entry["digest"] = sha_bytes(canon(entry))
        entry["sig_pub"] = signer.pub_hex
        entry["sig"] = signer.sign_hex(entry["digest"].encode())
        body = json.dumps({"entry": entry}).encode()
        headers = sign_headers(signer, "POST", "/api/entry", body)
        headers["Content-Type"] = "application/json"
        status, payload = raw("POST", f.url, "/api/entry", body, headers)
        assert status >= 400 and "extend" in payload.get("message", ""), payload
    finally:
        f.close()


@case
def T8_entry_cannot_impersonate_another_actor():
    f = Fixture()
    try:
        signer = signing.load_keyfile(f.key("planner"))
        head = f.planner.head()
        entry = {"type": "commit", "id": new_id("worker"), "actor": "worker",
                 "ref": None, "promise": "impersonation", "accept": "",
                 "seq": head["seq"] + 1, "ts": now(), "prev": head["digest"]}
        entry["digest"] = sha_bytes(canon(entry))
        entry["sig_pub"] = signer.pub_hex
        entry["sig"] = signer.sign_hex(entry["digest"].encode())
        body = json.dumps({"entry": entry}).encode()
        headers = sign_headers(signer, "POST", "/api/entry", body)
        headers["Content-Type"] = "application/json"
        status, payload = raw("POST", f.url, "/api/entry", body, headers)
        assert status >= 400 and "authenticated actor" in payload.get("message", ""), payload
    finally:
        f.close()


@case
def T9_cli_remote_roundtrip():
    f = Fixture()
    try:
        artifact = os.path.join(f.dir, "note.txt")
        open(artifact, "w").write("hello\n")
        out = run(f.root, "--remote", f.url, "send", "--to", "worker", "--body", "cli",
                  "--attach", artifact, key=f.key("planner"))[1]
        sent = json.loads(out[out.index("{"):])
        assert sent["id"]

        listed = f.worker.requests(actor="worker")
        assert any(r["id"] == sent["id"] for r in listed)

        out = run(f.root, "--remote", f.url, "verify", key=f.key("planner"))[1]
        assert "chain OK" in out and "0 failing" in out, out
    finally:
        f.close()


@case
def T10_mcp_over_remote_transport():
    f = Fixture()
    try:
        env = dict(os.environ, PYTHONPATH=SRC)
        proc = subprocess.Popen(
            [sys.executable, "-m", "agentbridge", "--root", f.root, "--remote", f.url,
             "--key", f.key("worker"), "mcp"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, bufsize=1, env=env)

        def send(message):
            proc.stdin.write(json.dumps(message) + "\n")
            proc.stdin.flush()

        def recv():
            line = proc.stdout.readline()
            if not line:
                raise AssertionError("mcp server died: " + proc.stderr.read()[-800:])
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                raise AssertionError(f"non-JSON from mcp server: {line[:300]!r} stderr={proc.stderr.read()[-500:]!r}")

        send({"jsonrpc": "2.0", "id": 1, "method": "initialize",
              "params": {"protocolVersion": "2025-06-18"}})
        assert recv()["result"]["serverInfo"]["name"] == "agentbridge"

        send({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
              "params": {"name": "bridge_status", "arguments": {}}})
        result = recv()["result"]
        assert result["isError"] is False, result
        assert json.loads(result["content"][0]["text"])["verified"] is True

        send({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
              "params": {"name": "send_request",
                         "arguments": {"to": "planner", "body": "from mcp over http"}}})
        sent = json.loads(recv()["result"]["content"][0]["text"])
        assert sent["id"]
        assert any(r["id"] == sent["id"] for r in f.planner.requests(actor="planner"))

        proc.stdin.close()
        proc.wait(timeout=10)
    finally:
        f.close()


@case
def T11_actors_endpoint_and_anchor_level():
    f = Fixture()
    try:
        actors = f.planner.actors()
        assert {a["actor"] for a in actors} == {"planner", "worker"}, actors
        assert all(a["fingerprint"].startswith("sha256:") for a in actors)
        report = f.planner.verify()
        assert report.anchor_level == "local_only", report.anchor_level
        head = f.planner.head()
        anchored = f.planner.verify(expect_head=f"{head['seq']}:{head['digest']}")
        assert anchored.anchor_level == "anchored", anchored.anchor_level
    finally:
        f.close()


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
