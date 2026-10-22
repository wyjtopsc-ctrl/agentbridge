"""HTTP transport: a single-writer sequencer plus a client that signs its own entries.

Design constraint: the server must never be able to forge authorship. So it holds no actor
keys. Clients build and sign ledger entries locally (using the same code paths as the
filesystem bridge) and POST them; the server verifies the chain position, the digest and the
signature, stores the envelope, and appends. The server is a sequencer, not an authority.

Every HTTP request is signed by the actor key as well (timestamp + nonce, replay-protected),
so reads are authenticated too.

    agentbridge serve --root ./shared --port 8765
    agentbridge --remote http://127.0.0.1:8765 --key ./keys/worker.key send --to planner ...

This is a local-first design; it is not hardened for hostile networks (no TLS, in-process
nonce cache, no rate limiting). Run it behind a reverse proxy if it leaves localhost.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import signing
from .core import (DIGEST_EXCLUDED, Bridge, BridgeError, BrokenLedger, CorruptLedger,
                   NotInitialised, NotFound, Refused, VerificationReport, bridge_id_of, canon,
                   new_id, now, sha_bytes, sha_file)

REQUEST_PREFIX = "agentbridge-v1"
MAX_BLOB_BYTES = 64 * 1024 * 1024
CLOCK_SKEW_SECONDS = 300


# ── wire helpers ────────────────────────────────────────────────────────────

def envelope_bytes(env: dict) -> bytes:
    """Canonical on-disk form of an envelope; both sides hash exactly these bytes."""
    return (json.dumps(env, ensure_ascii=False, indent=2) + "\n").encode()


def request_bytes(method: str, path: str, body: bytes, actor: str, ts: str, nonce: str) -> bytes:
    return "\n".join([REQUEST_PREFIX, method.upper(), path, sha_bytes(body), actor, ts, nonce]).encode()


def sign_headers(signer: signing.Signer, method: str, path: str, body: bytes) -> dict:
    ts = str(int(time.time()))
    nonce = secrets.token_hex(16)
    signature = signer.sign_hex(request_bytes(method, path, body, signer.actor, ts, nonce))
    return {"X-AB-Actor": signer.actor, "X-AB-Timestamp": ts, "X-AB-Nonce": nonce,
            "X-AB-Signature": signature}


class TransportError(BridgeError):
    code = "transport"


class StaleHead(TransportError):
    code = "stale_head"


def _error_status(code: str) -> int:
    return {"not_initialised": 409, "broken_ledger": 409, "corrupt_ledger": 409,
            "stale_head": 409, "refused": 400, "not_found": 404, "bad_artifact": 400,
            "transport": 502}.get(code, 500)


# ── client ──────────────────────────────────────────────────────────────────

class HttpBridge:
    """Same surface as `Bridge` for the operations a remote agent needs."""

    def __init__(self, url: str, signer: signing.Signer, timeout: float = 15.0, retries: int = 4):
        self.url = url.rstrip("/")
        self.signer = signer
        self.timeout = timeout
        self.retries = retries

    # -- transport ---------------------------------------------------------

    def _request(self, method: str, path: str, payload=None):
        body = b"" if payload is None else json.dumps(payload, ensure_ascii=False).encode()
        headers = sign_headers(self.signer, method, path, body)
        if payload is not None:
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(self.url + path, data=body or None, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", "replace")
            try:
                err = json.loads(raw)
            except json.JSONDecodeError:
                err = {"code": "transport", "message": raw[:400]}
            code = err.get("code", "transport")
            message = f"remote {exc.code}: {err.get('message', raw[:400])}"
            mapping = {"stale_head": StaleHead, "not_initialised": NotInitialised,
                       "broken_ledger": BrokenLedger, "corrupt_ledger": CorruptLedger,
                       "refused": Refused, "not_found": NotFound}
            raise mapping.get(code, TransportError)(message)
        except urllib.error.URLError as exc:
            raise TransportError(f"cannot reach {self.url}: {exc.reason}")

    def _expect_actor(self, actor):
        if actor and actor != self.signer.actor:
            raise Refused(f"this client signs as {self.signer.actor!r}, not {actor!r}")
        return self.signer.actor

    # -- reads -------------------------------------------------------------

    def head(self) -> dict:
        return self._request("GET", "/api/head")

    def bridge_id(self) -> str:
        return bridge_id_of(self.entries())

    def actors(self) -> list:
        return self._request("GET", "/api/actors")["actors"]

    def verify(self, expect_head=None) -> VerificationReport:
        path = "/api/verify"
        if expect_head:
            path += "?expect_head=" + urllib.parse.quote(expect_head)
        data = self._request("GET", path)
        report = VerificationReport()
        for key, value in data.items():
            if key == "problems":
                report.problems = list(value)
            elif key == "ok":
                continue                       # computed property, reflects problems
            elif hasattr(report, key):
                setattr(report, key, value)
        return report

    def anchor(self) -> dict:
        return self._request("GET", "/api/anchor")

    def doctor(self) -> dict:
        return self._request("GET", "/api/status")

    def entries(self, limit=None) -> list:
        path = "/api/ledger" + (f"?limit={int(limit)}" if limit else "")
        return self._request("GET", path)["entries"]

    def show(self, env_id: str) -> dict:
        return self._request("GET", "/api/envelope?id=" + urllib.parse.quote(env_id))["envelope"]

    def requests(self, actor=None) -> list:
        path = "/api/requests" + (f"?actor={urllib.parse.quote(actor)}" if actor else "")
        return self._request("GET", path)["requests"]

    def _inbox(self, actor) -> list:
        return self._request("GET", "/api/inbox?actor=" + urllib.parse.quote(actor))["envelopes"]

    # -- writes ------------------------------------------------------------

    def _upload(self, path: str, role: str) -> dict:
        with open(path, "rb") as f:
            data = f.read()
        name = os.path.basename(path)
        meta = self._request("POST", "/api/blob",
                             {"name": name, "b64": base64.b64encode(data).decode()})
        ap = os.path.abspath(os.path.expanduser(path))
        return {"role": role, "path": ap, "rel": name, "sha256": meta["sha256"],
                "bytes": meta["bytes"], "stored_as": meta["stored_as"], "recorded_at": now()}

    def _submit(self, build):
        """Build an entry against the current head, submit, retry on a lost race."""
        last = None
        for _ in range(self.retries):
            head = self.head()
            try:
                return self._request("POST", "/api/entry", build(head))
            except StaleHead as exc:
                last = exc
                continue
        raise last or StaleHead("could not append after retries")

    def _entry(self, head, fields) -> dict:
        entry = {**fields, "seq": head["seq"] + 1, "ts": now(), "prev": head["digest"]}
        entry["digest"] = sha_bytes(canon(entry))
        entry["sig_pub"] = self.signer.pub_hex
        entry["sig"] = self.signer.sign_hex(entry["digest"].encode())
        return entry

    def send(self, actor=None, to="", body="", intent="message", attach=None, in_reply_to=None) -> dict:
        actor = self._expect_actor(actor)
        artifacts = [self._upload(p, "target") for p in (attach or [])]
        env = {"v": 2, "id": new_id(actor), "from": actor, "to": to, "intent": intent,
               "in_reply_to": in_reply_to, "created_at": now(), "body": body,
               "artifacts": artifacts, "reply_box": "wire/inbox"}
        env["signature"] = {"alg": signing.ALG, "pub": self.signer.pub_hex,
                            "sig": self.signer.sign_hex(canon(env))}
        blob = envelope_bytes(env)

        def build(head):
            entry = self._entry(head, {"type": "send", "id": env["id"], "actor": actor,
                                       "from": actor, "to": to, "intent": intent,
                                       "in_reply_to": in_reply_to,
                                       "envelope_sha256": sha_bytes(blob),
                                       "artifacts": artifacts})
            return {"entry": entry, "envelope": json.loads(blob), "box": "outbox"}
        result = self._submit(build)
        return {"id": env["id"], "envelope": f"{self.url}/api/envelope?id={env['id']}",
                "ledger_seq": result["seq"], "artifacts": artifacts}

    def deliver(self, actor=None, to="", in_reply_to="", body="", intent="deliver", attach=None) -> dict:
        actor = self._expect_actor(actor)
        artifacts = [self._upload(p, "deliverable") for p in (attach or [])]
        env = {"v": 2, "id": new_id(actor), "from": actor, "to": to, "intent": intent,
               "in_reply_to": in_reply_to, "created_at": now(), "body": body,
               "artifacts": artifacts}
        env["signature"] = {"alg": signing.ALG, "pub": self.signer.pub_hex,
                            "sig": self.signer.sign_hex(canon(env))}
        blob = envelope_bytes(env)

        def build(head):
            entry = self._entry(head, {"type": "deliver", "id": env["id"], "actor": actor,
                                       "from": actor, "to": to, "intent": intent,
                                       "in_reply_to": in_reply_to,
                                       "envelope_sha256": sha_bytes(blob),
                                       "artifacts": artifacts})
            return {"entry": entry, "envelope": json.loads(blob), "box": "inbox"}
        result = self._submit(build)
        return {"id": env["id"], "envelope": f"{self.url}/api/envelope?id={env['id']}",
                "ledger_seq": result["seq"]}

    def commit(self, actor=None, promise="", accept="", ref=None) -> dict:
        actor = self._expect_actor(actor)

        def build(head):
            entry = self._entry(head, {"type": "commit", "id": new_id(actor), "actor": actor,
                                       "ref": ref, "promise": promise, "accept": accept})
            return {"entry": entry}
        result = self._submit(build)
        return {"commit_id": result["id"], "ledger_seq": result["seq"],
                "head": {"seq": result["seq"], "digest": result["digest"]}}

    def register_actor(self, actor=None, pub_hex=None) -> dict:
        actor = self._expect_actor(actor)
        if pub_hex and pub_hex != self.signer.pub_hex:
            raise Refused("the public key does not match the signing key")

        def build(head):
            entry = self._entry(head, {"type": "actor_register", "actor": actor,
                                       "pub": self.signer.pub_hex})
            return {"entry": entry}
        result = self._submit(build)
        return {"registered": actor, "pub_hex": self.signer.pub_hex, "ledger_seq": result["seq"]}

    def poll(self, actor=None, consume=False):
        from .core import PollResult
        actor = self._expect_actor(actor)
        inbox = self._inbox(actor)
        consumed, refused = [], [e for e in inbox if not e["verified"]]
        if consume:
            for env in inbox:
                if not env["verified"]:
                    continue

                def build(head, env=env):
                    entry = self._entry(head, {"type": "consume", "id": env["id"],
                                               "actor": actor,
                                               "envelope_sha256": env["sha256"],
                                               "archived_as": f"wire/archive/{env['id']}.json"})
                    return {"entry": entry, "consume_id": env["id"]}
                self._submit(build)
                consumed.append(env["id"])
        return PollResult(inbox, refused, consumed)


# ── server ──────────────────────────────────────────────────────────────────

class Sequencer:
    def __init__(self, root: str):
        self.bridge = Bridge(root)
        self._nonces: dict[str, float] = {}
        self._lock = threading.Lock()

    # -- auth --------------------------------------------------------------

    def authenticate(self, method: str, path: str, body: bytes, headers) -> str:
        actor = headers.get("X-AB-Actor", "")
        ts = headers.get("X-AB-Timestamp", "")
        nonce = headers.get("X-AB-Nonce", "")
        signature = headers.get("X-AB-Signature", "")
        if not all((actor, ts, nonce, signature)):
            raise Refused("missing authentication headers")
        try:
            when = int(ts)
        except ValueError:
            raise Refused("bad timestamp")
        if abs(time.time() - when) > CLOCK_SKEW_SECONDS:
            raise Refused("timestamp outside the allowed window")
        entries, _ = self.bridge.snapshot()
        registry, _, _ = self.bridge._actor_registry(entries)
        if not registry:
            raise Refused("this bridge has no registered actors — network transport requires signing")
        pub = registry.get(actor)
        if not pub:
            raise Refused(f"actor {actor!r} is not registered")
        if not signing.verify_hex(pub, request_bytes(method, path, body, actor, ts, nonce), signature):
            raise Refused("request signature does not verify")
        with self._lock:
            self._prune_nonces()
            if nonce in self._nonces:
                raise Refused("replayed nonce")
            self._nonces[nonce] = time.time() + CLOCK_SKEW_SECONDS * 2
        return actor

    def _prune_nonces(self):
        cutoff = time.time()
        for k in [k for k, exp in self._nonces.items() if exp < cutoff]:
            del self._nonces[k]

    # -- operations --------------------------------------------------------

    def blob(self, actor: str, payload: dict) -> dict:
        name = payload.get("name") or "blob"
        try:
            data = base64.b64decode(payload["b64"], validate=True)
        except (KeyError, ValueError):
            raise Refused("bad blob payload")
        if len(data) > MAX_BLOB_BYTES:
            raise Refused("blob too large")
        digest = sha_bytes(data)
        store = os.path.join(self.bridge.store)
        os.makedirs(store, exist_ok=True)
        dest = os.path.join(store, digest)
        if not os.path.exists(dest):
            tmp = f"{dest}.tmp.{os.getpid()}.{secrets.token_hex(4)}"
            with open(tmp, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, dest)
        elif sha_file(dest) != digest:
            raise Refused("content store corrupt for this digest")
        return {"name": name, "sha256": digest, "bytes": len(data),
                "stored_as": os.path.relpath(dest, self.bridge.root)}

    def submit(self, actor: str, payload: dict) -> dict:
        entry = payload.get("entry")
        if not isinstance(entry, dict):
            raise Refused("missing entry")
        if entry.get("actor") != actor and entry.get("from") != actor:
            raise Refused("entry actor does not match the authenticated actor")
        envelope = payload.get("envelope")
        box = payload.get("box")
        consume_id = payload.get("consume_id")

        # semantic checks that need the ledger
        entries = self.bridge.entries()
        if entry.get("type") == "deliver":
            ref = entry.get("in_reply_to")
            if not any(e.get("id") == ref and e.get("type") in ("send", "deliver") for e in entries):
                raise NotFound(f"in_reply_to is not a recorded request/delivery: {ref}")
        if entry.get("type") == "commit" and entry.get("ref"):
            ref = entry["ref"]
            if not any(e.get("id") == ref and e.get("type") in ("send", "deliver") for e in entries):
                raise NotFound(f"commit ref is not a recorded request/delivery: {ref}")

        if entry.get("type") in ("send", "deliver"):
            if not isinstance(envelope, dict) or box not in ("outbox", "inbox"):
                raise Refused("send/deliver requires an envelope and a box")
            if envelope.get("from") != actor:
                raise Refused("envelope sender does not match the authenticated actor")
            blob = envelope_bytes(envelope)
            if sha_bytes(blob) != entry.get("envelope_sha256"):
                raise Refused("envelope_sha256 does not match the envelope")
            dest = os.path.join(self.bridge.outbox if box == "outbox" else self.bridge.inbox,
                                f"{envelope['id']}.json")
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            if os.path.exists(dest):
                raise Refused("envelope already exists")
            with open(dest, "wb") as f:
                f.write(blob)
                f.flush()
                os.fsync(f.fileno())
            try:
                return self.bridge.append_entry(entry)
            except BridgeError:
                os.unlink(dest)
                raise

        if entry.get("type") == "consume":
            if not consume_id:
                raise Refused("consume requires consume_id")
            src = os.path.join(self.bridge.inbox, f"{consume_id}.json")
            if not os.path.exists(src):
                raise NotFound(f"envelope not in the inbox: {consume_id}")
            archived = os.path.join(self.bridge.archive, f"{consume_id}.json")
            os.makedirs(self.bridge.archive, exist_ok=True)
            os.replace(src, archived)
            try:
                return self.bridge.append_entry(entry)
            except BridgeError:
                os.replace(archived, src)
                raise

        return self.bridge.append_entry(entry)

    # -- reads -------------------------------------------------------------

    def inbox(self, actor: str) -> list:
        entries = self.bridge.entries()
        known = {e["id"]: e.get("envelope_sha256") for e in entries
                 if e.get("type") in ("send", "deliver")}
        out = []
        box = self.bridge.inbox
        if not os.path.isdir(box):
            return out
        for name in sorted(os.listdir(box)):
            if not name.endswith(".json"):
                continue
            path = os.path.join(box, name)
            try:
                env = json.load(open(path, encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if env.get("to") != actor:
                continue
            digest = sha_file(path)
            out.append({"id": env.get("id"), "from": env.get("from"), "to": env.get("to"),
                        "intent": env.get("intent"), "in_reply_to": env.get("in_reply_to"),
                        "created_at": env.get("created_at"), "body": env.get("body"),
                        "artifacts": env.get("artifacts", []), "sha256": digest,
                        "verified": known.get(env.get("id")) == digest})
        return out

    def requests(self, actor=None) -> list:
        entries = self.bridge.entries()
        known = {e["id"]: e.get("envelope_sha256") for e in entries if e.get("type") == "send"}
        out = []
        box = self.bridge.outbox
        if not os.path.isdir(box):
            return out
        for name in sorted(os.listdir(box)):
            if not name.endswith(".json"):
                continue
            path = os.path.join(box, name)
            try:
                env = json.load(open(path, encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if actor and env.get("to") != actor:
                continue
            digest = sha_file(path)
            out.append({"id": env.get("id"), "from": env.get("from"), "to": env.get("to"),
                        "intent": env.get("intent"), "created_at": env.get("created_at"),
                        "body": env.get("body"), "artifacts": env.get("artifacts", []),
                        "sha256": digest, "verified": known.get(env.get("id")) == digest})
        return out


def make_handler(sequencer: Sequencer):
    class Handler(BaseHTTPRequestHandler):
        server_version = "agentbridge/0.4"

        def log_message(self, fmt, *args):    # keep stdout/stderr clean
            if os.environ.get("AGENTBRIDGE_VERBOSE"):
                sys.stderr.write("agentbridge serve: " + (fmt % args) + "\n")

        def _send(self, status, payload):
            body = json.dumps(payload, ensure_ascii=False).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _handle(self, method):
            parsed = urllib.parse.urlparse(self.path)
            path = parsed.path
            query = urllib.parse.parse_qs(parsed.query)
            body = b""
            if method == "POST":
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
            try:
                actor = sequencer.authenticate(method, self.path, body, self.headers)
                if method == "GET":
                    if path == "/api/head":
                        return self._send(200, sequencer.bridge.head())
                    if path == "/api/anchor":
                        return self._send(200, sequencer.bridge.anchor())
                    if path == "/api/verify":
                        want = (query.get("expect_head") or [None])[0]
                        return self._send(200, sequencer.bridge.verify(expect_head=want).to_dict())
                    if path == "/api/status":
                        return self._send(200, sequencer.bridge.doctor())
                    if path == "/api/ledger":
                        limit = int((query.get("limit") or ["100"])[0])
                        return self._send(200, {"entries": sequencer.bridge.entries()[-limit:]})
                    if path == "/api/envelope":
                        env_id = (query.get("id") or [""])[0]
                        return self._send(200, {"envelope": sequencer.bridge.show(env_id)})
                    if path == "/api/inbox":
                        who = (query.get("actor") or [actor])[0]
                        return self._send(200, {"envelopes": sequencer.inbox(who)})
                    if path == "/api/actors":
                        return self._send(200, {"actors": sequencer.bridge.actors()})
                    if path == "/api/requests":
                        who = (query.get("actor") or [None])[0]
                        return self._send(200, {"requests": sequencer.requests(who)})
                    return self._send(404, {"code": "not_found", "message": f"no route {path}"})
                if method == "POST":
                    payload = json.loads(body.decode()) if body else {}
                    if path == "/api/blob":
                        return self._send(200, sequencer.blob(actor, payload))
                    if path == "/api/entry":
                        return self._send(200, sequencer.submit(actor, payload))
                    return self._send(404, {"code": "not_found", "message": f"no route {path}"})
                return self._send(405, {"code": "refused", "message": "method not allowed"})
            except BridgeError as exc:
                self._send(_error_status(exc.code), {"code": exc.code, "message": str(exc)})
            except json.JSONDecodeError as exc:
                self._send(400, {"code": "refused", "message": f"bad json: {exc}"})
            except Exception as exc:  # noqa: BLE001 - never leak a traceback
                self._send(500, {"code": "transport", "message": f"{type(exc).__name__}: {exc}"})

        def do_GET(self):
            self._handle("GET")

        def do_POST(self):
            self._handle("POST")

    return Handler


def serve(root: str, host: str = "127.0.0.1", port: int = 8765) -> None:
    sequencer = Sequencer(root)
    httpd = ThreadingHTTPServer((host, port), make_handler(sequencer))
    bound = httpd.server_address[1]
    sys.stdout.write(json.dumps({"listening": f"http://{host}:{bound}", "root": sequencer.bridge.root,
                                 "pid": os.getpid()}) + "\n")
    sys.stdout.flush()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
