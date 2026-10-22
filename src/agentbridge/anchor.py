"""Hosted anchor service: an append-only, signed notary for ledger tips.

Why this exists: every defence inside the bridge is rewritable by the same OS user. The only
defence against a coordinated rewrite is a value held *outside* the machine. This module gives
that value a concrete form — a receipt signed by a service that never sees content, only hashes.

Trust model:
  * The client signs its submission with its bridge key; the service binds a bridge id to the
    first public key it sees (trust on first use) and rejects later mismatches.
  * The service signs a receipt over (bridge_id, seq, digest, log_index, received_at, prev).
  * The service's log is an append-only chain of receipts; each receipt signs `prev`, so removing
    or reordering entries breaks the chain. The service publishes its head.
  * The service can refuse to anchor (availability), but cannot forge a receipt without its key,
    and cannot pretend a different digest was anchored at a given index.
"""
from __future__ import annotations

import fcntl
import json
import os
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import signing
from .core import BridgeError, Refused, canon, now, sha_bytes
from .transport import request_bytes, sign_headers

CLOCK_SKEW_SECONDS = 300


# ── receipt helpers (used by both sides) ────────────────────────────────────

from .core import receipt_body, verify_anchor_receipt  # noqa: E402


def verify_receipt(receipt: dict, expect_seq=None, expect_digest=None) -> list[str]:
    """Backwards-compatible alias; the implementation lives in core.verify_anchor_receipt."""
    return verify_anchor_receipt(receipt, expect_seq=expect_seq, expect_digest=expect_digest)


def verify_log(receipts: list[dict]) -> list[str]:
    """Check the service log: indices are dense, prev links, and every receipt verifies."""
    problems = []
    prev = ""
    for i, receipt in enumerate(receipts):
        problems.extend(verify_receipt(receipt))
        if receipt.get("log_index") != i:
            problems.append(f"log index {receipt.get('log_index')} at position {i}")
        if receipt.get("prev") != prev:
            problems.append(f"log chain broken at index {i}")
        prev = receipt.get("service_sig", "")
    return problems


# ── service ─────────────────────────────────────────────────────────────────

class AnchorService:
    def __init__(self, directory: str, signer: signing.Signer):
        self.dir = os.path.abspath(os.path.expanduser(directory))
        self.signer = signer
        self.log_path = os.path.join(self.dir, "log.jsonl")
        self.head_path = os.path.join(self.dir, "head.json")
        self.bridges_path = os.path.join(self.dir, "bridges.json")
        self._lock = threading.Lock()
        self._nonces: dict[str, float] = {}
        self._index: dict[tuple[str, int], dict] = {}
        self._receipts: list[dict] = []
        self._bridges: dict[str, str] = {}
        os.makedirs(self.dir, exist_ok=True)
        self._load()

    def _load(self):
        if os.path.exists(self.bridges_path):
            self._bridges = json.load(open(self.bridges_path, encoding="utf-8"))
        if not os.path.exists(self.log_path):
            return
        with open(self.log_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    receipt = json.loads(line)
                except json.JSONDecodeError:
                    raise Refused("anchor log is corrupt")
                self._receipts.append(receipt)
                self._index[(receipt["bridge_id"], receipt["seq"])] = receipt

    # -- auth --------------------------------------------------------------

    def authenticate(self, method: str, path: str, body: bytes, headers) -> tuple[str, str, str]:
        actor = headers.get("X-AB-Actor", "")
        bridge_id = headers.get("X-AB-Bridge", "")
        client_pub = headers.get("X-AB-Pub", "")
        ts = headers.get("X-AB-Timestamp", "")
        nonce = headers.get("X-AB-Nonce", "")
        signature = headers.get("X-AB-Signature", "")
        if not all((actor, bridge_id, client_pub, ts, nonce, signature)):
            raise Refused("missing authentication headers")
        try:
            when = int(ts)
        except ValueError:
            raise Refused("bad timestamp")
        if abs(time.time() - when) > CLOCK_SKEW_SECONDS:
            raise Refused("timestamp outside the allowed window")
        try:
            pub_bytes = bytes.fromhex(client_pub)
        except ValueError:
            raise Refused("bad public key")
        if not signing.verify(pub_bytes, request_bytes(method, path, body, actor, ts, nonce), bytes.fromhex(signature)):
            raise Refused("request signature does not verify")
        bound = self._bridges.get(bridge_id)
        if bound is None:
            self._bridges[bridge_id] = client_pub
            self._write_json(self.bridges_path, self._bridges)
        elif bound != client_pub:
            raise Refused(f"bridge {bridge_id!r} is bound to a different key (identity mismatch)")
        with self._lock:
            self._prune_nonces()
            if nonce in self._nonces:
                raise Refused("replayed nonce")
            self._nonces[nonce] = time.time() + CLOCK_SKEW_SECONDS * 2
        return bridge_id, client_pub, actor

    def _prune_nonces(self):
        cutoff = time.time()
        for k in [k for k, exp in self._nonces.items() if exp < cutoff]:
            del self._nonces[k]

    def _write_json(self, path, obj):
        tmp = f"{path}.tmp.{os.getpid()}"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False, indent=2)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)

    # -- operations --------------------------------------------------------

    def submit(self, bridge_id: str, client_pub: str, anchor_seq: int, digest: str) -> dict:
        if not isinstance(anchor_seq, int) or anchor_seq < 0:
            raise Refused("seq must be a non-negative integer")
        if not isinstance(digest, str) or len(digest) != 64:
            raise Refused("digest must be a sha256 hex string")
        try:
            bytes.fromhex(digest)
        except ValueError:
            raise Refused("digest must be hex")
        with self._lock:
            existing = self._index.get((bridge_id, anchor_seq))
            if existing is not None:
                if existing["digest"] == digest:
                    return existing            # idempotent: same claim, same receipt
                raise Refused(
                    f"equivocation detected: bridge {bridge_id!r} already anchored seq {anchor_seq} "
                    f"with digest {existing['digest'][:16]}…, now claiming {digest[:16]}…")
            prev = self._receipts[-1]["service_sig"] if self._receipts else ""
            receipt = {"v": 1, "bridge_id": bridge_id, "seq": anchor_seq, "digest": digest,
                       "log_index": len(self._receipts), "received_at": now(),
                       "client_pub": client_pub, "service_pub": self.signer.pub_hex,
                       "prev": prev}
            receipt["service_sig"] = self.signer.sign_hex(canon(receipt))
            with open(self.log_path, "a", encoding="utf-8") as f:
                fcntl.flock(f, fcntl.LOCK_EX)
                try:
                    f.write(json.dumps(receipt, ensure_ascii=False, sort_keys=True) + "\n")
                    f.flush()
                    os.fsync(f.fileno())
                finally:
                    fcntl.flock(f, fcntl.LOCK_UN)
            self._receipts.append(receipt)
            self._index[(bridge_id, anchor_seq)] = receipt
            self._write_json(self.head_path, {
                "log_len": len(self._receipts), "log_index": receipt["log_index"],
                "service_sig": receipt["service_sig"], "service_pub": self.signer.pub_hex,
                "updated_at": receipt["received_at"]})
            return receipt

    def head(self) -> dict:
        with self._lock:
            tip = self._receipts[-1] if self._receipts else None
            return {"log_len": len(self._receipts),
                    "log_index": tip["log_index"] if tip else None,
                    "service_sig": tip["service_sig"] if tip else "",
                    "service_pub": self.signer.pub_hex,
                    "updated_at": tip["received_at"] if tip else None}

    def lookup(self, bridge_id: str, anchor_seq: int):
        with self._lock:
            return self._index.get((bridge_id, anchor_seq))

    def log(self, limit: int = 100) -> list:
        with self._lock:
            return self._receipts[-limit:]


# ── client ──────────────────────────────────────────────────────────────────

def submit(url: str, signer: signing.Signer, bridge_id: str, seq: int, digest: str,
           timeout: float = 15.0) -> dict:
    body = json.dumps({"bridge_id": bridge_id, "seq": seq, "digest": digest},
                      ensure_ascii=False).encode()
    headers = sign_headers(signer, "POST", "/v1/anchor", body)
    headers.update({"X-AB-Bridge": bridge_id, "X-AB-Pub": signer.pub_hex,
                    "Content-Type": "application/json"})
    req = urllib.request.Request(url.rstrip("/") + "/v1/anchor", data=body,
                                 headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", "replace")
        try:
            err = json.loads(raw)
        except json.JSONDecodeError:
            err = {"code": "transport", "message": raw[:300]}
        raise Refused(f"anchor service {exc.code}: {err.get('message', raw[:300])}")
    except urllib.error.URLError as exc:
        raise Refused(f"cannot reach anchor service {url}: {exc.reason}")


# ── HTTP server ─────────────────────────────────────────────────────────────

def make_handler(service: AnchorService):
    class Handler(BaseHTTPRequestHandler):
        server_version = "agentbridge-anchor/0.5"

        def log_message(self, fmt, *args):
            if os.environ.get("AGENTBRIDGE_VERBOSE"):
                sys.stderr.write("anchor: " + (fmt % args) + "\n")

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
                if path == "/v1/head" and method == "GET":
                    return self._send(200, service.head())
                bridge_id, client_pub, _ = service.authenticate(method, self.path, body, self.headers)
                if path == "/v1/anchor" and method == "POST":
                    payload = json.loads(body.decode()) if body else {}
                    if payload.get("bridge_id") != bridge_id:
                        raise Refused("payload bridge_id does not match the authenticated bridge")
                    receipt = service.submit(bridge_id, client_pub,
                                             payload.get("seq"), payload.get("digest"))
                    return self._send(200, receipt)
                if path == "/v1/receipt" and method == "GET":
                    seq = int((query.get("seq") or ["-1"])[0])
                    receipt = service.lookup(bridge_id, seq)
                    if receipt is None:
                        return self._send(404, {"code": "not_found", "message": "no receipt"})
                    return self._send(200, receipt)
                if path == "/v1/log" and method == "GET":
                    return self._send(200, {"receipts": service.log()})
                return self._send(404, {"code": "not_found", "message": f"no route {path}"})
            except Refused as exc:
                status = 409 if "equivocation" in str(exc) else 400
                self._send(status, {"code": "refused", "message": str(exc)})
            except json.JSONDecodeError as exc:
                self._send(400, {"code": "refused", "message": f"bad json: {exc}"})
            except Exception as exc:  # noqa: BLE001
                self._send(500, {"code": "transport", "message": f"{type(exc).__name__}: {exc}"})

        def do_GET(self):
            self._handle("GET")

        def do_POST(self):
            self._handle("POST")

    return Handler


def serve(directory: str, signer: signing.Signer, host: str = "127.0.0.1", port: int = 8790) -> None:
    service = AnchorService(directory, signer)
    httpd = ThreadingHTTPServer((host, port), make_handler(service))
    bound = httpd.server_address[1]
    sys.stdout.write(json.dumps({"listening": f"http://{host}:{bound}", "dir": service.dir,
                                 "service_pub": signer.pub_hex, "pid": os.getpid()}) + "\n")
    sys.stdout.flush()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
