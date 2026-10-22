"""Minimal MCP (Model Context Protocol) server over stdio, zero dependencies.

Why hand-rolled: agentbridge's selling point is that `pip install` pulls in nothing. The
MCP stdio transport is newline-delimited JSON-RPC 2.0, which is small enough to implement
correctly for the subset we need (initialize / tools list / tools call / ping).

The server binds to one bridge directory and exposes it as a set of tools. It never writes
to stdout except for protocol messages; diagnostics go to stderr.
"""
from __future__ import annotations

import json
import sys
import traceback

from . import __version__
from .core import Bridge, BridgeError

SUPPORTED_VERSIONS = ("2024-11-05", "2025-03-26", "2025-06-18")
LATEST_VERSION = SUPPORTED_VERSIONS[-1]


def _schema(properties: dict, required: list[str] | None = None) -> dict:
    return {"type": "object", "properties": properties, "required": required or [],
            "additionalProperties": False}


TOOLS = [
    {
        "name": "bridge_status",
        "description": "Report the bridge directory, ledger size, inbox/outbox counts, and whether "
                       "the record currently verifies. Read-only; safe to call at any time.",
        "inputSchema": _schema({}),
    },
    {
        "name": "send_request",
        "description": "Send a request to the other agent. Attachments are hashed and copied into "
                       "the content-addressed store. Returns the envelope id to quote when replying.",
        "inputSchema": _schema({
            "to": {"type": "string", "description": "recipient agent name"},
            "body": {"type": "string", "description": "the request text"},
            "intent": {"type": "string", "description": "free-form label, e.g. review / handoff"},
            "attach": {"type": "array", "items": {"type": "string"},
                       "description": "absolute or relative file paths to attach"},
            "in_reply_to": {"type": "string", "description": "envelope id being replied to"},
        }, ["to"]),
    },
    {
        "name": "deliver_result",
        "description": "Deliver a result in reply to a recorded request. The deliverable is hashed "
                       "and stored; the reply becomes verifiable by the requester.",
        "inputSchema": _schema({
            "to": {"type": "string", "description": "recipient agent name"},
            "in_reply_to": {"type": "string", "description": "id of the request being answered"},
            "body": {"type": "string", "description": "the delivery text / conclusion"},
            "intent": {"type": "string", "description": "free-form label"},
            "attach": {"type": "array", "items": {"type": "string"},
                       "description": "absolute or relative file paths to attach"},
        }, ["to", "in_reply_to"]),
    },
    {
        "name": "list_requests",
        "description": "List pending requests (the outbox) addressed to an agent. Read-only: a "
                       "request stays here until the sender archives it, so it can be re-read.",
        "inputSchema": _schema({
            "actor": {"type": "string", "description": "which agent's requests to list"},
        }, ["actor"]),
    },
    {
        "name": "poll_inbox",
        "description": "Read envelopes addressed to this agent. With consume=true, verified "
                       "envelopes are archived and recorded; unverified ones are refused and left "
                       "in place (listed under 'refused').",
        "inputSchema": _schema({
            "actor": {"type": "string", "description": "which agent's inbox to read"},
            "consume": {"type": "boolean", "description": "archive verified envelopes"},
        }, ["actor"]),
    },
    {
        "name": "verify_bridge",
        "description": "Verify the hash chain, every envelope, and the artifact store. Optionally "
                       "check against an external anchor held by the human.",
        "inputSchema": _schema({
            "expect_head": {"type": "string", "description": "SEQ:DIGEST anchor to check against"},
        }),
    },
    {
        "name": "get_anchor",
        "description": "Return the current head digest. Copy it somewhere outside the filesystem "
                       "to defend against a coordinated rewrite of the ledger and head file.",
        "inputSchema": _schema({}),
    },
    {
        "name": "record_commitment",
        "description": "Record a promise ('I will fix X', 'done when Y') in the ledger so both "
                       "sides can cite it later.",
        "inputSchema": _schema({
            "promise": {"type": "string"},
            "accept": {"type": "string", "description": "what counts as done"},
            "ref": {"type": "string", "description": "envelope id this commitment refers to"},
            "actor": {"type": "string", "description": "who is promising"},
        }, ["promise"]),
    },
    {
        "name": "register_actor",
        "description": "Register this server's signing key as an actor in the ledger. Requires the "
                       "server to be started with --key. The first registration for an actor wins.",
        "inputSchema": _schema({}),
    },
    {
        "name": "list_actors",
        "description": "List the trust set: registered actors with key fingerprints and registration "
                       "sequence numbers. Read-only; this is what a security review asks for first.",
        "inputSchema": _schema({}),
    },
    {
        "name": "diagnose",
        "description": "Structured health report: verification result, anchor level, problems, and "
                       "ledger/envelope/artifact counts. Read-only.",
        "inputSchema": _schema({}),
    },
    {
        "name": "propose_repair",
        "description": "Propose repair commands for the current problems, with preconditions. It "
                       "never executes anything: the human decides. Read-only.",
        "inputSchema": _schema({}),
    },
    {
        "name": "show_envelope",
        "description": "Return one envelope by id, wherever it currently lives (outbox, inbox, archive).",
        "inputSchema": _schema({"id": {"type": "string"}}, ["id"]),
    },
    {
        "name": "read_ledger",
        "description": "Return the last N ledger entries (default 20).",
        "inputSchema": _schema({"limit": {"type": "integer", "minimum": 1, "maximum": 500}}),
    },
]

DESTRUCTIVE_TOOLS = [
    {
        "name": "repair",
        "description": "WRITE: re-anchor a ledger whose head is stale or missing. Destructive to the "
                       "old anchor; requires accept_head_loss=true and human confirmation.",
        "inputSchema": _schema({
            "accept_head_loss": {"type": "boolean",
                                 "description": "must be true: acknowledges abandoning the old head"},
        }, ["accept_head_loss"]),
    },
    {
        "name": "recover_empty",
        "description": "WRITE: write a genesis entry over an empty ledger left by a failed first "
                       "append. Requires consent=true; only valid when no head anchor exists.",
        "inputSchema": _schema({
            "consent": {"type": "boolean", "description": "must be true; leaves a recorded genesis note"},
        }, ["consent"]),
    },
]

TOOL_NAMES = [t["name"] for t in TOOLS]


class McpServer:
    def __init__(self, bridge, actor: str = "agent", allow_destructive: bool = False):
        self.bridge = bridge
        self.actor = actor
        self.tools = TOOLS + (DESTRUCTIVE_TOOLS if allow_destructive else [])
        self.tool_names = [t["name"] for t in self.tools]

    # -- protocol ----------------------------------------------------------

    def handle(self, message: dict):
        method = message.get("method")
        msg_id = message.get("id")
        params = message.get("params") or {}
        is_notification = "id" not in message

        if method == "initialize":
            requested = params.get("protocolVersion")
            version = requested if requested in SUPPORTED_VERSIONS else LATEST_VERSION
            return self._result(msg_id, {
                "protocolVersion": version,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "agentbridge", "version": __version__},
                "instructions": "Verifiable delivery between agents. Record what was requested, what "
                                "was delivered, and hold the anchor outside this filesystem.",
            })
        if method in ("notifications/initialized", "notifications/cancelled"):
            return None
        if method == "ping":
            return self._result(msg_id, {})
        if method == "tools/list":
            return self._result(msg_id, {"tools": self.tools})
        if method == "tools/call":
            return self._call(msg_id, params)
        if method == "resources/list":
            return self._result(msg_id, {"resources": []})
        if method == "prompts/list":
            return self._result(msg_id, {"prompts": []})
        if is_notification:
            return None
        return self._error(msg_id, -32601, f"method not found: {method}")

    def _result(self, msg_id, result):
        return {"jsonrpc": "2.0", "id": msg_id, "result": result}

    def _error(self, msg_id, code, message):
        return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}

    def _call(self, msg_id, params):
        name = params.get("name")
        args = params.get("arguments") or {}
        if name not in self.tool_names:
            return self._error(msg_id, -32602, f"unknown tool: {name}")
        try:
            payload = self._dispatch(name, args)
        except BridgeError as exc:
            return self._result(msg_id, {
                "content": [{"type": "text", "text": f"[{exc.code}] {exc}"}], "isError": True})
        except (KeyError, TypeError, ValueError) as exc:
            return self._result(msg_id, {
                "content": [{"type": "text", "text": f"bad arguments: {exc}"}], "isError": True})
        return self._result(msg_id, {"content": [{"type": "text", "text": payload}], "isError": False})

    # -- tools -------------------------------------------------------------

    def _dispatch(self, name: str, args: dict) -> str:
        if name == "bridge_status":
            report = self.bridge.verify()
            info = self.bridge.doctor()
            return _json({"verified": report.ok, "chain_ok": report.chain_ok,
                          "ledger_entries": report.ledger_len,
                          "envelopes_checked": report.envelopes_checked,
                          "artifacts_ok": report.artifacts_ok,
                          "problems": report.problems, "bridge": info})
        if name == "send_request":
            result = self.bridge.send(actor=self.actor, to=args["to"], body=args.get("body", ""),
                                      intent=args.get("intent", "message"),
                                      attach=args.get("attach"), in_reply_to=args.get("in_reply_to"))
            return _json(result)
        if name == "deliver_result":
            result = self.bridge.deliver(actor=self.actor, to=args["to"],
                                         in_reply_to=args["in_reply_to"],
                                         body=args.get("body", ""),
                                         intent=args.get("intent", "deliver"),
                                         attach=args.get("attach"))
            return _json(result)
        if name == "list_requests":
            envs = self.bridge.requests(actor=args["actor"])
            return _json({"requests": [{k: v for k, v in e.items() if k != "_envelope"}
                                       | {"verified": e["_verified"]} for e in envs]})
        if name == "poll_inbox":
            result = self.bridge.poll(actor=args["actor"], consume=args.get("consume") is True)
            return _json({
                "envelopes": [{k: v for k, v in e.items() if not k.startswith("_")}
                              | {"verified": e["_verified"]} for e in result.envelopes],
                "refused": [e["id"] for e in result.refused],
                "consumed": result.consumed,
            })
        if name == "verify_bridge":
            report = self.bridge.verify(expect_head=args.get("expect_head"))
            return _json(report.to_dict())
        if name == "get_anchor":
            return _json(self.bridge.anchor())
        if name == "record_commitment":
            return _json(self.bridge.commit(actor=args.get("actor", self.actor),
                                            promise=args["promise"],
                                            accept=args.get("accept", ""),
                                            ref=args.get("ref")))
        if name == "register_actor":
            if not self.bridge.signer:
                raise ValueError("this server has no signing key; start it with --key <keyfile>")
            return _json(self.bridge.register_actor(self.bridge.signer.actor,
                                                    self.bridge.signer.pub_hex))
        if name == "list_actors":
            return _json({"actors": self.bridge.actors()})
        if name == "diagnose":
            report = self.bridge.verify()
            return _json({"verified": report.ok, "anchor_level": report.anchor_level,
                          "problems": report.problems, "state": self.bridge.doctor()})
        if name == "propose_repair":
            return _json(self._propose_repair())
        if name == "repair":
            if not isinstance(self.bridge, Bridge):
                raise ValueError("remote transport: run repair on the sequencer host")
            if args.get("accept_head_loss") is not True:
                raise ValueError("refusing: accept_head_loss must be boolean true "
                                 "(a string such as \"false\" does not count)")
            return _json(self.bridge.repair(actor=self.actor, accept_head_loss=True))
        if name == "recover_empty":
            if not isinstance(self.bridge, Bridge):
                raise ValueError("remote transport: run init --recover-empty on the sequencer host")
            if args.get("consent") is not True:
                raise ValueError("refusing: consent must be boolean true "
                                 "(a string such as \"false\" does not count)")
            return _json({"message": self.bridge.init(actor=self.actor, recover_empty=True)})
        if name == "show_envelope":
            return _json(self.bridge.show(args["id"]))
        if name == "read_ledger":
            limit = int(args.get("limit", 20))
            entries = self.bridge.entries()[-limit:]
            return _json({"entries": entries, "returned": len(entries)})
        raise ValueError(f"unknown tool: {name}")

    def _propose_repair(self) -> dict:
        if not isinstance(self.bridge, Bridge):
            return {"requires_human": True, "actions": [],
                    "note": "remote transport: run `agentbridge --root <dir> ...` on the sequencer host"}
        report = self.bridge.verify()
        if report.ok:
            return {"requires_human": True, "actions": [],
                    "note": "nothing to repair: verification passes"}
        joined = " | ".join(report.problems)
        root = self.bridge.root
        actions = []
        if "head anchor mismatch" in joined or "head anchor missing" in joined:
            actions.append({"command": f'agentbridge --root "{root}" repair --accept-head-loss',
                            "reason": "the ledger tip does not match the head anchor",
                            "precondition": "human accepts abandoning whatever the old anchor covered"})
        if "ledger is empty" in joined:
            actions.append({"command": f'agentbridge --root "{root}" init --recover-empty',
                            "reason": "empty ledger left by a failed first append",
                            "precondition": "no head anchor exists"})
        if "init marker missing" in joined:
            actions.append({"command": f'agentbridge --root "{root}" init --rebind-marker',
                            "reason": "init marker is missing",
                            "precondition": "ledger chain and head are intact"})
        if "does not match the genesis entry" in joined:
            actions.append({"command": None,
                            "reason": "the ledger was rebuilt; restore from a backup",
                            "precondition": "no in-place repair exists for this case"})
        if not actions:
            actions.append({"command": None, "reason": "manual inspection required",
                            "detail": report.problems})
        return {"requires_human": True, "actions": actions}

    # -- transport ---------------------------------------------------------

    def serve(self, stdin=None, stdout=None) -> int:
        stdin = stdin or sys.stdin
        stdout = stdout or sys.stdout
        while True:
            message = _read_message(stdin)
            if message is None:
                return 0
            if isinstance(message, list):          # batch (older protocol); answer each
                responses = [r for r in (self.handle(m) for m in message if isinstance(m, dict)) if r]
            else:
                response = self.handle(message)
                responses = [response] if response else []
            for resp in responses:
                stdout.write(json.dumps(resp, ensure_ascii=False) + "\n")
                stdout.flush()


def _json(obj) -> str:
    return json.dumps(obj, ensure_ascii=False, indent=2)


def _read_message(stdin):
    """Read one JSON-RPC message: newline-delimited JSON, with Content-Length as a fallback."""
    while True:
        line = stdin.readline()
        if not line:
            return None
        line = line.rstrip("\r\n")
        if not line:
            continue
        if line.lower().startswith("content-length:"):
            try:
                length = int(line.split(":", 1)[1].strip())
            except ValueError:
                continue
            stdin.readline()                      # blank line after headers
            body = stdin.read(length)
            return json.loads(body)
        try:
            return json.loads(line)
        except json.JSONDecodeError:
            sys.stderr.write(f"agentbridge mcp: dropping unparseable line: {line[:120]!r}\n")
            sys.stderr.flush()
            continue


def run_stdio(bridge, actor: str = "agent", allow_destructive: bool = False) -> int:
    # The signing key is the identity: over a transport that authenticates every request,
    # a mismatch between --actor and the key would be rejected by the sequencer.
    signer = getattr(bridge, "signer", None)
    if signer is not None:
        actor = signer.actor
    server = McpServer(bridge, actor=actor, allow_destructive=allow_destructive)
    try:
        return server.serve()
    except KeyboardInterrupt:
        return 0
    except Exception:                              # never leak a traceback onto stdout
        sys.stderr.write("agentbridge mcp: fatal\n" + traceback.format_exc())
        return 1
