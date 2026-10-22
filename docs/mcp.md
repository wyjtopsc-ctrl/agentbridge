# MCP server

`agentbridge` ships a [Model Context Protocol](https://modelcontextprotocol.io) server over stdio,
so any MCP-capable agent can use a bridge as a set of tools without writing Python.

## Run it

```console
agentbridge --root /abs/path/to/shared mcp --actor worker
```

`--actor` is the identity this server writes as. `--root` is the shared bridge directory.

For a two-agent setup, give each agent its own server process with its own `--actor`; both point at
the same `--root`. This matters: the actor is what the ledger records, and one server cannot be two
agents.

## Client configuration

Any MCP client that supports stdio servers can use this shape:

```json
{
  "mcpServers": {
    "agentbridge": {
      "command": "python3",
      "args": ["-m", "agentbridge", "--root", "/abs/path/to/shared", "mcp", "--actor", "worker"],
      "env": { "PYTHONPATH": "/abs/path/to/agentbridge/src" }
    }
  }
}
```

If the package is pip-installed, drop `PYTHONPATH` and use `"command": "agentbridge"` with
`"args": ["--root", "/abs/path/to/shared", "mcp", "--actor", "worker"]`.

## Tools

| Tool | Side effects | Use |
|---|---|---|
| `bridge_status` | none | ledger counts, inbox/outbox, current verification result |
| `list_requests` | none | pending requests addressed to an agent |
| `show_envelope` | none | one envelope by id |
| `read_ledger` | none | last N entries |
| `verify_bridge` | none | chain + envelopes + artifact store; optional `expect_head` anchor |
| `get_anchor` | none | the head digest to copy off-filesystem |
| `list_actors` | none | the trust set: actors, key fingerprints, registration sequence |
| `diagnose` | none | structured health report including `anchor_level` |
| `propose_repair` | none | repair commands and preconditions; never executes |
| `send_request` | writes envelope + ledger | ask the other agent for work |
| `deliver_result` | writes envelope + ledger | answer a recorded request |
| `poll_inbox` | writes ledger if `consume` | read deliveries; unverified ones are refused |
| `record_commitment` | writes ledger | "I will do X, done when Y" |

A typical loop:

1. planner: `send_request {to: "worker", body: "...", attach: ["/path/module.py"]}` → returns `id`
2. worker: `list_requests {actor: "worker"}` → sees the request and its verified status
3. worker: `deliver_result {to: "planner", in_reply_to: "<id>", body: "...", attach: ["/path/findings.md"]}`
4. planner: `poll_inbox {actor: "planner", consume: true}` → verified delivery archived
5. planner: `verify_bridge {}` → `{"ok": true, ...}`
6. planner: `get_anchor {}` → copy `verify_with` somewhere off-disk

## Protocol behaviour

- Transport: newline-delimited JSON-RPC 2.0 over stdin/stdout (the MCP stdio transport). A
  `Content-Length` framing fallback is accepted for robustness.
- `initialize` echoes the client's protocol version when it is one of `2024-11-05`, `2025-03-26`,
  `2025-06-18`, otherwise answers with the newest supported one.
- Notifications (`notifications/initialized`, `notifications/cancelled`) produce no response.
- `ping` returns `{}`; `resources/list` and `prompts/list` return empty lists.
- Unknown methods return JSON-RPC `-32601`; unknown tools `-32602`.
- Bridge errors come back as a tool result with `"isError": true` and text `"[code] message"`, so a
  model can read and act on them (`not_initialised`, `broken_ledger`, `refused`, …).
- stdout is protocol only. Diagnostics go to stderr.

## Verified against

The hand-rolled stdio transport is cross-checked with the **official MCP Python SDK 2.3.0**
(`tests/crosscheck_official_sdk.py`): initialize / protocol negotiation, `tools/list`, and every
tool call. It has also been used for a real review task by a different agent harness (Hermes),
which discovered 10 tools, read a pending request, wrote findings, delivered them, verified the
ledger and recorded a commitment — all through MCP, no filesystem shortcuts.

One operational detail from that run: **take the anchor after your last write.** `get_anchor`
returns the tip at call time; if you then record a commitment, `--expect-head` on the older value
will legitimately fail. Either call `get_anchor` last, or call it again.

## Destructive tools are opt-in

`repair` and `recover_empty` write to the ledger, so they are **not registered by default**. Start
the server with `--allow-destructive-tools` to expose them; both still require explicit consent
arguments (`accept_head_loss=true` / `consent=true`). The default surface stays read-only beyond the
normal send/deliver/poll/commit/register tools.

## Security notes

- The server runs with the permissions of the process that started it. `attach` accepts any path
  that process can read, and the content is copied into the bridge store. Do not point an agent at
  files you would not let it read.
- `poll_inbox {consume: true}` has side effects: verified envelopes are archived and recorded.
  Default is `false`.
- One server per agent identity. Two agents sharing one process would share one actor name.
- There is no authentication on stdio; it is a local transport. Exposing it over a network would
  need a different transport and a real identity layer (see `docs/threat-model.md`).

## Limitations

The MCP surface exposes the bridge, not a new capability model: it cannot make an untrusted agent
trusted, and `verified` still means "this envelope is the one the ledger records", not "the sender
is who it claims". The external anchor remains the human's job.
