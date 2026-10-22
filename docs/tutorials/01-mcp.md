# 1. MCP: give an agent delivery evidence tools

Goal: an MCP client can send a request, deliver a result, and verify the record without shelling out.

## Start the server

```console
$ mkdir -p keys shared
$ agentbridge keygen --actor client --out keys
$ agentbridge keygen --actor worker --out keys
$ agentbridge --root shared init --actor client
$ agentbridge --root shared --key keys/client.key register
$ agentbridge --root shared --key keys/worker.key register
$ agentbridge --root shared --key keys/client.key mcp
```

The server speaks stdio JSON-RPC. Read-only and safe-write tools are exposed by default;
destructive tools (`repair`, `recover_empty`) require `--allow-destructive-tools` and a boolean
`consent=true` argument.

## Tool flow

| Step | Tool | Key arguments |
|---|---|---|
| send request | `send_request` | `to`, `body`, `attach` |
| deliver | `deliver_result` | `in_reply_to`, `body`, `attach` |
| read inbox | `poll_inbox` | `actor`, `consume` (boolean only) |
| verify | `verify_bridge` | — |
| inspect | `list_actors`, `read_ledger`, `diagnose` | — |

A minimal MCP client using the official Python SDK (version-dependent API; adapt to your SDK):

```python
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

params = StdioServerParameters(command="agentbridge", args=["--root", "shared"])
async with stdio_client(params) as (read, write):
    async with ClientSession(read, write) as session:
        await session.initialize()
        sent = await session.call_tool("send_request", {"to": "worker", "body": "review"})
        # later: deliver_result with the request id
        await session.call_tool("verify_bridge", {})
```

## Export and verify the evidence pack

MCP is the runtime path; the evidence pack is exported by the CLI (so the receiver does not need
MCP at all):

```console
$ agentbridge --root shared --key keys/exporter.key \
    evidence export --delivery <v2 id> --out ./pack \
    --status ./status.json --task-system linear --task-id ENG-42
$ agentbridge evidence verify --pack ./pack --trust ./trust.json
```

The trust file must be delivered out-of-band and must live outside the pack.
