#!/usr/bin/env python3
"""Cross-check agentbridge's hand-rolled MCP server against the official MCP Python SDK.

The server in `agentbridge/mcp_server.py` implements the stdio transport by hand so the
package keeps zero runtime dependencies. This script is the independent check: it uses the
official `mcp` client to spawn the server, initialize the session, list tools, and call them.

    python3.11 -m venv .venv
    .venv/bin/pip install mcp
    PYTHONPATH=src .venv/bin/python tests/crosscheck_official_sdk.py

Exits non-zero on any mismatch.
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(os.path.dirname(HERE), "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

from agentbridge import Bridge  # noqa: E402

try:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
except ImportError:  # pragma: no cover - only runs when the optional SDK is present
    sys.stderr.write("crosscheck: the official 'mcp' package is not installed in this interpreter\n"
                     "  python3.11 -m venv .venv && .venv/bin/pip install mcp\n")
    sys.exit(2)

EXPECTED_TOOLS = {
    "bridge_status", "send_request", "deliver_result", "list_requests", "poll_inbox",
    "verify_bridge", "get_anchor", "record_commitment", "show_envelope", "read_ledger",
}


def text_of(result) -> str:
    parts = []
    for item in result.content:
        text = getattr(item, "text", None)
        if text is not None:
            parts.append(text)
    return "".join(parts)


def is_error(result) -> bool:
    return bool(getattr(result, "is_error", getattr(result, "isError", False)))


async def main() -> int:
    work = tempfile.mkdtemp(prefix="agentbridge-crosscheck.")
    root = os.path.join(work, "bridge")
    Bridge(root).init(actor="planner")

    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "agentbridge", "--root", root, "mcp", "--actor", "crosscheck"],
        env=dict(os.environ, PYTHONPATH=SRC),
    )

    failures = []

    def check(condition, label):
        print(("PASS  " if condition else "FAIL  ") + label)
        if not condition:
            failures.append(label)

    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            init = await session.initialize()
            server_info = getattr(init, "server_info", None) or getattr(init, "serverInfo")
            protocol = getattr(init, "protocol_version", None) or getattr(init, "protocolVersion")
            print(f"      server: {server_info.name} {server_info.version} (protocol {protocol})")
            check(server_info.name == "agentbridge", "initialize → serverInfo.name")

            tools = await session.list_tools()
            names = {t.name for t in tools.tools}
            check(EXPECTED_TOOLS <= names, f"tools/list exposes all {len(EXPECTED_TOOLS)} tools")
            check(all((getattr(t, "input_schema", None) or t.inputSchema).get("type") == "object"
                      for t in tools.tools),
                  "every tool has an object inputSchema")

            status = await session.call_tool("bridge_status", {})
            check(not is_error(status), "bridge_status is not an error")
            payload = json.loads(text_of(status))
            check(payload["verified"] is True and payload["chain_ok"] is True,
                  "bridge_status reports a verified chain")

            artifact = os.path.join(work, "module.py")
            with open(artifact, "w") as f:
                f.write("x = 1\n")
            sent = await session.call_tool("send_request",
                                           {"to": "worker", "body": "review", "attach": [artifact]})
            check(not is_error(sent), "send_request succeeds")
            envelope_id = json.loads(text_of(sent))["id"]

            listed = await session.call_tool("list_requests", {"actor": "worker"})
            requests = json.loads(text_of(listed))["requests"]
            check(len(requests) == 1 and requests[0]["id"] == envelope_id,
                  "list_requests sees the request, verified")

            delivered = await session.call_tool("deliver_result",
                                                {"to": "planner", "in_reply_to": envelope_id,
                                                 "body": "done"})
            check(not is_error(delivered), "deliver_result succeeds")

            polled = await session.call_tool("poll_inbox", {"actor": "planner", "consume": True})
            payload = json.loads(text_of(polled))
            check(len(payload["consumed"]) == 1 and payload["refused"] == [],
                  "poll_inbox consumes exactly the verified delivery")

            report = json.loads(text_of(await session.call_tool("verify_bridge", {})))
            check(report["ok"] is True, "verify_bridge reports ok")

            anchor = json.loads(text_of(await session.call_tool("get_anchor", {})))
            check("verify_with" in anchor, "get_anchor returns a copyable anchor")

            bad = await session.call_tool("send_request", {"body": "missing recipient"})
            check(is_error(bad), "a bad tool call comes back as isError")

    print(f"\n{len(failures)} failure(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
