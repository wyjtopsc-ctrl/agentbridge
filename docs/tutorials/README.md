# Tutorials

Three ways to put verifiable delivery around an existing agent workflow. All examples call the
same primitives; pick the integration shape that matches your stack.

1. [MCP client](01-mcp.md) — expose delivery/verification as MCP tools.
2. [LangGraph](02-langgraph.md) — wrap graph nodes with send/deliver/accept.
3. [CrewAI](03-crewai.md) — record task output and acceptance from callbacks.

Every tutorial keeps the same boundary: the library records and verifies **delivery evidence**; it
does not judge quality, and `hashes_only` packs do not review file contents.
