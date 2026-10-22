# Public snapshot

This tree is a clean, publishable snapshot of agentbridge 0.9.3 (evidence-pack v0.2).

- Source, tests, CLI, MCP/HTTP components, protocol docs and the whitepaper/manual are included.
- Internal commercial strategy, customer/pilot material, agent review logs and the private release
  workspace are intentionally excluded (see `PUBLIC-MANIFEST.md`).
- License: MIT (see `LICENSE`). The evidence-pack v0.2 protocol is frozen only at the technical
  level; approval signatures and production certification are separate matters.

Quick check: `make ci` (needs Node + Ajv for schema validation; otherwise those checks SKIP).
