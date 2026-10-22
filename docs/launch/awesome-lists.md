# Awesome-list submissions

Read each repository's CONTRIBUTING section first; most require alphabetical order, a one-line
description, and a PR from a real use case. Do not mass-submit the same text.

| List | Candidate entry | Notes |
|---|---|---|
| `awesome-mcp-servers` | `agentbridge` — verifiable delivery/acceptance evidence for agent workflows; MCP stdio server + offline verifier. | Check whether “security/audit” or “productivity” section fits; include repo link and one-line description only. |
| `awesome-ai-agents` | `agentbridge` — signed delivery, rejection/revision and offline evidence packs for multi-agent collaboration. | Framework-agnostic; avoid claiming framework support that is not tested. |
| `awesome-agent-security` (if exists) | `agentbridge` — tamper-evident delivery ledger, key timeline and offline verification. | Emphasize detection/forensics, not prevention. |
| `awesome-verifiable-credentials` | `agentbridge` — delivery evidence packs with Ed25519 signatures and external checkpoints. | Clarify it is not a W3C VC implementation. |
| `awesome-supply-chain-security` | `agentbridge` — evidence packs for AI-generated deliverables with sha256 + signed acceptance. | Only submit if the list accepts AI/agent tooling. |

PR description template:

> Adds agentbridge, an MIT-licensed delivery-evidence layer for multi-agent workflows. It records
> signed delivery/acceptance/revision events and exports an offline-verifiable evidence pack. It is
> pre-1.0 and explicitly does not review file contents in hashes_only mode.
