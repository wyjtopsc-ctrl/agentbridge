# Public snapshot manifest

```json
{
  "snapshot_of": "agentbridge 0.9.3",
  "protocol": "evidence-pack v0.2",
  "license": "MIT",
  "excluded": [
    "docs/strategy-2026-10-21*.md",
    "docs/status-2026-10-21.md",
    "docs/pilot-*.md",
    "docs/first-delivery-drill-*.md",
    "docs/dev-tasks-0.7.0-plan.md",
    "reviews/",
    "deliverables/ (except exports)",
    "dist/",
    "wire/",
    "ledger.jsonl",
    "keys and local credentials"
  ],
  "included": [
    "src/",
    "tests/",
    "examples/",
    "tools/ (public test/build tooling)",
    "docs/ protocol + protocol history + fixtures",
    "frozen/evidence-pack-v0.2/",
    "docs/exports/ (whitepaper, manual, history)"
  ],
  "note": "Frozen protocol material is included for verification; approval signatures and production certification are separate and not implied."
}
```
