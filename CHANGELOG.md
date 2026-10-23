# Changelog

All notable changes to `agentbridge`. Versions follow semver; the project is pre-1.0, so minor
versions may change behaviour.

## 0.9.4 — replay and timestamp hardening

- Sequencer nonce state is persisted (`wire/sequencer-nonces.json`); restart replay is rejected
  and corrupt/unwritable nonce state fails closed.
- Rotation-authorization boundaries are compared as timezone-aware datetimes, not strings;
  missing/invalid timestamps do not pass.
- Tests: 111 (transport 12, evidence v2 13).
- evidence-pack v0.2 field/format unchanged; 0.9.3 remains the frozen protocol baseline.

## 0.9.3 — leak-time semantics + export write blocking

- Trusted time for a suspected compromise only bounds whether a record existed before the
  earliest possible invalidation; it does not restore key trust. Rotations after a known or
  unknown leak start are rejected (`E-ROTATE-AFTER-COMPROMISE`); recovery needs K3.
- Export now holds a shared lock on the ledger for the whole read, blocking writers; a new
  concurrent test checks the exported snapshot against the ledger tip.
- Protocol/drill docs add receiver restatement questions, pilot-admission checklist, and the
  hashes_only disclosure requirement.
- Tests: 109.

## 0.9.2 — freeze-candidate semantics

- Rotation authorization: a revoked key cannot authorize a rotation (`E-ROTATE-AFTER-REVOCATION`);
  trust no longer propagates through a revocation boundary.
- Revision binding: manifest delivery rows must match the original ledger entry (type, id,
  delivery_id, version, previous_delivery) — `E-DELIVERY-BINDING`.
- `superseded` only affects the expectation check (not_applicable); signatures, bindings and
  historical acceptances are still fully verified.
- Verifier output now carries a `disclosure` line: hashes_only verifies delivery digests and
  signing records, not file content.
- Protocol text: `docs/evidence-pack-v0.2.md` (freeze candidate); 107 tests.

## 0.9.1 — revision-rule negative tests

- Added two v0.2 tests that tamper with the exported manifest and re-sign it: duplicate version
  labels and a broken `previous_version` chain must both be rejected (`E-DUPLICATE-VERSION`,
  `E-REVISION-CHAIN`).
- Total tests: 103.

## 0.9.0 — evidence pack v0.2 (K4 + revisions)

- Product: deliveries carry versions and revision links (`deliver --version --revises`); acceptance
  binds logical delivery + version; rejection and re-acceptance are first-class.
- Export emits `agentbridge-evidence/0.2`: `identity.history` (register/rotate/revoke tied to ledger
  seq + digest), all versions of a delivery, per-version acceptances.
- Verifier: replays the key timeline from the original ledger, cross-checks manifest history,
  selects the key active at each record, enforces revision chain (duplicate version, broken
  previous_version), dangling acceptance, superseded acceptances (not_applicable) and conflicts
  (unknown). Expected-version rules apply only to the accepted/superseded outcome.
- Schema `evidence-pack-v0.2.schema.json`; fixed fixture generated from a real bridge flow
  (deliver v1 -> reject -> rotate -> revise v2 -> accept) in `docs/fixtures/evidence-pack-v0.2/`.
- Tests: 5 real-bridge v0.2 tests; total 101. Known limits: K3 emergency recovery still deferred;
  content remains `hashes_only`.

## 0.8.0 — key lifecycle (K1)

- `rotate_key`: succession entry signed by the old key, with the new key's proof (`new_sig`);
  the old key can no longer write afterwards.
- `revoke_key`: records `normal_retirement`, `suspected_compromise` or `revoked` with effective
  and suspected-leak times; history is not rewritten, future writes are refused.
- Verification now replays a key timeline: each entry/envelope is checked against the key active
  at its ledger position; `verify` reports `key_status`.
- CLI: `rotate`, `revoke`, `key-status`.
- Tests: 7 key-lifecycle tests; total 96. Known limitation: evidence packs do not yet carry the
  key timeline (K4), so exporting a rotated/revoked bridge will report identity uncertainty.

## 0.7.3 — CI gate and fuzzing

- `tools/ci.py` + `make ci`: one entry point running all 7 product suites, the 16-case protocol
  matrix, rebuild determinism, static schema checks, Ajv instance validation, fuzz, and the
  independent crypto cross-check (13 checks; optional toolchains are SKIP, never PASS).
- `tools/fuzz_pack.py`: deterministic malformed-pack fuzzing; 300/300 mutations never crash and
  never report a mutated pack as fully valid.
- Verifier is now wrapped fail-closed: unexpected exceptions become protocol errors (exit 3).
- Pinned test tooling: `tools/package.json` (ajv 8.20.0, ajv-formats 3.0.1) and
  `tools/requirements-test.txt` (cryptography 50.0.2); GitHub Actions workflow added.
- Total tests: 89.

## 0.7.2 — sdist packaging fix

- The sdist ignore rules excluded `wire/` and `ledger.jsonl` globally, which stripped the frozen
  0.6.1 golden corpus from `tests/golden/`. Tests are now copied with their own ignore rules.
- Release gate now runs the full 89-test suite from the unpacked sdist and from an installed
  wheel, not just a smoke test.

## 0.7.1 — evidence-pack hardening tests

- 10 adversarial tests (`tests/run_evidence_hardening.py`): tail truncation with/without receipt,
  export leaves the source bridge byte-identical, acceptance-record transplant, foreign acceptance
  signer, total exit-code aggregation, acceptance rollback on ledger failure, snapshot never
  returns partial lines, default-deny for malformed packs, frozen 0.6.1 golden corpus.
- Verifier fixes found by those tests: missing manifest fields and empty/non-genesis ledgers are
  protocol errors (exit 3); an acceptance record whose fields disagree with the manifest entry is
  rejected with `E-RECORD-MISMATCH`.
- Golden corpus generated from the released `agentbridge-0.6.1.tar.gz` (not from 0.7.x code).
- Total tests: 89 (30+11+12+11+10+5+10).

## 0.7.0 — evidence packs (delivery acceptance + offline verification)

- `accept_delivery`: acceptance/rejection records signed with the evidence domain, stored as
  original files; ledger gains `accept`/`reject` entries that reference `record_sha256`.
  Legacy ledger/envelope/receipt verification rules are unchanged.
- `evidence export`: export one real delivery chain into the v0 evidence-pack layout — full
  ledger slice from genesis, verbatim envelopes, acceptance records, signed status file, anchor
  receipts, and a signed manifest (`content_mode=hashes_only`).
- `evidence verify`: six-axis offline verification (integrity, identity, acceptance, coverage,
  anchoring, content) with external trust input; trust files inside the pack are refused.
- Protocol decisions recorded in `docs/adr-0001-evidence-pack-v0.md`; real-bridge export spike
  confirms the mapping (see `tools/spike_export_real_pack.py`).
- Tests: 79 total (added 5 evidence tests). Known limits: no attachment content review,
  no key rotation, status-publisher operation is a pilot-admission condition.

## 0.6.1 — consent-gate type fix (found by the Codex falsifier)

- Codex (GPT-6 over ChatGPT Plus) independently verified the 0.6.0 claims: the `actors` listing and
  `anchor_level` distinction were reproduced; the MCP consent guarantee was **falsified** — a JSON
  string `"false"` is truthy, so `repair` executed despite the check.
- Fix: consent gates now require boolean `true` (`is True`), not merely truthy; `poll_inbox`
  accepts `consume` only as boolean `true`.
- Tests: M11 (consent type bypass) and M12 (consume type) added; 74 across five suites.

## 0.6.0 — review-driven: trust-set visibility and anchor levels

Triggered by the first daily review (2026-10-20): two suggestions accepted, one accepted in reduced
form (read-only diagnostics only; destructive repair stays behind an explicit opt-in).

- `agentbridge actors [--json]`: list the trust set (actor, key fingerprint, registration seq/time).
  `verify` now reports the actor set (`report.actors`) and MCP exposes `list_actors`.
- `VerificationReport.anchor_level` (`local_only` / `anchored`) plus an `anchor` summary; CLI prints
  "anchored (kind=…, seq=…)" or "local_only — internally consistent, not externally anchored".
  `verify --expect-anchor` and `--expect-head` both raise the level when they match.
- MCP adds read-only `diagnose` and `propose_repair` (returns commands + preconditions, never
  executes). `repair` / `recover_empty` are only registered when the server starts with
  `--allow-destructive-tools`, and still require explicit consent arguments.
- `verify_anchor_receipt` moved into core so receipts and ledgers are checked by one implementation.
- Tests: 72 across five suites (regression 30, identity 11, MCP 10, transport 11, anchors 10).

## 0.5.0 — hosted anchors

- `anchor-service`: append-only, signed notary for `(bridge_id, seq, digest)`.
- `anchor-submit` / `anchor-verify` / `verify --expect-anchor`.
- Receipts embed `prev`, so the service log is a hash chain; equivocation (same seq, different
  digest) is refused with 409.
- Bridge identity derived from the genesis entry (`br-…`); `anchor` ledger entries are checked
  against real local history.
- 9 adversarial tests, including restart persistence and log-deletion detection.
- Docs: whitepaper gained an "AI security positioning" section (OWASP AISVS C9.4 / Agentic Top 10
  NHI mapping); added a 12-slide security go-to-market deck.

## 0.4.0 — network transport

- `serve`: single-writer HTTP sequencer. Holds no actor keys; validates and orders client-signed
  entries (`POST /api/entry`), never re-signs.
- `--remote URL` for the CLI and the MCP server.
- Request authentication: Ed25519 over `(method, path, body hash, timestamp, nonce)`, replay
  protection, 300 s window.
- Content-addressed blob upload endpoint; stale-head retry on races.
- 10 transport tests, including MCP over HTTP.

## 0.3.0 — identity

- Ed25519 signatures (RFC 8032) in pure Python, zero dependencies.
- Ledger entries and envelopes are signed; `actor_register` binds an actor to a public key;
  post-registration writes must verify.
- Pre-registration history is exempt so keys can be added to an existing bridge.
- `keygen`, `register`, global `--key`, MCP `register_actor` tool.
- 10 identity tests; 321 byte-for-byte comparisons against OpenSSL.

## 0.2.0 — MCP server

- `mcp`: stdio MCP server exposing 10 tools; optionally remote.
- Hand-rolled JSON-RPC transport; cross-checked against the official MCP Python SDK 2.3.0.
- `requests` command and `list_requests` tool (the original API only read the inbox).

## 0.1.0 — filesystem bridge

- Hash-chained ledger, content-addressed artifact store, head anchor, envelopes.
- `verify` re-checks envelopes, artifacts and anchors; fail-closed appends.
- Explicit recovery: `repair`, `init --recover-empty`, `init --rebind-marker`.
- 30 adversarial regression cases distilled from five rounds of independent review.
