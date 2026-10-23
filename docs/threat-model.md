# Threat model

Stated plainly, because a provenance tool that over-claims is worse than no tool. This document is
deliberately pessimistic.

> **Current status (0.9.3, 2026-10-23).** This document began as the 0.1 local-filesystem model.
> The historical paragraphs below are kept for traceability; current capabilities include signed
> envelopes, an HTTP single-writer sequencer, Ed25519 identities, key rotation/revocation, evidence
> packs and external anchors. The “no network transport / rotation out of scope” wording describes
> 0.1, not 0.9.3. K3 emergency recovery is still not implemented.

## Deployment assumption

Two supported shapes:

1. **Local shared filesystem** — two agents (or two processes) run as the same OS user on the same
   machine. No network; the original 0.1 model.
2. **HTTP sequencer** — one single-writer service, signed requests, no TLS in the service itself;
   deploy behind a reverse proxy. Replay protection uses timestamp + nonce cache (see P0 note below).

Identity is optional for local use and required for network use: actor registry, Ed25519 signatures,
ledger-level key rotation/revocation. Certificate authorities / cross-org PKI are not implemented.

## What an attacker can do

Assume an adversary with the same filesystem privileges as the participants. They can read
everything, write anything, delete anything, and call any command. The only thing they cannot do is
change a digest that is held outside the filesystem.

| Attack | Detected? | How |
|---|---|---|
| Edit an artifact after delivery | **No effect.** Delivery is verified against the content-addressed copy | `wire/artifacts/<sha256>` is snapshotted at attach time; the live path only shows `drifted` |
| Delete or corrupt a stored artifact | Yes | store hashes are re-checked |
| Rewrite an envelope's body after delivery | Yes | envelope re-hashed by id and compared with `envelope_sha256` |
| Forge a delivery into the inbox and consume it | Yes | not in ledger → `UNVERIFIED`, consume refused (exit 2) |
| Delete a middle ledger entry | Yes | `seq` continuity + `prev` chain |
| Delete the last ledger entry | Yes | head anchor mismatch; further appends refuse (fail-closed) |
| Delete `wire/.initialised` | Yes | marker missing is an error; rebinding requires an explicit, recorded command |
| Delete `wire/head.json` | Yes | head missing is an error; appends refuse |
| Empty the ledger, leave traces | Yes | empty ledger + any head/envelopes is an error |
| Call `commit` before `init` | Yes | the append path requires `genesis` first; nothing is created |
| Point a symlink at a file outside the tree | Yes | symlinks are refused; `lstat`, never `follow` |
| Attach the ledger/wire files as artifacts | Yes | self-referential artifacts are refused |
| **Edit `ledger.jsonl` *and* `wire/head.json` together** | **No**, unless you hold an external anchor | This is the boundary. Two files, no privileged access needed. |
| **Rebuild everything** (ledger, head, marker, wire/) | **No**, unless you hold an external anchor | Indistinguishable from a fresh directory |
| Drag a file system back in time | No | no trusted clock |
| Sign as another actor (no keys configured) | No — trivially | `--actor` is a label, not a signature |
| Sign as another actor (keys registered) | No, unless the key file is readable | entries and envelopes are Ed25519-signed and checked against the registry |
| Rewrite a signed entry | Yes | digest changes, signature no longer verifies |
| Re-register an actor with a new key | Yes | reported as a conflict; ledger-level rotation/revocation exists in 0.9.3, K3 recovery does not |
| Compromise the OS user | No | game over by assumption |
| Rewrite ledger + head together | **Yes, if a receipt is held** | a service-signed receipt pins (seq, digest) off-machine |
| Anchor service issues a false receipt | Partly | receipts are service-signed and client-bound; collusion is possible but a held receipt cannot be altered |
| Anchor service withholds | No | availability only; already-issued receipts stay valid |
| Replay a captured HTTP request | Yes (network mode) | signed timestamp window + in-memory nonce cache; a restart window is a known P0 gap |
| Tamper with a request in flight | Yes (network mode) | request signature covers method, path, body hash |
| Compromised sequencer forges authorship | No | the server holds no keys; entries and envelopes are client-signed |
| Compromised sequencer reorders or withholds | No | it is the single writer; detect via gaps/anchor |
| Read traffic on the network | No | no TLS; put the sequencer behind a reverse proxy |

## What is deliberately not defended

- **Identity, by default.** Without keys, `from: hermes` proves only that the string was written by
  someone with write access. With keys, signatures prove *key possession* — not key custody. A key
  file stored in the shared directory is readable by every participant, so key files must live
  outside it. Certificate authorities / cross-org PKI and K3 emergency recovery are out of scope; ledger-level rotation and revocation are implemented.
- **Truth.** The ledger records what was said and what bytes were exchanged. It cannot verify that
  the content is correct, honest, or produced by the claimed process.
- **Adjudication.** Nothing here decides who is right. `commit` records a promise, not its
  fulfilment. A third party (human or institution) still has to read the record and judge.
- **Availability.** A same-user attacker can delete the whole directory, fill the disk, or hold the
  lock. There is no replication.
- **Confidentiality.** Everything is plaintext on disk, including envelope bodies and artifact
  copies. Encryption is not implemented.

## Residual risk that users must own

1. **Hold the anchor.** Run `agentbridge anchor` at meaningful checkpoints and store the
   `SEQ:DIGEST` outside this filesystem. Without it, only tail truncation is caught, not a
   coordinated rewrite. This is the single most important operational habit.
2. **Give each agent its own bridge directory.** Sharing one directory means both agents can write
   each other's envelopes. The semantics assume `outbox` is one side's and `inbox` the other's.
3. **Do not treat `verified` as "trusted source".** It means "this envelope is the one the ledger
   records". Any writer can produce a verified envelope by calling `deliver`.

## Design history

The prototype was reviewed by a second agent over five adversarial rounds. Every round found real
defects, including in the fixes for the previous round. The recurring lesson: fixes relocate the
attack surface rather than remove it — crypto (no envelope check) → state machine (tail truncation)
→ guard placement (a guard hanging on a deletable file) → semantics (`verified` meaning the wrong
thing) → **the recovery path itself** (`init` was the only repair entry point and the only command
that did not verify). The current design assumes the next defect will also be in a recovery or
repair path, and is structured so that recovery is explicit and recorded.
