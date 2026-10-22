# Protocol

Wire format for `agentbridge` 0.1. Everything lives under one directory:

```
<root>/
├── ledger.jsonl          # append-only, hash-chained
└── wire/
    ├── outbox/           # requests:  from -> to
    ├── inbox/            # deliveries: from -> to
    ├── archive/          # consumed envelopes
    ├── artifacts/        # content-addressed copies, filename = sha256
    ├── head.json         # {"seq", "digest", "updated_at"} — the anchor
    └── .initialised      # {"genesis_digest", "initialised_at"}
```

## Envelope

One JSON file per message, named `<id>.json`.

```json
{
  "v": 2,
  "id": "20261020T161249-planner-c20c437089d9b23e",
  "from": "planner",
  "to": "worker",
  "intent": "review",
  "in_reply_to": null,
  "created_at": "2026-10-20T16:12:49+08:00",
  "signature": {"alg": "ed25519", "pub": "…", "sig": "…"},
  "body": "review this module",
  "artifacts": [{
    "role": "target",
    "path": "/abs/path/build.py",
    "rel": "build.py",
    "sha256": "9544884c…",
    "bytes": 14151,
    "stored_as": "wire/artifacts/9544884c…",
    "recorded_at": "2026-10-20T16:12:49+08:00"
  }],
  "reply_box": "wire/inbox"
}
```

`id` is `timestamp-actor-16 hex chars` (64 random bits), so collisions are not a practical concern.
Envelopes are created with `O_EXCL` and are never overwritten.

`in_reply_to`, when present, must refer to a recorded `send` or `deliver` ledger entry; dangling
references are rejected before anything is written.

## Ledger entry

One JSON object per line, canonicalised as `json.dumps(sort_keys=True, separators=(",", ":"),
ensure_ascii=False)` before hashing.

```json
{
  "seq": 3,
  "ts": "2026-10-20T16:12:50+08:00",
  "type": "deliver",
  "id": "20261020T161250-worker-…",
  "actor": "worker",
  "from": "worker",
  "to": "planner",
  "in_reply_to": "20261020T161249-planner-…",
  "envelope_sha256": "…",
  "artifacts": [ … ],
  "prev": "<previous entry digest>",
  "digest": "<sha256 of this entry minus digest/sig/sig_pub>",
  "sig_pub": "<actor public key, hex>",
  "sig": "<ed25519 signature over the hex digest string>"
}
```

`type` is one of `genesis`, `send`, `deliver`, `consume`, `commit`, `repair`, `marker_rebind`,
`actor_register`, `anchor`.

An `anchor` entry records a hosted-anchor receipt locally: `{bridge_id, anchor_seq, anchor_digest,
log_index, service_url, receipt_sha256}`. `verify` checks that `anchor_seq`/`anchor_digest` match a
real local ledger entry, so an anchor cannot be pointed at a head that never existed. The receipt
itself (service-signed) lives under `wire/anchors/` and is checked by `verify --expect-anchor`.

`actor_register` carries `{"actor": name, "pub": "<hex>"}` as signed data. The first registration
for an actor wins; a later entry with a different key is reported as a conflict. Entries with a
`seq` lower than the first registration are exempt from the signature requirement, so keys can be
added to an existing bridge.

Invariants enforced on **append**:

1. The first entry must be `genesis` — enforced in the append path, not per command, because every
   command writes through it. (`commit` once bypassed this and could start a chain with itself.)
2. If the ledger is non-empty, `head.json` must exist and match the ledger tip, otherwise the
   append is refused. This is what stops a deleted tail entry from being silently "healed" by the
   next ordinary write; recovery requires the explicit `repair --accept-head-loss`.
3. A corrupt ledger (unparseable line) refuses further appends.

`head.json` is rewritten inside the append lock, immediately after the ledger line is fsynced.

## Verification

`verify` does, in order:

1. **Chain** — `seq == index`, `prev` links to the previous digest, `digest` recomputes.
2. **Origin** — first entry is `genesis`; `.initialised` exists and its `genesis_digest` matches
   the genesis entry. A missing marker is an error, not a reason to start fresh — otherwise
   deleting one file would silently re-bind the ledger to a rewritten history.
3. **Head** — `head.json` matches the tip. A missing head is an error. An empty ledger with any
   trace of history present (head or envelopes) is an error.
4. **Signatures** — if the ledger contains any `actor_register` entry, every post-registration
   entry must be signed by a registered actor, its `sig_pub` must match the registry, and its
   signature must verify over the digest. Envelopes must carry a signature by their `from` actor.
   Pre-registration history is exempt. Bridges without a registry skip this step entirely.
5. **Envelopes** — for every `send`/`deliver`/`consume` entry, locate the envelope *by id* across
   outbox/inbox/archive, hash it, compare with `envelope_sha256`. This is what catches a rewritten
   conclusion; without it the ledger vouched for attachments but not for what was actually said.
6. **Artifacts** — hash the copy in `wire/artifacts/`, not the original path. If the original path
   still exists and now differs, report `drifted` as information; the delivery is still intact.
7. **External anchor** — if `--expect-head SEQ:DIGEST` or `--expect-anchor RECEIPT` is given,
   compare with the tip (or the receipt's seq/digest). A successful external check raises
   `anchor_level` to `anchored` and records which anchor matched; otherwise it stays `local_only`.
   The report also carries `actors`, the trust set used for signature verification.

Failure is `exit 1` and a list of concrete problems. There is no "warning" state for integrity.

## Remote appends

`POST /api/entry` accepts an entry that the client built and signed (see `docs/transport.md`).
The server validates `seq`/`prev` against its current tip, recomputes the digest, checks the
signature against the actor registry, verifies `envelope_sha256`, then appends verbatim. It never
re-signs. Losing a race returns `stale_head`; clients rebuild against the new head.

## Poll and consume

`poll` lists envelopes addressed to `--actor`. An envelope is `verified` only if a `send`/`deliver`
ledger entry exists for its id **and** its current bytes hash to the recorded `envelope_sha256`.

`poll --consume` archives verified envelopes (move first, then append the `consume` entry) and
**refuses** unverified ones: they stay in the inbox and the command exits `2`. Before this was
enforced, a forged delivery could be consumed and thereby laundered into the ledger.

## Recovery

| Situation | Command | What is recorded |
|---|---|---|
| Failed head write (crash, disk full) | `repair --accept-head-loss` | `repair` entry with the abandoned `prior_head` |
| Empty ledger left by a failed first write | `init --recover-empty` | `genesis` with a `(recovered …)` note |
| `.initialised` deleted | `init --rebind-marker` | `marker_rebind` entry, then a new marker |
| Ledger intact, head anchor stale | `repair` | same as row 1 |

All recovery is explicit. `init` never silently writes over a state it does not understand: if the
ledger is broken it fails instead of reporting `bridge ready`.

## Anchors and what they are for

`head.json` protects against tail truncation, but it lives next to the ledger and is therefore
rewritable by the same user. `anchor` prints the current tip; copy it somewhere else. Then:

```console
agentbridge verify --expect-head 20:<digest>
```

A coordinated rewrite of both `ledger.jsonl` and `wire/head.json` is invisible without a value held
outside this filesystem. That is the boundary of the design, not a bug in it.
