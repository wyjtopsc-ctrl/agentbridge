# Network transport

`agentbridge serve` turns a bridge directory into a small HTTP service so agents on different
machines can share one ledger. The server is a **sequencer**, not an authority: it holds no actor
keys and cannot forge authorship.

```console
# on the host that owns the directory
agentbridge --root ./shared serve --host 127.0.0.1 --port 8765
# {"listening": "http://127.0.0.1:8765", "root": "...", "pid": 1234}

# on a client
agentbridge --remote http://127.0.0.1:8765 --key ./keys/worker.key send --to planner --body "review this"
agentbridge --remote http://127.0.0.1:8765 --key ./keys/worker.key poll --actor worker
agentbridge --remote http://127.0.0.1:8765 --key ./keys/worker.key verify
```

The MCP server works in remote mode with no extra code path:

```console
agentbridge --remote http://127.0.0.1:8765 --key ./keys/worker.key mcp
```

## Why a single writer

A ledger's value is one unambiguous order. Multiple writers would turn ordering into a consensus
problem, which is a different (and much larger) product. The sequencer serialises appends with a
file lock; clients that lose a race get `stale_head` and rebuild their entry against the new head
(the CLI client retries automatically).

## Authentication

Every HTTP request — reads included — is signed by the actor's Ed25519 key:

```
X-AB-Actor: worker
X-AB-Timestamp: 1792500000
X-AB-Nonce: 3f9c…
X-AB-Signature: <ed25519 over "agentbridge-v1\nMETHOD\nPATH\nsha256(body)\nactor\nts\nnonce">
```

The server checks the signature against the actor registry in the ledger, rejects timestamps more
than 300 s off, and rejects replayed nonces (in-memory cache, twice the window). The bridge must
have at least one registered actor; an unregistered bridge refuses network access.

Writes are protected twice: the HTTP request is authenticated, **and** the ledger entry itself is
built and signed by the client (`POST /api/entry`). The server re-validates the chain position,
recomputes the digest, verifies the signature against the registry, checks the envelope hash, and
only then appends. It never re-signs, so a compromised server can reorder or withhold, but cannot
put words in an actor's mouth.

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/head` | current tip |
| GET | `/api/verify[?expect_head=SEQ:DIGEST]` | full verification |
| GET | `/api/anchor` | tip to hold off-filesystem |
| GET | `/api/status` | doctor |
| GET | `/api/ledger[?limit=N]` | recent entries |
| GET | `/api/envelope?id=` | one envelope |
| GET | `/api/actors` | the registered trust set (actor, fingerprint, seq) |
| GET | `/api/requests[?actor=]` | pending requests |
| GET | `/api/inbox?actor=` | deliveries, with a `verified` flag |
| POST | `/api/blob` | upload an artifact (`{name, b64}`), content-addressed |
| POST | `/api/entry` | submit a signed entry (and envelope, or `consume_id`) |

## Trust model shift

Local filesystem mode: the ledger lives where both agents can write it. Network mode: the ledger
lives on the server; clients trust it for **ordering and availability**, never for **authorship**.
Client signatures are checked by any verifier, not only by the server.

What the server can do:

- reorder or refuse writes (availability / ordering attack) — visible as a gap or a refusal;
- read all envelope bodies and artifacts — the protocol is plaintext;
- run a wrong clock — timestamps come from clients, but the chain order is the server's.

What it cannot do:

- forge an entry signed by an actor (no keys);
- forge an envelope accepted as `verified` (envelope hash and actor signature are in the entry);
- rewrite history silently if a human holds an external anchor.

## Not hardened yet

No TLS (put it behind a reverse proxy), no rate limiting, in-process nonce cache (single process),
no multi-server replication or failover, no offline queue. This is a local-first transport for
agents you already trust to talk to each other; it is not a public API.
