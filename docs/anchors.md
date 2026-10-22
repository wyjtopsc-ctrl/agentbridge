# Hosted anchors

Every defence inside the bridge is rewritable by the same OS user. The only remaining defence is
a value held **outside** the machine. A hosted anchor service turns that value into a portable,
signed receipt.

```console
# once: the service's own key
agentbridge keygen --actor anchor-service --out ./keys

# the notary (self-hosted or operated by someone else)
agentbridge --key ./keys/anchor-service.key anchor-service --dir ./anchor-state --port 8790

# the client: submit the current tip, get a receipt
agentbridge --root ./shared --key ./keys/planner.key anchor-submit --url http://127.0.0.1:8790
# {"receipt": "./shared/wire/anchors/anchor-12-abc123….json", "log_index": 0, ...}

# later, prove it
agentbridge --root ./shared anchor-verify --receipt ./shared/wire/anchors/anchor-12-abc123….json
agentbridge --root ./shared verify --expect-anchor ./shared/wire/anchors/anchor-12-abc123….json
```

A receipt is small enough to paste into a ticket, an email, or a chat log:

```json
{
  "v": 1,
  "bridge_id": "br-3f9c…",
  "seq": 12,
  "digest": "460b57c7…",
  "log_index": 0,
  "received_at": "2026-10-20T17:05:00+08:00",
  "client_pub": "0ec9…",
  "service_pub": "074a…",
  "prev": "",
  "service_sig": "9d21…"
}
```

## Trust model

- **The service never sees content**, only `(bridge_id, seq, digest)`.
- **Submissions are client-signed** (same Ed25519 request signing as the sequencer, timestamp +
  nonce replay protection). The service binds a `bridge_id` to the first public key it sees —
  trust on first use — and rejects later keys for the same bridge.
- **Receipts are service-signed** over every field except the signature, including `prev`.
- **The service log is an append-only chain**: each receipt signs the previous receipt's
  signature. Deleting or reordering entries breaks the chain (`verify_log`).
- **Equivocation is refused**: the same `(bridge_id, seq)` with a different digest is rejected
  with `409`. The notary is also a fork detector.
- **Restart-safe**: receipts are fsynced to `log.jsonl`; `head.json` is republished on restart.

What the service can still do: refuse to anchor (availability), or collude with a client to issue
a receipt for a head that never existed. It cannot modify a receipt you already hold, and it cannot
impersonate your bridge key.

## Self-hosting vs hosted

The service is ~300 lines and MIT-licensed, so anyone can self-host it. The hosted version is the
part that cannot be replaced by code: it lives on a machine you don't control, which is exactly
what the anchor is for. That is the natural paid layer.

## Limits

- No TLS; run it behind a reverse proxy if it leaves localhost.
- Service key custody is the service operator's problem. Rotating it would invalidate verification
  of old receipts unless the old public keys are retained (they are embedded in receipts, so
  verification of history still works; rotation needs a policy).
- No transparency-log gossip: a dishonest service could show different logs to different people.
  The receipt you hold still protects you, but not third parties.
