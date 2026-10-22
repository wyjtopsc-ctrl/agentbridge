# Show HN

**Title:** Show HN: Offline-verifiable delivery receipts for AI agents

**Body:**

When two AI agents hand work to each other, the record usually lives in logs or chat. If the
delivery is disputed, neither side can prove which version was delivered, who accepted it, or
whether the record was edited afterwards. Platforms are often a party to the transaction.

agentbridge is a small Python library + CLI that records “promise → delivery → acceptance” in a
hash-chained ledger, signs each step with Ed25519 keys, and exports an evidence pack that a receiver
can verify offline, without trusting the sender or buying anything.

It does not adjudicate quality or blame. It shows what it can prove and what it cannot.

Try it:

```console
$ git clone https://github.com/wyjtopsc-ctrl/agentbridge
$ cd agentbridge && PYTHONPATH=src python3 demo/run_demo.py
```

Current limits: pre-1.0; `hashes_only` does not review file contents; K3 emergency recovery is not
implemented; unanchored tail rollback is undetectable by design; local CI evidence only.

Repo: https://github.com/wyjtopsc-ctrl/agentbridge
Release: https://github.com/wyjtopsc-ctrl/agentbridge/releases/tag/v0.9.3

I would value feedback on the threat model and on which workflow you would actually use this for.
