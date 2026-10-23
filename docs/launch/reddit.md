# Reddit (r/LocalLLaMA, r/AI_Agents)

**Title:** I built offline-verifiable delivery receipts for multi-agent workflows — what would you use it for?

**Body:**

Most multi-agent demos stop at “the agents talked”. The harder question is what happens when two
agents (or two organizations) disagree about what was delivered.

agentbridge records a delivery as ledger entries: sender, receiver, logical delivery id, version,
artifact hashes, rejection reason, acceptance, revisions. Each record is signed; the ledger is
hash-chained; an optional external anchor catches rewrites of the whole local history. A receiver
can export an evidence pack and verify it offline with an open verifier.

It is deliberately narrow: no quality judgment, no dispute resolution, no magic. `hashes_only` mode
does not review file contents, and the report says so explicitly.

Repo + 2-minute demo: https://github.com/wyjtopsc-ctrl/agentbridge
Demo video: https://github.com/wyjtopsc-ctrl/agentbridge/blob/main/demo/agentbridge-demo-zh.mp4
Run: `PYTHONPATH=src python3 demo/run_demo.py`

Where do you see this being useful — agent marketplaces, agency → client deliveries, internal
multi-agent pipelines, or somewhere else? Honest criticism welcome.
