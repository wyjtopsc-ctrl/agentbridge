# X / Twitter thread

1/ Multi-agent demos show agents talking. They rarely show what happens when two agents disagree
about what was delivered.

2/ I built agentbridge: a hash-chained delivery ledger with signed acceptance, revisions, key
timeline, and an offline-verifiable evidence pack.

3/ The point is not “trust our log”. The receiver exports a pack and verifies it without trusting
the sender — or buying anything.

4/ It also states what it cannot prove: file contents are not reviewed in hashes_only mode; business
quality is not judged; unanchored tail rollback is undetectable offline.

5/ Pre-1.0, MIT, local CI evidence only. Looking for feedback from people building agent platforms,
MCP tools, or cross-org AI delivery.

Repo: https://github.com/wyjtopsc-ctrl/agentbridge
Demo: `PYTHONPATH=src python3 demo/run_demo.py`
