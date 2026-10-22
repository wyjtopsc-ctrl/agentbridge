# 3. CrewAI: record task output and acceptance from callbacks

Goal: when a CrewAI task finishes, record the delivered artifact and let the receiving side accept it.
The callback shape depends on your CrewAI version; the agentbridge calls are the stable part.

```python
import json
from agentbridge import Bridge, signing

client = Bridge("shared", signing.load_keyfile("keys/client.key"))
worker = Bridge("shared", signing.load_keyfile("keys/worker.key"))


def on_task_end(task_output):
    """CrewAI task callback: record the output as a delivery."""
    path = "out/result.md"
    open(path, "w").write(task_output.raw)
    delivered = worker.deliver(
        actor="worker", to="client",
        in_reply_to=task_output.request_id,   # id from the request step
        body=task_output.raw, attach=[path],
        version="v1",
    )
    state["delivery_id"] = delivered["id"]


def accept_delivery(delivery_id, decision="accepted", reason=""):
    client.accept_delivery("client", delivery_id, decision=decision, reason=reason)
```

For a multi-agent crew, give each agent its own key and register it; do not reuse the same key for
planner and worker. If a task is revised, call `deliver(..., version="v2", revises=previous_id)`
and require a fresh acceptance.

## Export

```console
$ agentbridge evidence export --delivery <v2 id> --out ./pack --status ./status.json
$ agentbridge evidence verify --pack ./pack --trust ./trust.json
```

The receiving side does not need CrewAI installed; a verifier and an evidence pack are enough.
