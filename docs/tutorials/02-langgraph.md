# 2. LangGraph: wrap graph nodes with delivery and acceptance

Goal: a graph node that hands work to another agent records a delivery step and a later acceptance
step, so a dispute can be resolved without reading chat logs.

The adapter is framework-agnostic; the graph wiring below is a sketch — adapt node names and state
to your LangGraph version.

```python
from agentbridge import Bridge, signing

client_key = signing.load_keyfile("keys/client.key")
worker_key = signing.load_keyfile("keys/worker.key")
client = Bridge("shared", client_key)
worker = Bridge("shared", worker_key)


def request_node(state):
    sent = client.send(
        actor="client", to="worker", intent="review",
        body=state["task"], attach=state.get("inputs", []),
    )
    return {"request_id": sent["id"]}


def deliver_node(state):
    delivered = worker.deliver(
        actor="worker", to="client", in_reply_to=state["request_id"],
        body=state["result"], attach=state.get("outputs", []),
        version="v1",
    )
    return {"delivery_id": delivered["id"], "version": delivered["version"]}


def accept_node(state):
    client.accept_delivery(
        "client", state["delivery_id"], version=state["version"],
        decision="accepted", reason="",
    )
    return {"accepted": True}
```

Revision loop: on rejection, call `accept_delivery(..., decision="rejected", reason=...)`, then
`deliver(..., version="v2", revises=state["delivery_id"])`. The next acceptance must target v2; it
does not inherit v1.

## Why this shape

- The graph controls the workflow; agentbridge only stores evidence.
- If a graph checkpoint is lost, the delivery/acceptance record still exists in the ledger.
- Export at the end of the run: `agentbridge evidence export --delivery <v2 id> ...`.

Caveat: LangGraph persistence is not the same as delivery evidence. A checkpoint store can be
edited by whoever controls it; the external anchor is what makes the delivery record hard to rewrite.
