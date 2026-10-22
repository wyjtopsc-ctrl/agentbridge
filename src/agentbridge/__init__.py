"""agentbridge — verifiable delivery between autonomous agents.

    from agentbridge import Bridge

    a = Bridge("./shared")
    a.init(actor="planner")
    req = a.send(actor="planner", to="worker", intent="review",
                 body="review this", attach=["build.py"])

    # ... the other agent reads the envelope and calls:
    # b = Bridge("./shared"); b.deliver(actor="worker", to="planner",
    #     in_reply_to=req["id"], body="two findings", attach=["findings.md"])
"""
from . import signing
from .core import (
    Bridge,
    BridgeError,
    NotInitialised,
    BrokenLedger,
    CorruptLedger,
    Refused,
    NotFound,
    BadArtifact,
    VerificationReport,
    PollResult,
    sha_file,
    new_id,
)

__version__ = "0.9.3"
__all__ = [
    "Bridge", "BridgeError", "NotInitialised", "BrokenLedger", "CorruptLedger",
    "Refused", "NotFound", "BadArtifact", "VerificationReport", "PollResult",
    "sha_file", "new_id", "signing", "__version__",
]
