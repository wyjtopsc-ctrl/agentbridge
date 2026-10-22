"""agentbridge core — verifiable delivery between autonomous agents over a filesystem.

Two agents (or two processes acting for agents) exchange *envelopes* through a shared
directory. Every send, delivery and consumption is appended to a hash-chained ledger;
every attached artifact is copied into a content-addressed store. A head anchor makes
tail truncation detectable. An external anchor (a digest held outside this filesystem)
makes a coordinated rewrite detectable.

The design is deliberately boring: no network, no keys, no consensus. The threat model
is stated rather than implied — see docs/threat-model.md.

This module is the library. `agentbridge.cli` is a thin wrapper.
"""
from __future__ import annotations

import datetime
import fcntl
import hashlib
import json
import os
import secrets
import shutil
import stat as statmod
import time

from . import signing

GENESIS = "GENESIS"
RESERVED = {"seq", "ts", "prev", "digest", "sig", "sig_pub"}
DIGEST_EXCLUDED = {"digest", "sig", "sig_pub", "new_sig"}
ENVELOPE_VERSION = 2


# ── errors ───────────────────────────────────────────────────────────────────

class BridgeError(Exception):
    """Base class. `code` is a stable machine-readable tag, safe to branch on."""

    code = "bridge_error"

    def __init__(self, message: str, code: str | None = None):
        super().__init__(message)
        if code:
            self.code = code


class NotInitialised(BridgeError):
    code = "not_initialised"


class BrokenLedger(BridgeError):
    code = "broken_ledger"


class CorruptLedger(BridgeError):
    code = "corrupt_ledger"


class Refused(BridgeError):
    code = "refused"


class NotFound(BridgeError):
    code = "not_found"


class BadArtifact(BridgeError):
    code = "bad_artifact"


# ── primitives ───────────────────────────────────────────────────────────────

def now() -> str:
    return datetime.datetime.now().astimezone().isoformat(timespec="seconds")


def canon(obj) -> bytes:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def sha_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def bridge_id_of(entries: list) -> str:
    """Stable identity for a bridge: a digest of its genesis entry."""
    if not entries:
        raise NotInitialised("no ledger — bridge identity is derived from the genesis entry")
    return "br-" + hashlib.sha256(str(entries[0].get("digest", "")).encode()).hexdigest()[:16]


def new_id(actor: str) -> str:
    return f"{time.strftime('%Y%m%dT%H%M%S')}-{actor}-{secrets.token_hex(8)}"


def _fsync_dir(path: str) -> None:
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


# ── reports ──────────────────────────────────────────────────────────────────

def receipt_body(receipt: dict) -> dict:
    return {k: v for k, v in receipt.items() if k != "service_sig"}


def verify_anchor_receipt(receipt: dict, expect_seq=None, expect_digest=None) -> list[str]:
    """Check a hosted-anchor receipt. Empty list means valid."""
    problems = []
    if not isinstance(receipt, dict):
        return ["receipt is not an object"]
    for field in ("v", "bridge_id", "seq", "digest", "log_index", "received_at",
                  "client_pub", "service_pub", "prev", "service_sig"):
        if field not in receipt:
            problems.append(f"receipt is missing {field!r}")
    if problems:
        return problems
    if not signing.verify_hex(receipt["service_pub"], canon(receipt_body(receipt)),
                              receipt["service_sig"]):
        problems.append("service signature does not verify")
    if expect_seq is not None and receipt.get("seq") != expect_seq:
        problems.append(f"receipt anchors seq {receipt.get('seq')}, expected {expect_seq}")
    if expect_digest is not None and receipt.get("digest") != expect_digest:
        problems.append("receipt digest does not match the expected digest")
    if len(str(receipt.get("digest", ""))) != 64:
        problems.append("receipt digest is not a sha256 hex string")
    return problems


class VerificationReport:
    def __init__(self):
        self.chain_ok = True
        self.ledger_len = 0
        self.envelopes_checked = 0
        self.envelopes_failed = 0
        self.artifacts_ok = 0
        self.artifacts_failed = 0
        self.originals_drifted = 0
        self.problems: list[str] = []
        self.actors: list[str] = []
        self.anchor_level = "local_only"
        self.anchor = None
        self.key_status: list[dict] = []

    @property
    def ok(self) -> bool:
        return not self.problems

    def to_dict(self) -> dict:
        return {
            "ok": self.ok,
            "chain_ok": self.chain_ok,
            "ledger_len": self.ledger_len,
            "envelopes_checked": self.envelopes_checked,
            "envelopes_failed": self.envelopes_failed,
            "artifacts_ok": self.artifacts_ok,
            "artifacts_failed": self.artifacts_failed,
            "originals_drifted": self.originals_drifted,
            "problems": self.problems,
            "actors": self.actors,
            "anchor_level": self.anchor_level,
            "anchor": self.anchor,
        }


class PollResult:
    def __init__(self, envelopes, refused, consumed):
        self.envelopes = envelopes      # list[dict], each carries "_verified"
        self.refused = refused          # list[dict] of unverified envelopes (consume refused)
        self.consumed = consumed        # list[str] of envelope ids moved to the archive


# ── bridge ───────────────────────────────────────────────────────────────────

class Bridge:
    """A directory that two agents share. Construct with the directory path."""

    def __init__(self, root, signer: "signing.Signer | None" = None):
        self.signer = signer
        self.root = os.path.abspath(os.path.expanduser(str(root)))
        self.wire = os.path.join(self.root, "wire")
        self.outbox = os.path.join(self.wire, "outbox")
        self.inbox = os.path.join(self.wire, "inbox")
        self.archive = os.path.join(self.wire, "archive")
        self.store = os.path.join(self.wire, "artifacts")
        self.head_path = os.path.join(self.wire, "head.json")
        self.marker = os.path.join(self.wire, ".initialised")
        self.ledger = os.path.join(self.root, "ledger.jsonl")

    # -- layout ------------------------------------------------------------

    def _ensure_dirs(self) -> None:
        for d in (self.wire, self.outbox, self.inbox, self.archive, self.store):
            os.makedirs(d, exist_ok=True)

    def _atomic_write(self, path: str, text: str) -> None:
        tmp = f"{path}.tmp.{os.getpid()}"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        _fsync_dir(os.path.dirname(path))

    def _write_new(self, path: str, text: str) -> None:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(text)
                f.flush()
                os.fsync(f.fileno())
        except Exception:
            try:
                os.unlink(path)
            except OSError:
                pass
            raise
        _fsync_dir(os.path.dirname(path))

    # -- artifacts ---------------------------------------------------------

    def _is_bridge_file(self, ap: str) -> bool:
        real = os.path.realpath(ap)
        if real in (os.path.realpath(self.ledger), os.path.realpath(self.head_path)):
            return True
        for box in (self.outbox, self.inbox, self.archive):
            try:
                if os.path.commonpath([real, os.path.realpath(box)]) == os.path.realpath(box):
                    return True
            except ValueError:
                pass
        return False

    def artifact(self, path: str, role: str = "file") -> dict:
        """Hash the file once, copy those exact bytes into the store, record both."""
        ap = os.path.abspath(os.path.expanduser(path))
        try:
            st = os.lstat(ap)
        except OSError:
            raise BadArtifact(f"not a file: {path}")
        if statmod.S_ISLNK(st.st_mode):
            raise BadArtifact(f"refusing symlink: {path}")
        if not statmod.S_ISREG(st.st_mode):
            raise BadArtifact(f"not a regular file: {path}")
        if self._is_bridge_file(ap):
            raise BadArtifact(f"refusing self-referential artifact: {path}")

        h = hashlib.sha256()
        with open(ap, "rb") as f:
            fd_stat = os.fstat(f.fileno())          # size from the same descriptor we hash
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
            digest, size = h.hexdigest(), fd_stat.st_size

            os.makedirs(self.store, exist_ok=True)
            dest = os.path.join(self.store, digest)
            if not os.path.exists(dest):
                tmp = f"{dest}.tmp.{os.getpid()}"
                f.seek(0)
                with open(tmp, "wb") as out:
                    shutil.copyfileobj(f, out, 1 << 20)
                    out.flush()
                    os.fsync(out.fileno())
                if sha_file(tmp) != digest:
                    os.unlink(tmp)
                    raise BadArtifact(f"artifact changed while being stored: {path}")
                os.replace(tmp, dest)
                _fsync_dir(self.store)
            elif sha_file(dest) != digest:
                raise BadArtifact(f"content store corrupt for {digest}")

        try:
            rel = os.path.relpath(ap, self.root)
        except ValueError:
            rel = None
        return {"role": role, "path": ap, "rel": rel, "sha256": digest, "bytes": size,
                "stored_as": os.path.relpath(dest, self.root), "recorded_at": now()}

    # -- ledger ------------------------------------------------------------

    def _parse(self, text: str):
        entries, bad = [], []
        for i, line in enumerate(text.splitlines(), 1):
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError as exc:
                bad.append(f"line {i}: unparseable ({exc.msg})")
        return entries, bad

    def snapshot(self):
        """Consistent read of the ledger under a shared lock."""
        if not os.path.exists(self.ledger):
            return [], []
        with open(self.ledger, "r", encoding="utf-8") as f:
            fcntl.flock(f, fcntl.LOCK_SH)
            try:
                text = f.read()
            finally:
                fcntl.flock(f, fcntl.LOCK_UN)
        return self._parse(text)

    def entries(self):
        return self.snapshot()[0]

    def _read_head(self):
        if not os.path.exists(self.head_path):
            return None
        try:
            return json.load(open(self.head_path, encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None

    def _debris_present(self) -> bool:
        """Evidence that a ledger existed. Deliberately not the deletable marker."""
        if os.path.exists(self.head_path):
            return True
        for d in (self.outbox, self.inbox, self.archive):
            if os.path.isdir(d) and any(not n.startswith(".") for n in os.listdir(d)):
                return True
        return False

    def _write_marker(self, entries) -> None:
        self._atomic_write(self.marker, json.dumps(
            {"genesis_digest": entries[0]["digest"] if entries else "", "initialised_at": now()},
            ensure_ascii=False) + "\n")

    def actors(self) -> list[dict]:
        """The trust set, as data: who is registered, with which key, when."""
        entries, bad = self.snapshot()
        if bad:
            raise CorruptLedger(f"ledger has unparseable lines ({bad[0]})")
        registry, problems, _ = self._actor_registry(entries)
        first = {}
        for e in entries:
            if e.get("type") == "actor_register" and e.get("actor") not in first:
                first[e.get("actor")] = e
        out = []
        for actor, pub in registry.items():
            entry = first.get(actor, {})
            out.append({"actor": actor, "pub": pub,
                        "fingerprint": signing.fingerprint(pub),
                        "registered_seq": entry.get("seq"),
                        "registered_at": entry.get("ts")})
        out.sort(key=lambda a: (a["registered_seq"] if a["registered_seq"] is not None else 1 << 30,
                                a["actor"]))
        return out

    def bridge_id(self) -> str:
        entries, bad = self.snapshot()
        if bad:
            raise CorruptLedger(f"ledger has unparseable lines ({bad[0]})")
        return bridge_id_of(entries)

    def head(self) -> dict:
        """Current ledger tip, or an error when there is no ledger yet."""
        entries, bad = self.snapshot()
        if bad:
            raise CorruptLedger(f"ledger has unparseable lines ({bad[0]})")
        if not entries:
            raise NotInitialised("ledger is empty")
        tip = entries[-1]
        return {"seq": tip["seq"], "digest": tip["digest"]}

    def build_entry(self, fields: dict) -> dict:
        """Build the next entry, digest it and sign it — without writing it.

        A remote client uses this to construct an entry it will hand to a sequencer that
        does not hold its key. `append_entry` re-validates everything server-side.
        """
        clash = RESERVED & set(fields)
        if clash:
            raise Refused(f"reserved ledger fields passed by caller: {sorted(clash)}")
        entries, bad = self.snapshot()
        if bad:
            raise CorruptLedger(f"refusing to build on a corrupt ledger ({bad[0]})")
        prev = entries[-1]["digest"] if entries else GENESIS
        entry = {**fields, "seq": len(entries), "ts": now(), "prev": prev}
        entry["digest"] = sha_bytes(canon(entry))
        if self.signer:
            entry["sig_pub"] = self.signer.pub_hex
            entry["sig"] = self.signer.sign_hex(entry["digest"].encode())
        return entry

    def append_entry(self, entry: dict, bypass_head: bool = False) -> dict:
        """Validate an externally built entry and append it verbatim.

        This is the sequencer's entry point: it never re-signs, so a server cannot forge
        authorship. It checks the chain position, the digest, and the signature.
        """
        if not isinstance(entry, dict):
            raise Refused("entry must be an object")
        body = {k: v for k, v in entry.items() if k not in DIGEST_EXCLUDED}
        if sha_bytes(canon(body)) != entry.get("digest"):
            raise Refused("entry digest does not match its content")
        entries, bad = self.snapshot()
        if bad:
            raise CorruptLedger(f"refusing to append to a corrupt ledger ({bad[0]})")
        expected_prev = entries[-1]["digest"] if entries else GENESIS
        if entry.get("prev") != expected_prev or entry.get("seq") != len(entries):
            raise BrokenLedger(
                f"entry does not extend the ledger (expected seq={len(entries)} "
                f"prev={str(expected_prev)[:12]}…, got seq={entry.get('seq')} "
                f"prev={str(entry.get('prev'))[:12]}…) — someone else wrote first")
        sig, pub = entry.get("sig"), entry.get("sig_pub")
        registry, current, history, revocations, _problems, _first = self._key_timeline(entries)
        actor = entry.get("actor") or entry.get("from")
        typ = entry.get("type")
        if typ == "rotate":
            if any(r.get("actor") == actor for r in revocations):
                raise Refused(f"{actor!r} was revoked; a revoked key cannot authorize a rotation")
            if not sig or not pub:
                raise Refused("a rotate entry must be signed by the old key")
            if current.get(actor) != pub or entry.get("old_pub") != pub:
                raise Refused("rotate entry is not signed by the actor's active key")
            if not signing.verify_hex(pub, str(entry["digest"]).encode(), sig):
                raise Refused("rotate entry signature does not verify")
            new_pub = entry.get("new_pub")
            if not new_pub or new_pub == pub:
                raise Refused("rotate entry needs a different new_pub")
            if not signing.verify_hex(new_pub, str(entry["digest"]).encode(),
                                      entry.get("new_sig", "")):
                raise Refused("rotate entry is missing the new key's proof (new_sig)")
        elif sig and pub:
            if not signing.verify_hex(pub, str(entry["digest"]).encode(), sig):
                raise Refused("entry signature does not verify")
            expected = current.get(actor)
            if registry and expected and expected != pub:
                raise Refused(f"signing key does not match the active key for {actor!r}")
            if any(r.get("actor") == actor for r in revocations):
                raise Refused(f"{actor!r} has a revocation entry; this key can no longer write")
        elif not registry:
            pass                                  # unsigned bridge: allowed
        else:
            raise Refused("a registered bridge requires signed entries")
        return self._write_entry(entry, bypass_head=bypass_head)

    def _write_entry(self, entry: dict, bypass_head: bool = False) -> dict:
        if not bypass_head and not os.path.exists(self.ledger):
            if entry.get("type") != "genesis":
                raise NotInitialised(f"no ledger — run `init` first (refusing to start a chain with "
                                     f"{entry.get('type')})")
            if self._debris_present():
                raise Refused("no ledger but history exists (head/envelopes) — refusing to append")
        os.makedirs(self.root, exist_ok=True)
        with open(self.ledger, "a+", encoding="utf-8") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            try:
                f.seek(0)
                entries, bad = self._parse(f.read())
                if bad:
                    raise CorruptLedger(f"refusing to append to a corrupt ledger ({bad[0]})")
                expected_prev = entries[-1]["digest"] if entries else GENESIS
                if entry.get("seq") != len(entries) or entry.get("prev") != expected_prev:
                    raise BrokenLedger("entry does not extend the ledger — someone else wrote first")
                if not bypass_head:
                    if not entries:
                        if entry.get("type") != "genesis":
                            raise CorruptLedger(f"empty ledger — the first entry must be genesis, "
                                                f"not {entry.get('type')}")
                    else:
                        head = self._read_head()
                        if head is None:
                            raise BrokenLedger("head anchor missing — refusing to append "
                                               "(evidence may have been truncated)")
                        tip = entries[-1]
                        if head.get("seq") != tip.get("seq") or head.get("digest") != tip.get("digest"):
                            raise BrokenLedger(
                                "ledger tip does not match the head anchor — refusing to append "
                                "(a tail entry may have been deleted; use `repair --accept-head-loss` "
                                "only if you have decided to abandon whatever the anchor pointed at)")
                f.write(json.dumps(entry, ensure_ascii=False, sort_keys=True) + "\n")
                f.flush()
                os.fsync(f.fileno())
                self._atomic_write(self.head_path, json.dumps(
                    {"seq": entry["seq"], "digest": entry["digest"], "updated_at": entry["ts"]},
                    ensure_ascii=False) + "\n")
            finally:
                fcntl.flock(f, fcntl.LOCK_UN)
        return entry

    def _append(self, fields: dict, bypass_head: bool = False) -> dict:
        self._assert_signer_active()
        return self._write_entry(self.build_entry(fields), bypass_head=bypass_head)

    def _assert_signer_active(self) -> None:
        if not self.signer:
            return
        entries, _ = self.snapshot()
        _registry, current, _history, revocations, _problems, _first = self._key_timeline(entries)
        actor = self.signer.actor
        if current.get(actor) and current[actor] != self.signer.pub_hex:
            raise Refused(f"the signing key for {actor!r} was rotated away; use the current key")
        for rev in revocations:
            if rev.get("actor") == actor:
                raise Refused(f"{actor!r} has a revocation entry (seq {rev.get('seq')}); "
                              f"this key can no longer write")

    def _key_timeline(self, entries):
        """Replay registrations, rotations and revocations.

        Returns (registry, current, history, revocations, problems, first_seq) where history maps
        actor -> [(seq, pub)] start points and current is the key at the ledger tip.
        """
        registry, current, history = {}, {}, {}
        revocations, problems, first_seq = [], [], None
        for e in entries:
            typ, actor = e.get("type"), e.get("actor")
            seq = e.get("seq", 0)
            if typ == "actor_register":
                if first_seq is None:
                    first_seq = seq
                pub = e.get("pub")
                if not actor or not pub:
                    problems.append(f"seq {seq}: malformed actor_register entry")
                elif actor not in registry:
                    registry[actor] = pub
                    current[actor] = pub
                    history[actor] = [(seq, pub)]
                elif registry[actor] != pub:
                    problems.append(f"seq {seq}: actor {actor!r} re-registered with a different key "
                                    f"(use a rotate entry)")
            elif typ == "rotate":
                old, new = e.get("old_pub"), e.get("new_pub")
                if actor not in current:
                    problems.append(f"seq {seq}: rotation for unregistered actor {actor!r}")
                elif current[actor] != old:
                    problems.append(f"seq {seq}: rotation old key does not match the active key for {actor!r}")
                elif not new:
                    problems.append(f"seq {seq}: rotation has no new_pub")
                elif not signing.verify_hex(new, str(e.get("digest", "")).encode(), e.get("new_sig", "")):
                    problems.append(f"seq {seq}: rotation new key did not sign the entry (new_sig)")
                else:
                    current[actor] = new
                    history.setdefault(actor, []).append((seq, new))
            elif typ == "revoke":
                revocations.append(e)
        return registry, current, history, revocations, problems, first_seq

    @staticmethod
    def _key_at(history, actor, seq):
        found = None
        for start, pub in history.get(actor, []):
            if start < seq:
                found = pub
            else:
                break
        return found

    def _verify_chain(self):
        entries, bad = self.snapshot()
        report = VerificationReport()
        report.ledger_len = len(entries)
        report.problems.extend(f"corrupt: {b}" for b in bad)
        prev = GENESIS
        for i, e in enumerate(entries):
            body = {k: v for k, v in e.items() if k not in DIGEST_EXCLUDED}
            if e.get("seq") != i:
                report.problems.append(f"seq mismatch at line {i + 1}: {e.get('seq')} != {i}")
            if e.get("prev") != prev:
                report.problems.append(f"broken chain at seq {e.get('seq')}: prev does not match previous digest")
            if sha_bytes(canon(body)) != e.get("digest"):
                report.problems.append(f"digest mismatch at seq {e.get('seq')} ({e.get('type')} {e.get('id')})")
            prev = e.get("digest") or GENESIS
        report.chain_ok = not any(p.startswith(("corrupt:", "seq mismatch", "broken chain", "digest mismatch"))
                                  for p in report.problems)

        if entries:
            if entries[0].get("type") != "genesis":
                report.problems.append("first ledger entry is not a genesis entry")
            marker = None
            if os.path.exists(self.marker):
                try:
                    marker = json.load(open(self.marker, encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    marker = None
            if marker is None:
                report.problems.append("init marker missing (wire/.initialised) — cannot bind the ledger to an origin")
            elif marker.get("genesis_digest") != entries[0].get("digest"):
                report.problems.append("init marker does not match the genesis entry — the ledger was rebuilt")
            head = self._read_head()
            if head is None:
                report.problems.append("no head anchor (wire/head.json missing) — truncation is undetectable")
            else:
                tip = entries[-1]
                if head.get("seq") != tip.get("seq") or head.get("digest") != tip.get("digest"):
                    report.problems.append(
                        f"head anchor mismatch: anchor says seq={head.get('seq')} "
                        f"digest={str(head.get('digest'))[:12]}…, ledger tip is seq={tip.get('seq')} "
                        f"digest={str(tip.get('digest'))[:12]}… (tail truncated, or the ledger was rebuilt)")
        elif self._debris_present():
            report.problems.append("ledger is empty but this bridge has history (head/envelopes) — the ledger is missing")
        return report, entries

    # -- envelopes ---------------------------------------------------------

    def _env_path(self, env_id: str):
        for box in (self.outbox, self.inbox, self.archive):
            p = os.path.join(box, f"{env_id}.json")
            if os.path.exists(p):
                return p
        return None

    def _entry_by_id(self, env_id: str):
        if not env_id:
            return None
        for e in self.entries():
            if e.get("id") == env_id:
                return e
        return None

    def _sign_envelope(self, env: dict) -> None:
        if not self.signer:
            return
        env["signature"] = {"alg": signing.ALG, "pub": self.signer.pub_hex,
                            "sig": self.signer.sign_hex(canon(env))}

    def _actor_registry(self, entries):
        """Current actor -> pubkey at the ledger tip (registrations + rotations)."""
        registry, current, _history, _rev, problems, first_seq = self._key_timeline(entries)
        return current, problems, first_seq

    def _check_signatures(self, report, entries):
        registry, current, history, revocations, problems, first_seq = self._key_timeline(entries)
        report.actors = sorted(registry)
        report.problems.extend(problems)
        report.key_status = [
            {"actor": r.get("actor"), "fingerprint": r.get("fingerprint"),
             "kind": r.get("kind"), "effective_at": r.get("effective_at"),
             "suspected_leak_at": r.get("suspected_leak_at"), "seq": r.get("seq")}
            for r in revocations
        ]
        if not registry:
            return current, history, first_seq
        revoked_at = {r.get("actor"): r.get("seq") for r in revocations}
        for e in entries:
            seq = e.get("seq", 0)
            if first_seq is not None and seq < first_seq:
                continue                          # genesis and pre-registration history is unsigned
            actor = e.get("actor") or e.get("from")
            typ = e.get("type")
            if actor not in registry:
                report.problems.append(f"seq {seq}: actor {actor!r} is not registered")
                continue
            if typ == "rotate":
                expected = e.get("old_pub")
            elif typ == "actor_register":
                expected = e.get("pub")
            else:
                expected = self._key_at(history, actor, seq)
            sig, pub = e.get("sig"), e.get("sig_pub")
            if not sig or not pub:
                report.problems.append(f"seq {seq}: unsigned ledger entry by registered actor {actor!r}")
            elif pub != expected:
                report.problems.append(f"seq {seq}: signing key does not match the active key for {actor!r}")
            elif not signing.verify_hex(pub, str(e.get("digest", "")).encode(), sig):
                report.problems.append(f"seq {seq}: bad signature on ledger entry by {actor!r}")
            if typ == "rotate":
                new = e.get("new_pub")
                if not new or not signing.verify_hex(new, str(e.get("digest", "")).encode(),
                                                      e.get("new_sig", "")):
                    report.problems.append(f"seq {seq}: rotation new key proof missing or invalid")
            if actor in revoked_at and seq > revoked_at[actor] and typ != "revoke":
                report.problems.append(f"seq {seq}: {actor!r} wrote after its revocation "
                                       f"(revoked at seq {revoked_at[actor]})")
        return current, history, first_seq

    def register_actor(self, actor: str, pub_hex: str) -> dict:
        if not self.signer:
            raise Refused("registering an actor requires a signing key (--key)")
        if self.signer.actor != actor:
            raise Refused(f"the signing key belongs to {self.signer.actor!r}, not {actor!r}")
        if pub_hex != self.signer.pub_hex:
            raise Refused("the public key does not match the signing key")
        entries, _ = self.snapshot()
        _registry, current, _history, _rev, _problems, _first = self._key_timeline(entries)
        if actor in current:
            raise Refused(f"actor {actor!r} is already registered; use `rotate` to change its key")
        return self._append({"type": "actor_register", "actor": actor, "pub": pub_hex})

    def rotate_key(self, new_signer: signing.Signer, reason: str = "") -> dict:
        """Rotate this actor's key: the old key authorizes the new one (succession)."""
        if not self.signer:
            raise Refused("rotating a key requires a signing key (--key)")
        if new_signer.actor != self.signer.actor:
            raise Refused(f"the new key belongs to {new_signer.actor!r}, not {self.signer.actor!r}")
        if new_signer.pub_hex == self.signer.pub_hex:
            raise Refused("the new key is the same as the old key")
        self._assert_signer_active()
        entry = self.build_entry({
            "type": "rotate", "actor": self.signer.actor,
            "old_pub": self.signer.pub_hex, "new_pub": new_signer.pub_hex,
            "reason": reason, "protocol_version": "0.1",
        })
        entry["new_sig"] = new_signer.sign_hex(entry["digest"].encode())
        return self.append_entry(entry)

    def revoke_key(self, kind: str = "normal_retirement", effective_at: str | None = None,
                   suspected_leak_at: str | None = None, evidence: str = "") -> dict:
        """Record a key revocation. History is not rewritten; future writes are refused."""
        if not self.signer:
            raise Refused("revoking a key requires a signing key (--key)")
        if kind not in ("normal_retirement", "suspected_compromise", "revoked"):
            raise Refused("kind must be normal_retirement, suspected_compromise or revoked")
        return self._append({
            "type": "revoke", "actor": self.signer.actor,
            "fingerprint": signing.fingerprint(self.signer.pub_hex),
            "kind": kind, "effective_at": effective_at or now(),
            "suspected_leak_at": suspected_leak_at, "evidence": evidence,
            "protocol_version": "0.1",
        })

    def key_status(self) -> dict:
        entries, bad = self.snapshot()
        if bad:
            raise CorruptLedger(f"ledger has unparseable lines ({bad[0]})")
        registry, current, history, revocations, problems, _first = self._key_timeline(entries)
        rotations = [
            {"actor": e.get("actor"), "old_pub": e.get("old_pub"), "new_pub": e.get("new_pub"),
             "seq": e.get("seq"), "reason": e.get("reason")}
            for e in entries if e.get("type") == "rotate"
        ]
        return {"current": dict(current), "rotations": rotations,
                "revocations": [
                    {"actor": r.get("actor"), "fingerprint": r.get("fingerprint"),
                     "kind": r.get("kind"), "effective_at": r.get("effective_at"),
                     "suspected_leak_at": r.get("suspected_leak_at"), "seq": r.get("seq")}
                    for r in revocations],
                "problems": problems}

    def _write_envelope(self, box: str, env: dict) -> str:
        os.makedirs(box, exist_ok=True)
        path = os.path.join(box, f"{env['id']}.json")
        self._write_new(path, json.dumps(env, ensure_ascii=False, indent=2) + "\n")
        return path

    # -- lifecycle ---------------------------------------------------------

    def init(self, actor: str = "bridge", recover_empty: bool = False,
             rebind_marker: bool = False) -> str:
        self._ensure_dirs()
        for base in (self.root, self.store):
            for n in os.listdir(base):
                if ".tmp." in n:
                    try:
                        os.unlink(os.path.join(base, n))
                    except OSError:
                        pass

        exists = os.path.exists(self.ledger)
        empty = exists and os.path.getsize(self.ledger) == 0
        head_exists = os.path.exists(self.head_path)

        if exists and not empty:
            if rebind_marker:
                report, entries = self._verify_chain()
                structural = [p for p in report.problems if not p.startswith("init marker")]
                if structural:
                    raise BrokenLedger("cannot rebind the marker, the ledger itself is not intact:\n  - "
                                       + "\n  - ".join(structural))
                self._append({"type": "marker_rebind", "actor": actor,
                              "reason": "operator rebind after the init marker went missing"})
                self._write_marker(self.snapshot()[0])
                return "init marker rebound (recorded as a marker_rebind ledger entry)"
            report, entries = self._verify_chain()
            if not report.ok:
                raise BrokenLedger("refusing to report 'bridge ready' over a broken ledger:\n  - "
                                   + "\n  - ".join(report.problems)
                                   + "\n  (use `repair` for a stale head, `init --rebind-marker` for a missing marker)")
            return "bridge ready (verified)"
        if empty:
            if head_exists:
                raise BrokenLedger("ledger is empty but a head anchor exists — this is truncated history, "
                                   "not a fresh bridge; refusing to re-init")
            if not recover_empty:
                raise Refused("ledger exists but is empty (a failed first write?) — run "
                              "`init --recover-empty` to write a genesis entry")
            if self._debris_present():
                # orphan envelopes are not evidence of a chain; they stay unverified
                pass
        else:
            if head_exists:
                raise BrokenLedger("ledger is missing but a head anchor exists — refusing to re-init "
                                   "(evidence may have been destroyed; restore the ledger or archive "
                                   "the directory explicitly)")
            if self._debris_present() and not recover_empty:
                raise Refused("ledger is missing but this bridge has history (envelopes) — refusing to "
                              "re-init; use `init --recover-empty` only if you accept that orphan envelopes "
                              "are lost")

        self._append({"type": "genesis", "actor": actor,
                      "note": "bridge initialised" + (" (recovered from empty ledger)" if empty else "")},
                     bypass_head=empty or (not exists))
        self._write_marker(self.snapshot()[0])
        return "bridge ready"

    # -- commands ----------------------------------------------------------

    def send(self, actor: str, to: str, body: str = "", intent: str = "message",
             attach=None, in_reply_to=None) -> dict:
        if in_reply_to:
            ref = self._entry_by_id(in_reply_to)
            if not ref or ref.get("type") not in ("send", "deliver"):
                raise NotFound(f"in_reply_to is not a recorded request/delivery: {in_reply_to}")
        env = {"v": ENVELOPE_VERSION, "id": new_id(actor), "from": actor, "to": to,
               "intent": intent, "in_reply_to": in_reply_to, "created_at": now(),
               "body": body, "artifacts": [self.artifact(p, "target") for p in (attach or [])],
               "reply_box": "wire/inbox"}
        self._sign_envelope(env)
        path = self._write_envelope(self.outbox, env)
        try:
            entry = self._append({"type": "send", "id": env["id"], "actor": actor,
                                  "from": actor, "to": to, "intent": intent,
                                  "in_reply_to": in_reply_to,
                                  "envelope_sha256": sha_file(path), "artifacts": env["artifacts"]})
        except BridgeError:
            try:
                os.unlink(path)          # roll the envelope back; blobs are content-addressed
            except OSError:
                pass
            raise
        return {"id": env["id"], "envelope": path, "ledger_seq": entry["seq"],
                "artifacts": [{"path": a["path"], "sha256": a["sha256"], "stored_as": a["stored_as"]}
                              for a in env["artifacts"]]}

    def deliver(self, actor: str, to: str, in_reply_to: str, body: str = "",
                intent: str = "deliver", attach=None, version: str = "v1",
                revises: str | None = None, delivery_id: str | None = None) -> dict:
        ref = self._entry_by_id(in_reply_to)
        if not ref or ref.get("type") not in ("send", "deliver"):
            raise NotFound(f"in_reply_to is not a recorded request/delivery: {in_reply_to}")
        previous = None
        if revises:
            previous = self._entry_by_id(revises)
            if not previous or previous.get("type") != "deliver":
                raise NotFound(f"revises is not a recorded delivery: {revises}")
            logical_id = previous.get("delivery_id") or previous["id"]
            previous_version = previous.get("version") or "v1"
            if version == previous_version:
                raise Refused(f"revision must use a new version label (still {version!r})")
            previous_delivery = previous["id"]
        else:
            logical_id = delivery_id or None          # filled with the envelope id below
            previous_version = None
            previous_delivery = None
        env = {"v": ENVELOPE_VERSION, "id": new_id(actor), "from": actor, "to": to,
               "intent": intent, "in_reply_to": in_reply_to, "created_at": now(),
               "body": body, "artifacts": [self.artifact(p, "deliverable") for p in (attach or [])],
               "version": version, "previous_delivery": previous_delivery}
        if logical_id:
            env["delivery_id"] = logical_id
        self._sign_envelope(env)
        path = self._write_envelope(self.inbox, env)
        fields = {"type": "deliver", "id": env["id"], "actor": actor,
                  "from": actor, "to": to, "intent": intent,
                  "in_reply_to": in_reply_to,
                  "envelope_sha256": sha_file(path), "artifacts": env["artifacts"],
                  "version": version, "previous_delivery": previous_delivery,
                  "delivery_id": logical_id or env["id"],
                  "previous_version": previous_version}
        try:
            entry = self._append(fields)
        except BridgeError:
            try:
                os.unlink(path)
            except OSError:
                pass
            raise
        return {"id": env["id"], "envelope": path, "ledger_seq": entry["seq"],
                "delivery_id": entry["delivery_id"], "version": version,
                "previous_delivery": previous_delivery, "previous_version": previous_version}

    def requests(self, actor=None):
        """Envelopes sitting in the outbox (requests). Read-only: a request stays until the
        sender archives it, so the recipient can always re-read what it was asked to do."""
        os.makedirs(self.outbox, exist_ok=True)
        known = {e.get("id"): e.get("envelope_sha256") for e in self.entries()
                 if e.get("type") == "send"}
        out = []
        for name in sorted(os.listdir(self.outbox)):
            if not name.endswith(".json"):
                continue
            p = os.path.join(self.outbox, name)
            try:
                env = json.load(open(p, encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if actor is not None and env.get("to") != actor:
                continue
            env["_envelope"] = p
            expected = known.get(env.get("id"))
            env["_verified"] = bool(expected) and expected == sha_file(p)
            out.append(env)
        return out

    def poll(self, actor: str = "dsh", consume: bool = False) -> PollResult:
        os.makedirs(self.inbox, exist_ok=True)
        known = {}
        for e in self.entries():
            if e.get("type") in ("send", "deliver") and e.get("id") and e.get("envelope_sha256"):
                known[e["id"]] = e["envelope_sha256"]

        envs = []
        for name in sorted(os.listdir(self.inbox)):
            if not name.endswith(".json"):
                continue
            p = os.path.join(self.inbox, name)
            try:
                env = json.load(open(p, encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if env.get("to") != actor:
                continue
            env["_envelope"] = p
            expected = known.get(env.get("id"))
            env["_verified"] = bool(expected) and expected == sha_file(p)
            envs.append(env)

        refused, consumed = [], []
        if consume:
            good = [e for e in envs if e["_verified"]]
            refused = [e for e in envs if not e["_verified"]]
            os.makedirs(self.archive, exist_ok=True)
            for env in good:
                dest = os.path.join(self.archive, os.path.basename(env["_envelope"]))
                os.replace(env["_envelope"], dest)     # move first: a crash leaves it unconsumed
                _fsync_dir(self.inbox)
                self._append({"type": "consume", "id": env["id"], "actor": actor,
                              "envelope_sha256": sha_file(dest),
                              "archived_as": os.path.relpath(dest, self.root)})
                consumed.append(env["id"])
        return PollResult(envs, refused, consumed)

    def commit(self, actor: str, promise: str, accept: str = "", ref=None) -> dict:
        if ref:
            e = self._entry_by_id(ref)
            if not e or e.get("type") not in ("send", "deliver"):
                raise NotFound(f"commit ref is not a recorded request/delivery: {ref}")
        entry = self._append({"type": "commit", "id": new_id(actor), "actor": actor,
                              "ref": ref, "promise": promise, "accept": accept})
        return {"commit_id": entry["id"], "ledger_seq": entry["seq"],
                "head": {"seq": entry["seq"], "digest": entry["digest"]}}

    def accept_delivery(self, actor: str, delivery_id: str, version: str | None = None,
                        decision: str = "accepted", reason: str = "",
                        requires_anchoring: bool = False,
                        artifacts: list | None = None) -> dict:
        """Record an acceptance/rejection of a delivered version.

        The acceptance record is a separate signed object (evidence domain 0.1); the ledger
        entry only references its sha256. Original bytes are never rewritten on export.
        """
        from .jcs import canonical_bytes
        if decision not in ("accepted", "rejected"):
            raise Refused("decision must be 'accepted' or 'rejected'")
        if not self.signer:
            raise Refused("accepting a delivery requires a signing key (--key)")
        if actor != self.signer.actor:
            raise Refused(f"the signing key belongs to {self.signer.actor!r}, not {actor!r}")
        ref = self._entry_by_id(delivery_id)
        if not ref or ref.get("type") != "deliver":
            raise NotFound(f"not a recorded delivery: {delivery_id}")
        logical_id = ref.get("delivery_id") or ref["id"]
        if version is None:
            version = ref.get("version") or "v1"
        hashes = (sorted(artifacts) if artifacts is not None
                  else sorted(a["sha256"] for a in ref.get("artifacts", [])))
        acceptance_id = "acc-" + delivery_id
        record = {
            "protocol_version": "0.2",
            "acceptance_id": acceptance_id,
            "delivery_id": logical_id,
            "version": version,
            "delivery_ref": delivery_id,
            "artifacts_sha256": hashes,
            "decision": decision,
            "reason": reason,
            "requires_anchoring": bool(requires_anchoring),
            "actor": actor,
            "signed_at": now(),
        }
        payload = b"agentbridge-evidence/0.1\nacceptance-record\n" + canonical_bytes(record)
        record["signature"] = {"alg": signing.ALG, "pub": self.signer.pub_hex,
                               "sig": self.signer.sign_hex(payload)}
        adir = os.path.join(self.wire, "acceptances")
        os.makedirs(adir, exist_ok=True)
        path = os.path.join(adir, acceptance_id + ".json")
        self._write_new(path, json.dumps(record, ensure_ascii=False, indent=2) + "\n")
        try:
            entry = self._append({
                "type": "accept" if decision == "accepted" else "reject",
                "acceptance_id": acceptance_id,
                "actor": actor,
                "delivery_id": logical_id,
                "delivery_ref": delivery_id,
                "version": version,
                "decision": decision,
                "record_sha256": sha_file(path),
            })
        except BridgeError:
            try:
                os.unlink(path)
            except OSError:
                pass
            raise
        return {"acceptance_id": acceptance_id, "record": path, "ledger_seq": entry["seq"]}

    def verify(self, expect_head=None, expect_receipt=None) -> VerificationReport:
        report, entries = self._verify_chain()

        for e in entries:
            if e.get("type") not in ("send", "deliver", "consume"):
                continue
            expected = e.get("envelope_sha256")
            if not expected:
                continue
            path = self._env_path(e.get("id"))
            if path is None:
                report.envelopes_failed += 1
                report.problems.append(f"seq {e['seq']}: envelope missing: {e.get('id')}")
                continue
            report.envelopes_checked += 1
            if sha_file(path) != expected:
                report.envelopes_failed += 1
                report.problems.append(f"seq {e['seq']}: envelope content changed since recorded: {e.get('id')}")

        for e in entries:
            for a in e.get("artifacts") or []:
                stored = a.get("stored_as")
                if not stored:
                    report.artifacts_failed += 1
                    report.problems.append(f"seq {e['seq']}: artifact has no stored copy: {a.get('path')}")
                    continue
                sp = os.path.join(self.root, stored)
                if not os.path.isfile(sp):
                    report.artifacts_failed += 1
                    report.problems.append(f"seq {e['seq']}: stored artifact missing: {stored}")
                    continue
                if sha_file(sp) != a.get("sha256"):
                    report.artifacts_failed += 1
                    report.problems.append(f"seq {e['seq']}: stored artifact corrupt: {stored}")
                else:
                    report.artifacts_ok += 1
                    live = a.get("path", "")
                    if os.path.isfile(live) and sha_file(live) != a.get("sha256"):
                        report.originals_drifted += 1

        by_seq = {e.get("seq"): e for e in entries}
        for e in entries:
            if e.get("type") != "anchor":
                continue
            target = by_seq.get(e.get("anchor_seq"))
            if target is None:
                report.problems.append(f"seq {e['seq']}: anchor points to a missing ledger seq "
                                       f"{e.get('anchor_seq')}")
            elif target.get("digest") != e.get("anchor_digest"):
                report.problems.append(f"seq {e['seq']}: anchor digest does not match ledger seq "
                                       f"{e.get('anchor_seq')}")

        registry, history, first_seq = self._check_signatures(report, entries)
        if registry:
            for e in entries:
                if e.get("type") not in ("send", "deliver"):
                    continue
                if first_seq is not None and e.get("seq", 0) < first_seq:
                    continue
                path = self._env_path(e.get("id"))
                if path is None:
                    continue
                try:
                    env = json.load(open(path, encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    continue
                sender = env.get("from")
                sig = (env.get("signature") or {}).get("sig")
                pub = self._key_at(history, sender, e["seq"])
                if pub is None:
                    report.problems.append(f"seq {e['seq']}: envelope from unregistered actor {sender!r}")
                elif not sig or not signing.verify_hex(
                        pub, canon({k: v for k, v in env.items() if k != "signature"}), sig):
                    report.problems.append(f"seq {e['seq']}: envelope signature invalid for {sender!r}")

        if expect_head:
            want_seq, _, want_digest = expect_head.partition(":")
            tip = entries[-1] if entries else {}
            if str(tip.get("seq")) != want_seq.strip() or tip.get("digest") != want_digest.strip():
                report.problems.append(f"expected head {expect_head}, ledger tip is "
                                       f"{tip.get('seq')}:{str(tip.get('digest'))[:16]}…")
            else:
                report.anchor_level = "anchored"
                report.anchor = {"kind": "head", "seq": tip.get("seq"), "digest": tip.get("digest")}

        if expect_receipt:
            receipt_problems = verify_anchor_receipt(expect_receipt)
            report.problems.extend(f"anchor: {p}" for p in receipt_problems)
            if not receipt_problems:
                target = by_seq.get(expect_receipt.get("seq"))
                if target is None:
                    report.problems.append("anchor: ledger has no entry at the receipt's seq")
                elif target.get("digest") != expect_receipt.get("digest"):
                    report.problems.append("anchor: receipt digest does not match the ledger")
                else:
                    report.anchor_level = "anchored"
                    report.anchor = {"kind": "receipt", "seq": expect_receipt.get("seq"),
                                     "digest": expect_receipt.get("digest"),
                                     "service_pub": expect_receipt.get("service_pub"),
                                     "log_index": expect_receipt.get("log_index")}
        return report

    def anchor(self) -> dict:
        entries, _ = self.snapshot()
        if not entries:
            raise NotInitialised("ledger is empty — nothing to anchor")
        tip = entries[-1]
        return {"seq": tip["seq"], "digest": tip["digest"], "ts": tip["ts"],
                "verify_with": f"--expect-head {tip['seq']}:{tip['digest']}"}

    def repair(self, actor: str = "bridge", accept_head_loss: bool = False) -> dict:
        entries, bad = self.snapshot()
        if bad:
            raise CorruptLedger(f"ledger has unparseable lines ({bad[0]}) — repair refuses")
        if not entries:
            raise NotInitialised("ledger is empty — nothing to repair, use init")
        prev = GENESIS
        for i, e in enumerate(entries):
            body = {k: v for k, v in e.items() if k != "digest"}
            if e.get("seq") != i or e.get("prev") != prev or sha_bytes(canon(body)) != e.get("digest"):
                raise BrokenLedger("ledger chain is not intact — repair refuses "
                                   "(this is tampering, not a stale head)")
            prev = e["digest"]
        head = self._read_head()
        tip = entries[-1]
        if head and head.get("seq") == tip["seq"] and head.get("digest") == tip["digest"]:
            return {"repaired": False, "head": head}
        if not accept_head_loss:
            raise Refused("head anchor does not match the ledger tip; refusing to re-anchor without "
                          "accept_head_loss (this abandons whatever the old anchor pointed at, and "
                          "records that decision in the ledger)")
        entry = self._append({"type": "repair", "actor": actor, "prior_head": head or {},
                              "prior_head_status": "missing" if head is None else "stale"},
                             bypass_head=True)
        return {"repaired": True, "prior_head": head,
                "new_head": {"seq": entry["seq"], "digest": entry["digest"]}}

    def show(self, env_id: str) -> dict:
        p = self._env_path(env_id)
        if p is None:
            raise NotFound(f"envelope not found: {env_id}")
        return json.load(open(p, encoding="utf-8"))

    def doctor(self) -> dict:
        entries, bad = self.snapshot()

        def count(d):
            return len([n for n in os.listdir(d) if n.endswith(".json")]) if os.path.isdir(d) else 0

        return {"root": self.root, "ledger_entries": len(entries), "unparseable": len(bad),
                "head": self._read_head(), "outbox": count(self.outbox),
                "inbox": count(self.inbox), "archive": count(self.archive),
                "store": len(os.listdir(self.store)) if os.path.isdir(self.store) else 0}
