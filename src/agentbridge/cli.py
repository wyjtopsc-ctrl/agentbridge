"""Command line interface for agentbridge.

Exit codes:
  0  success
  1  a bridge error (the message says which)
  2  `poll --consume` found an envelope that is not in the ledger and refused it
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from . import core, evidence, signing
from .core import Bridge, BridgeError

DEFAULT_ROOT = os.environ.get("AGENTBRIDGE_ROOT", ".")


def _bridge(args):
    remote = getattr(args, "remote", None)
    key = getattr(args, "key", None)
    if remote:
        if not key:
            raise core.Refused("--remote requires --key: every request is signed")
        from .transport import HttpBridge
        return HttpBridge(remote, signing.load_keyfile(key))
    if key:
        return Bridge(args.root, signer=signing.load_keyfile(key))
    return Bridge(args.root)


def _actor(args, bridge) -> str:
    return bridge.signer.actor if bridge.signer else getattr(args, "actor", "dsh")


def _emit(text: str) -> None:
    sys.stdout.write(text if text.endswith("\n") else text + "\n")


def cmd_init(args) -> int:
    bridge = _bridge(args)
    if not isinstance(bridge, Bridge):
        raise core.Refused("`init` must run against the server's directory, not over the transport")
    _emit(bridge.init(actor=args.actor, recover_empty=args.recover_empty,
                            rebind_marker=args.rebind_marker))
    return 0


def cmd_send(args) -> int:
    bridge = _bridge(args)
    result = bridge.send(actor=_actor(args, bridge), to=args.to, body=args.body,
                                intent=args.intent, attach=args.attach,
                                in_reply_to=args.in_reply_to)
    _emit(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


def cmd_deliver(args) -> int:
    bridge = _bridge(args)
    result = bridge.deliver(actor=_actor(args, bridge), to=args.to, in_reply_to=args.in_reply_to,
                                   body=args.body, intent=args.intent, attach=args.attach)
    _emit(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


def cmd_actors(args) -> int:
    bridge = _bridge(args)
    actors = bridge.actors()
    if args.json:
        _emit(json.dumps(actors, ensure_ascii=False, indent=2))
        return 0
    if not actors:
        _emit("no registered actors (unsigned bridge)")
        return 0
    for actor in actors:
        _emit(f"{actor['actor']:<20} {actor['fingerprint']}  "
              f"seq={actor['registered_seq']}  {actor['registered_at'] or ''}")
    return 0


def cmd_keygen(args) -> int:
    signer = signing.new_signer(args.actor)
    out = os.path.abspath(args.out or ".")
    os.makedirs(out, exist_ok=True)
    path = os.path.join(out, f"{args.actor}.key")
    signing.save_keyfile(signer, path, force=args.force)
    _emit(json.dumps({"actor": args.actor, "pub_hex": signer.pub_hex, "keyfile": path},
                     ensure_ascii=False, indent=2))
    return 0


def cmd_register(args) -> int:
    bridge = _bridge(args)
    if not bridge.signer:
        raise core.Refused("registering requires --key <keyfile>")
    entry = bridge.register_actor(bridge.signer.actor, bridge.signer.pub_hex)
    _emit(json.dumps({"registered": bridge.signer.actor, "pub_hex": bridge.signer.pub_hex,
                      "ledger_seq": entry["seq"]}, ensure_ascii=False, indent=2))
    return 0


def cmd_requests(args) -> int:
    envs = _bridge(args).requests(actor=args.actor)
    if args.json:
        _emit(json.dumps([{k: v for k, v in e.items() if k != "_envelope"} for e in envs],
                         ensure_ascii=False, indent=2))
        return 0
    if not envs:
        _emit(f"no pending requests for {args.actor}")
        return 0
    for env in envs:
        mark = "verified" if env["_verified"] else "UNVERIFIED"
        _emit(f"[{env['id']}] {env['from']} -> {env['to']}  intent={env['intent']}  "
              f"{env['created_at']}  [{mark}]")
        for line in (env.get("body") or "").splitlines():
            _emit(f"   | {line}")
    return 0


def cmd_poll(args) -> int:
    result = _bridge(args).poll(actor=args.actor, consume=args.consume)
    if args.json:
        _emit(json.dumps([{k: v for k, v in e.items() if not k.startswith("_") or k == "_verified"}
                          for e in result.envelopes], ensure_ascii=False, indent=2))
    elif not result.envelopes:
        _emit(f"inbox empty for {args.actor}")
    else:
        for env in result.envelopes:
            mark = "verified" if env["_verified"] else "UNVERIFIED (envelope not in ledger / digest mismatch)"
            _emit(f"[{env['id']}] {env['from']} -> {env['to']}  intent={env['intent']}"
                  f"  re={env.get('in_reply_to')}  {env['created_at']}  [{mark}]")
            for a in env.get("artifacts", []):
                _emit(f"   artifact {a['role']}: {a['path']}  sha256={a['sha256'][:16]}…  {a['bytes']}B")
            for line in (env.get("body") or "").splitlines():
                _emit(f"   | {line}")
            _emit("")
    for env in result.refused:
        sys.stderr.write(f"refused to consume UNVERIFIED envelope {env['id']} from {env['from']!r}: "
                         f"it is not in the ledger (or its content changed). It stays in the inbox.\n")
    if result.consumed:
        _emit(f"consumed {len(result.consumed)} envelope(s)")
    if result.refused:
        if not result.consumed:
            _emit("nothing consumed")
        return 2
    return 0



def cmd_evidence_export(args) -> int:
    bridge = _bridge(args)
    if not isinstance(bridge, Bridge):
        raise core.Refused("evidence export must run against a bridge directory")
    if not bridge.signer:
        raise core.Refused("evidence export requires --key (the exporter signs the manifest)")
    ref = {"system": args.task_system, "id": args.task_id}
    if args.task_url:
        ref["url"] = args.task_url
    result = evidence.export_pack(
        bridge, args.out, task_ref=ref, delivery_id=args.delivery,
        exporter=bridge.signer, status_file=args.status,
        receipt_files=args.receipt or [], version=args.version)
    _emit(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


def cmd_evidence_verify(args) -> int:
    result = evidence.verify(args.pack, args.trust)
    _emit(json.dumps(result.to_dict(args.pack), ensure_ascii=False, indent=2))
    return result.exit_code()


def cmd_evidence(args) -> int:
    return args.evidence_fn(args)



def cmd_rotate(args) -> int:
    bridge = _bridge(args)
    if not isinstance(bridge, Bridge):
        raise core.Refused("rotation must run against the bridge directory")
    new_signer = signing.load_keyfile(args.new_key)
    entry = bridge.rotate_key(new_signer, reason=args.reason)
    _emit(json.dumps({"rotated": bridge.signer.actor if bridge.signer else None,
                      "new_pub": new_signer.pub_hex, "ledger_seq": entry["seq"]},
                     ensure_ascii=False, indent=2))
    return 0


def cmd_revoke(args) -> int:
    bridge = _bridge(args)
    if not isinstance(bridge, Bridge):
        raise core.Refused("revocation must run against the bridge directory")
    entry = bridge.revoke_key(kind=args.kind, effective_at=args.effective_at,
                              suspected_leak_at=args.suspected_leak_at,
                              evidence=args.evidence)
    _emit(json.dumps({"revoked": entry["actor"], "fingerprint": entry["fingerprint"],
                      "kind": entry["kind"], "ledger_seq": entry["seq"]},
                     ensure_ascii=False, indent=2))
    return 0


def cmd_key_status(args) -> int:
    bridge = _bridge(args)
    _emit(json.dumps(bridge.key_status(), ensure_ascii=False, indent=2))
    return 0


def cmd_verify(args) -> int:
    bridge = _bridge(args)
    is_local = isinstance(bridge, Bridge)
    receipt = None
    if args.expect_anchor:
        if not is_local:
            raise core.Refused("anchor receipts are verified against the local ledger; run this "
                               "on the host that owns the bridge, or use --expect-head")
        try:
            with open(args.expect_anchor, encoding="utf-8") as f:
                receipt = json.load(f)
        except (OSError, json.JSONDecodeError) as exc:
            raise core.Refused(f"cannot read anchor receipt: {exc}")

    kwargs = {"expect_head": args.expect_head}
    if is_local:
        kwargs["expect_receipt"] = receipt
    report = bridge.verify(**kwargs)
    _emit(f"ledger: {report.ledger_len} entries, chain {'OK' if report.chain_ok else 'BROKEN'}")
    _emit(f"envelopes: {report.envelopes_checked} checked, {report.envelopes_failed} failing")
    _emit(f"artifacts: {report.artifacts_ok} verified in store, {report.artifacts_failed} failing, "
          f"{report.originals_drifted} original path(s) drifted (info)")
    if report.actors:
        _emit(f"actors: {', '.join(report.actors)}")
    if report.anchor_level == "anchored":
        anchor = report.anchor or {}
        detail = f" (kind={anchor.get('kind')}, seq={anchor.get('seq')}"
        if anchor.get("log_index") is not None:
            detail += f", log_index={anchor['log_index']}"
        _emit(f"anchor: anchored{detail})")
    else:
        _emit("anchor: local_only — internally consistent, not externally anchored")
    for problem in report.problems:
        _emit(f"  ! {problem}")
    return 0 if report.ok else 1


def cmd_ledger(args) -> int:
    for e in _bridge(args).entries():
        arts = f" arts={len(e['artifacts'])}" if e.get("artifacts") else ""
        ref = f"  re={e['in_reply_to']}" if e.get("in_reply_to") else ""
        _emit(f"{e['seq']:>3}  {e['ts']}  {e['type']:<9} {e.get('from', e.get('actor', '')):>7} -> "
              f"{e.get('to', '-'):<7} {e.get('id', '')}{ref}{arts}")
    return 0


def cmd_show(args) -> int:
    env = _bridge(args).show(args.id)
    _emit(json.dumps(env, ensure_ascii=False, indent=2))
    return 0


def cmd_commit(args) -> int:
    bridge = _bridge(args)
    result = bridge.commit(actor=_actor(args, bridge), promise=args.promise,
                                  accept=args.accept, ref=args.ref)
    _emit(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


def cmd_anchor(args) -> int:
    _emit(json.dumps(_bridge(args).anchor(), ensure_ascii=False, indent=2))
    return 0


def cmd_repair(args) -> int:
    result = _bridge(args).repair(actor=args.actor, accept_head_loss=args.accept_head_loss)
    if not result.get("repaired"):
        _emit("nothing to repair: head already matches the ledger tip")
    else:
        _emit(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


def cmd_anchor_service(args) -> int:
    from . import anchor
    if not args.key:
        raise core.Refused("anchor-service requires --key (the service's signing key)")
    anchor.serve(args.dir, signing.load_keyfile(args.key), host=args.host, port=args.port)
    return 0


def cmd_anchor_submit(args) -> int:
    from . import anchor
    bridge = _bridge(args)
    if not isinstance(bridge, Bridge):
        raise core.Refused("run anchor-submit on the host that owns the bridge "
                           "(it writes a receipt file and a ledger entry)")
    if not bridge.signer:
        raise core.Refused("anchor-submit requires --key")
    head = bridge.head()
    bridge_id = bridge.bridge_id()
    receipt = anchor.submit(args.url, bridge.signer, bridge_id, head["seq"], head["digest"])
    receipts_dir = os.path.join(bridge.wire, "anchors")
    os.makedirs(receipts_dir, exist_ok=True)
    path = os.path.join(receipts_dir, f"anchor-{receipt['seq']}-{receipt['digest'][:12]}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(receipt, f, ensure_ascii=False, indent=2)
        f.write("\n")
    entry = bridge._append({"type": "anchor", "id": core.new_id(bridge.signer.actor),
                            "actor": bridge.signer.actor, "bridge_id": bridge_id,
                            "anchor_seq": receipt["seq"], "anchor_digest": receipt["digest"],
                            "log_index": receipt["log_index"], "service_url": args.url,
                            "receipt_sha256": core.sha_bytes(core.canon(receipt))})
    _emit(json.dumps({"receipt": path, "bridge_id": bridge_id,
                      "log_index": receipt["log_index"], "ledger_seq": entry["seq"],
                      "service_pub": receipt["service_pub"]}, ensure_ascii=False, indent=2))
    return 0


def cmd_anchor_verify(args) -> int:
    from . import anchor
    try:
        receipt = json.load(open(args.receipt, encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        _emit(f"anchor receipt: INVALID ({exc})")
        return 1
    problems = anchor.verify_receipt(receipt)
    if args.expect_head:
        want_seq, _, want_digest = args.expect_head.partition(":")
        if str(receipt.get("seq")) != want_seq.strip() or receipt.get("digest") != want_digest.strip():
            problems.append("receipt does not match --expect-head")
    else:
        try:
            entries = _bridge(args).entries()
            target = next((e for e in entries if e.get("seq") == receipt.get("seq")), None)
            if target is None:
                problems.append(f"local ledger has no entry at seq {receipt.get('seq')}")
            elif target.get("digest") != receipt.get("digest"):
                problems.append("receipt digest does not match the local ledger")
        except core.BridgeError as exc:
            problems.append(f"cannot read the local ledger: {exc}")
    for p in problems:
        _emit(f"  ! {p}")
    _emit("anchor receipt: " + ("OK" if not problems else "INVALID"))
    return 0 if not problems else 1


def cmd_serve(args) -> int:
    from .transport import serve
    serve(args.root, host=args.host, port=args.port)
    return 0


def cmd_mcp(args) -> int:
    from .mcp_server import run_stdio
    return run_stdio(_bridge(args), actor=args.actor,
                     allow_destructive=args.allow_destructive_tools)


def cmd_doctor(args) -> int:
    info = _bridge(args).doctor()
    _emit(f"root:      {info['root']}")
    _emit(f"ledger:    {info['ledger_entries']} entries, {info['unparseable']} unparseable line(s)")
    _emit(f"head:      {info['head'] if info['head'] is not None else 'MISSING'}")
    _emit(f"outbox:    {info['outbox']}")
    _emit(f"inbox:     {info['inbox']}")
    _emit(f"archive:   {info['archive']}")
    _emit(f"store:     {info['store']} blob(s)")
    return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="agentbridge",
                                 description="verifiable delivery between autonomous agents")
    ap.add_argument("--root", default=DEFAULT_ROOT,
                    help="bridge directory (default: $AGENTBRIDGE_ROOT or .)")
    ap.add_argument("--key", default=None, metavar="KEYFILE",
                    help="Ed25519 key file to sign writes with (also sets the actor)")
    ap.add_argument("--remote", default=None, metavar="URL",
                    help="talk to an agentbridge sequencer instead of the local filesystem")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("keygen", help="create an Ed25519 key pair for an actor")
    p.add_argument("--actor", required=True)
    p.add_argument("--out", default=".", help="directory to write <actor>.key into")
    p.add_argument("--force", action="store_true")
    p.set_defaults(fn=cmd_keygen)

    p = sub.add_parser("register", help="register this key as an actor in the ledger")
    p.set_defaults(fn=cmd_register)

    p = sub.add_parser("init", help="create or check a bridge directory")
    p.add_argument("--actor", default="bridge")
    p.add_argument("--recover-empty", action="store_true",
                   help="write a genesis entry over an empty ledger left by a failed first append")
    p.add_argument("--rebind-marker", action="store_true",
                   help="re-create a missing init marker, recorded as a ledger entry")
    p.set_defaults(fn=cmd_init)

    p = sub.add_parser("send", help="send a request")
    p.add_argument("--actor", default="dsh")
    p.add_argument("--to", required=True)
    p.add_argument("--intent", default="message")
    p.add_argument("--body", default="")
    p.add_argument("--attach", action="append")
    p.add_argument("--in-reply-to", default=None)
    p.set_defaults(fn=cmd_send)

    p = sub.add_parser("deliver", help="deliver a result")
    p.add_argument("--actor", default="hermes")
    p.add_argument("--to", default="dsh")
    p.add_argument("--in-reply-to", required=True)
    p.add_argument("--intent", default="deliver")
    p.add_argument("--body", default="")
    p.add_argument("--attach", action="append")
    p.set_defaults(fn=cmd_deliver)

    p = sub.add_parser("actors", help="list registered actors and their key fingerprints")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_actors)

    p = sub.add_parser("requests", help="read pending requests (outbox) addressed to an agent")
    p.add_argument("--actor", default="dsh")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_requests)

    p = sub.add_parser("poll", help="read (and optionally consume) the inbox")
    p.add_argument("--actor", default="dsh")
    p.add_argument("--consume", action="store_true")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_poll)

    p = sub.add_parser("verify", help="verify chain, envelopes, artifacts")
    p.add_argument("--expect-head", default=None, metavar="SEQ:DIGEST")
    p.add_argument("--expect-anchor", default=None, metavar="RECEIPT",
                   help="verify a hosted-anchor receipt against this ledger")
    p.set_defaults(fn=cmd_verify)

    sub.add_parser("ledger", help="print the ledger").set_defaults(fn=cmd_ledger)

    p = sub.add_parser("show", help="print one envelope")
    p.add_argument("id")
    p.set_defaults(fn=cmd_show)

    p = sub.add_parser("commit", help="record a commitment")
    p.add_argument("--actor", default="dsh")
    p.add_argument("--ref", default=None)
    p.add_argument("--promise", required=True)
    p.add_argument("--accept", default="")
    p.set_defaults(fn=cmd_commit)

    sub.add_parser("anchor", help="print the head anchor to hold off-filesystem").set_defaults(fn=cmd_anchor)

    p = sub.add_parser("repair", help="re-anchor after a failed head write")
    p.add_argument("--actor", default="bridge")
    p.add_argument("--accept-head-loss", action="store_true")
    p.set_defaults(fn=cmd_repair)

    p = sub.add_parser("anchor-service", help="run a hosted anchor notary (append-only receipts)")
    p.add_argument("--dir", required=True, help="service state directory")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8790)
    p.set_defaults(fn=cmd_anchor_service)

    p = sub.add_parser("anchor-submit", help="submit the current ledger tip to an anchor service")
    p.add_argument("--url", required=True)
    p.set_defaults(fn=cmd_anchor_submit)

    p = sub.add_parser("anchor-verify", help="verify an anchor receipt against this ledger")
    p.add_argument("--receipt", required=True)
    p.add_argument("--expect-head", default=None, metavar="SEQ:DIGEST")
    p.set_defaults(fn=cmd_anchor_verify)

    p = sub.add_parser("rotate", help="rotate this actor's signing key (old key authorizes new)")
    p.add_argument("--new-key", required=True, help="key file for the new key (same actor)")
    p.add_argument("--reason", default="")
    p.set_defaults(fn=cmd_rotate)

    p = sub.add_parser("revoke", help="record a key revocation; history is not rewritten")
    p.add_argument("--kind", default="normal_retirement",
                   choices=["normal_retirement", "suspected_compromise", "revoked"])
    p.add_argument("--effective-at", default=None)
    p.add_argument("--suspected-leak-at", default=None)
    p.add_argument("--evidence", default="")
    p.set_defaults(fn=cmd_revoke)

    sub.add_parser("key-status", help="show key timelines and revocations").set_defaults(
        fn=cmd_key_status)

    p = sub.add_parser("evidence", help="export a delivery evidence pack and verify it offline")
    ev = p.add_subparsers(dest="evidence_cmd", required=True)

    e = ev.add_parser("export", help="export one delivery chain into the v0 pack layout")
    e.add_argument("--delivery", required=True, help="delivery envelope id")
    e.add_argument("--out", required=True, help="output directory for the pack")
    e.add_argument("--status", required=True, help="signed revocation-status file")
    e.add_argument("--receipt", action="append", default=[],
                   help="anchor receipt file (repeatable)")
    e.add_argument("--task-system", default="external")
    e.add_argument("--task-id", required=True)
    e.add_argument("--task-url", default=None)
    e.add_argument("--version", default=None, help="version label (default from acceptance)")
    e.set_defaults(fn=cmd_evidence_export)

    v = ev.add_parser("verify", help="verify a pack with an external trust file")
    v.add_argument("--pack", required=True)
    v.add_argument("--trust", required=True)
    v.set_defaults(fn=cmd_evidence_verify)

    p = sub.add_parser("serve", help="run an HTTP sequencer over a bridge directory")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8765)
    p.set_defaults(fn=cmd_serve)

    p = sub.add_parser("mcp", help="run an MCP stdio server exposing the bridge as tools")
    p.add_argument("--actor", default="agent", help="identity this server writes as")
    p.add_argument("--allow-destructive-tools", action="store_true",
                   help="also expose repair/recover_empty (off by default: they write)")
    p.set_defaults(fn=cmd_mcp)

    sub.add_parser("doctor", help="print bridge state").set_defaults(fn=cmd_doctor)
    return ap


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.fn(args)
    except core.BridgeError as exc:
        sys.stderr.write(f"agentbridge: [{exc.code}] {exc}\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
