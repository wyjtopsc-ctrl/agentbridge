#!/usr/bin/env python3
"""Randomized malformed-pack fuzzing for the product verifier.

Invariant: malformed input must never crash and must never be reported as fully valid
(exit 0). Deterministic seed; failures print the seed/index so they can be replayed.
"""
from __future__ import annotations

import argparse
import json
import os
import random
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "src"))

from agentbridge import evidence, signing  # noqa: E402

FIX = os.path.join(ROOT, "docs", "fixtures", "evidence-pack-v0")
EXPORTER_SEED = b"\x55" * 32


def load_pack(pack):
    files = {}
    for dirpath, _dirs, names in os.walk(pack):
        for name in names:
            path = os.path.join(dirpath, name)
            files[os.path.relpath(path, pack)] = open(path, "rb").read()
    return files


def leaf_paths(obj, prefix=()):
    out = []
    if isinstance(obj, dict):
        for key, value in obj.items():
            out.extend(leaf_paths(value, prefix + (key,)))
    elif isinstance(obj, list):
        for i, value in enumerate(obj):
            out.extend(leaf_paths(value, prefix + (i,)))
    else:
        out.append(prefix)
    return out


def set_path(obj, path, value):
    cur = obj
    for key in path[:-1]:
        cur = cur[key]
    cur[path[-1]] = value


WRONG = [None, True, 123, "x", [], {}]


def mutate(files: dict, rng: random.Random):
    """Return (kind, mutated_files)."""
    kind = rng.choice(["byteflip", "truncate", "append", "json-garbage",
                       "json-type", "manifest-delete"])
    out = dict(files)
    names = sorted(out)
    if kind in ("byteflip", "truncate", "append", "json-garbage"):
        name = rng.choice(names)
        data = bytearray(out[name])
        if kind == "byteflip" and data:
            i = rng.randrange(len(data))
            data[i] ^= 1 << rng.randrange(8)
            out[name] = bytes(data)
        elif kind == "truncate":
            out[name] = bytes(data[: rng.randrange(len(data) + 1)])
        elif kind == "append":
            out[name] = bytes(data) + bytes(rng.randrange(256) for _ in range(rng.randrange(1, 8)))
        else:
            out[name] = b"{not json"
        return kind, out
    name = rng.choice([n for n in names if n.endswith(".json")])
    try:
        obj = json.loads(out[name].decode("utf-8"))
    except Exception:  # noqa: BLE001
        out[name] = b"{not json"
        return "json-garbage", out
    if kind == "json-type":
        paths = leaf_paths(obj)
        if not paths:
            out[name] = b"{}"
            return kind, out
        set_path(obj, rng.choice(paths), rng.choice(WRONG))
        out[name] = (json.dumps(obj, ensure_ascii=False, indent=2) + "\n").encode()
        return kind, out
    # manifest-delete: remove a required top-level field, then re-sign so the signature passes
    if "manifest.json" not in name:
        set_path(obj, rng.choice(leaf_paths(obj)), rng.choice(WRONG))
        out[name] = (json.dumps(obj, ensure_ascii=False, indent=2) + "\n").encode()
        return "json-type", out
    keys = [k for k in obj if k != "signatures"]
    if not keys:
        return kind, out
    del obj[rng.choice(keys)]
    obj.pop("signatures", None)
    obj["signatures"] = {"exporter": evidence.sign_domain(
        signing.Signer("exporter", EXPORTER_SEED), "manifest", obj)}
    out["manifest.json"] = (json.dumps(obj, ensure_ascii=False, indent=2) + "\n").encode()
    return kind, out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--iterations", type=int, default=200)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--pack", default=os.path.join(FIX, "normal"))
    ap.add_argument("--trust", default=os.path.join(FIX, "trust", "normal.json"))
    args = ap.parse_args()
    base = load_pack(args.pack)
    # fixture metadata (expected.json) is not part of the signed pack contract
    base.pop("expected.json", None)
    rng = random.Random(args.seed)
    failures = []
    counts = {}
    for i in range(args.iterations):
        kind, files = mutate(base, rng)
        work = tempfile.mkdtemp(prefix="agentbridge-fuzz.")
        pack = os.path.join(work, "pack")
        try:
            for rel, data in files.items():
                dest = os.path.join(pack, rel)
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                with open(dest, "wb") as f:
                    f.write(data)
            result = evidence.verify(pack, args.trust).to_dict(pack)
            code = result["exit_code"]
            counts[kind] = counts.get(kind, 0) + 1
            if code == 0:
                failures.append((i, kind, "reported fully valid (exit 0)"))
            elif code not in (1, 2, 3):
                failures.append((i, kind, f"unexpected exit {code}"))
            elif code != 3 and result["axes"]["integrity"]["status"] == "pass":
                failures.append((i, kind, "mutated signed material left integrity=pass"))
        except Exception as exc:  # noqa: BLE001 - a crash is a failure
            failures.append((i, kind, f"CRASH {type(exc).__name__}: {exc}"))
        finally:
            shutil.rmtree(work, ignore_errors=True)
    print(f"fuzz: {args.iterations} iterations, seed={args.seed}, mutations={counts}")
    for item in failures[:10]:
        print("  FAIL", item)
    print(f"{args.iterations - len(failures)}/{args.iterations} passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
