#!/usr/bin/env python3
"""Rebuild the vectors into a temp dir and require byte-identical files to the saved vectors."""
import hashlib
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FIX = os.path.join(ROOT, "docs", "fixtures", "evidence-pack-v0")


def tree_hash(root):
    out = {}
    for dirpath, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d != "schema-invalid"]
        for name in files:
            path = os.path.join(dirpath, name)
            rel = os.path.relpath(path, root)
            out[rel] = hashlib.sha256(open(path, "rb").read()).hexdigest()
    return out


def main() -> int:
    saved = tree_hash(FIX)
    with tempfile.TemporaryDirectory() as tmp:
        subprocess.run([sys.executable, os.path.join(HERE, "make_pack_fixtures.py"),
                        "--out", tmp], check=True, cwd=ROOT)
        rebuilt = tree_hash(tmp)
    missing = sorted(set(saved) - set(rebuilt))
    extra = sorted(set(rebuilt) - set(saved))
    changed = sorted(k for k in saved if k in rebuilt and saved[k] != rebuilt[k])
    print(f"saved={len(saved)} rebuilt={len(rebuilt)} missing={len(missing)} "
          f"extra={len(extra)} changed={len(changed)}")
    for label, items in (("missing", missing), ("extra", extra), ("changed", changed)):
        for item in items[:10]:
            print(f"  {label}: {item}")
    return 1 if (missing or extra or changed) else 0


if __name__ == "__main__":
    sys.exit(main())
