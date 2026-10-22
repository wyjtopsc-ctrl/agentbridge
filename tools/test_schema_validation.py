#!/usr/bin/env python3
"""Regression wrapper: Ajv schema validation of real and invalid manifests."""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def main() -> int:
    env = dict(os.environ)  # validate_schema.js resolves tools/node_modules first
    proc = subprocess.run(["node", os.path.join(HERE, "validate_schema.js")],
                          cwd=ROOT, env=env, capture_output=True, text=True)
    print(proc.stdout.strip())
    if proc.returncode != 0:
        print(proc.stderr.strip())
    return proc.returncode


if __name__ == "__main__":
    sys.exit(main())
