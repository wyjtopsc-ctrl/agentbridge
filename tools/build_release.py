#!/usr/bin/env python3
"""Assemble the release: wheel, source tarball, documentation, checksums, zip.

The project's normal build path is `python -m build`; this script exists because the build
backend stalled in the packaging environment, and a wheel is a simple enough format to write
directly. It produces the same layout (`agentbridge/<pkg>`, `*.dist-info/`), so the result is a
valid wheel — verified by installing it into a fresh virtualenv.

  python3 tools/build_release.py
"""
from __future__ import annotations

import base64
import hashlib
import os
import shutil
import tarfile
import tempfile
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
NAME = "agentbridge"


def product_version() -> str:
    import re
    text = open(os.path.join(ROOT, "src", "agentbridge", "__init__.py"), encoding="utf-8").read()
    return re.search(r'__version__\s*=\s*"([^"]+)"', text).group(1)


VERSION = product_version()
DIST = os.path.join(ROOT, "dist")
DELIVERABLES = os.path.join(ROOT, "deliverables")
RELEASE = os.path.join(DELIVERABLES, f"{NAME}-{VERSION}-release")
IGNORE = shutil.ignore_patterns("__pycache__", "*.pyc", ".venv", "dist", "deliverables",
                                "wire", "ledger.jsonl", ".dsh-office*", "node_modules")
TEST_IGNORE = shutil.ignore_patterns("__pycache__", "*.pyc", ".venv", "node_modules")


def sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def read(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def build_wheel() -> str:
    os.makedirs(DIST, exist_ok=True)
    wheel_path = os.path.join(DIST, f"{NAME}-{VERSION}-py3-none-any.whl")
    src = os.path.join(ROOT, "src")
    dist_info = f"{NAME}-{VERSION}.dist-info"

    metadata_lines = [
        "Metadata-Version: 2.1",
        f"Name: {NAME}",
        f"Version: {VERSION}",
        "Summary: Verifiable delivery between autonomous agents: hash-chained commitments, "
        "content-addressed artifacts, external anchors.",
        "Home-page: https://example.invalid/agentbridge",
        "License: MIT",
        "Requires-Python: >=3.9",
        "Description-Content-Type: text/markdown",
        "Classifier: Development Status :: 3 - Alpha",
        "Classifier: Intended Audience :: Developers",
        "Classifier: License :: OSI Approved :: MIT License",
        "Classifier: Programming Language :: Python :: 3",
        "Classifier: Topic :: Security",
        "",
        read(os.path.join(ROOT, "README.md")).decode("utf-8"),
    ]
    wheel_meta = ["Wheel-Version: 1.0", "Generator: agentbridge-build-release",
                  "Root-Is-Purelib: true", "Tag: py3-none-any", ""]
    entry_points = "[console_scripts]\nagentbridge = agentbridge.cli:main\n"

    records: list[str] = []

    def add(zf, arc: str, data: bytes):
        zf.writestr(arc, data)
        digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
        records.append(f"{arc},sha256={digest},{len(data)}")

    with zipfile.ZipFile(wheel_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for dirpath, dirnames, filenames in os.walk(src):
            dirnames[:] = [d for d in dirnames if d != "__pycache__"]
            for filename in sorted(filenames):
                if filename.endswith(".pyc"):
                    continue
                full = os.path.join(dirpath, filename)
                arc = os.path.relpath(full, src).replace(os.sep, "/")
                add(zf, arc, read(full))
        add(zf, f"{dist_info}/METADATA", ("\n".join(metadata_lines) + "\n").encode("utf-8"))
        add(zf, f"{dist_info}/WHEEL", ("\n".join(wheel_meta) + "\n").encode("utf-8"))
        add(zf, f"{dist_info}/entry_points.txt", entry_points.encode("utf-8"))
        add(zf, f"{dist_info}/top_level.txt", b"agentbridge\n")
        records.append(f"{dist_info}/RECORD,,")
        zf.writestr(f"{dist_info}/RECORD", ("\n".join(records) + "\n").encode("utf-8"))
    print(f"wheel  {wheel_path}  ({os.path.getsize(wheel_path)} B)")
    return wheel_path


def build_sdist() -> str:
    os.makedirs(DIST, exist_ok=True)
    sdist_path = os.path.join(DIST, f"{NAME}-{VERSION}.tar.gz")
    staging = tempfile.mkdtemp(prefix="agentbridge-sdist.")
    top = os.path.join(staging, f"{NAME}-{VERSION}")
    os.makedirs(top, exist_ok=True)
    try:
        include = ["pyproject.toml", "setup.py", "README.md", "LICENSE", "CHANGELOG.md",
                   "src", "tests", "docs", "examples", "tools"]
        for name in include:
            src = os.path.join(ROOT, name)
            if not os.path.exists(src):
                continue
            if os.path.isdir(src):
                # tests/ carries a frozen golden bridge (wire/ + ledger.jsonl); the
                # bridge-runtime ignore rules must not strip it from the sdist.
                ignore = TEST_IGNORE if name == "tests" else IGNORE
                shutil.copytree(src, os.path.join(top, name), ignore=ignore)
            else:
                shutil.copy2(src, os.path.join(top, name))
        with tarfile.open(sdist_path, "w:gz") as tar:
            tar.add(top, arcname=f"{NAME}-{VERSION}")
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    print(f"sdist  {sdist_path}  ({os.path.getsize(sdist_path)} B)")
    return sdist_path


def build_release(wheel: str, sdist: str) -> str:
    if os.path.isdir(RELEASE):
        shutil.rmtree(RELEASE)
    os.makedirs(os.path.join(RELEASE, "dist"))
    os.makedirs(os.path.join(RELEASE, "docs"))
    for name in ("README.md", "LICENSE", "CHANGELOG.md"):
        shutil.copy2(os.path.join(ROOT, name), os.path.join(RELEASE, name))
    shutil.copy2(wheel, os.path.join(RELEASE, "dist"))
    shutil.copy2(sdist, os.path.join(RELEASE, "dist"))
    for name in (f"agentbridge-whitepaper-{VERSION}.docx", f"agentbridge-whitepaper-{VERSION}.pdf",
                 f"agentbridge-manual-{VERSION}.docx", f"agentbridge-manual-{VERSION}.pdf",
                 f"agentbridge-security-deck-{VERSION}.pptx",
                 f"agentbridge-security-deck-{VERSION}.pdf"):
        shutil.copy2(os.path.join(DELIVERABLES, name), os.path.join(RELEASE, "docs"))
    for name in ("protocol.md", "threat-model.md", "mcp.md", "transport.md", "anchors.md"):
        shutil.copy2(os.path.join(ROOT, "docs", name), os.path.join(RELEASE, "docs"))

    lines = []
    for dirpath, dirnames, filenames in os.walk(RELEASE):
        dirnames.sort()
        for filename in sorted(filenames):
            if filename == "SHA256SUMS":
                continue
            path = os.path.join(dirpath, filename)
            rel = os.path.relpath(path, RELEASE)
            lines.append(f"{sha256(path)}  {rel}")
    with open(os.path.join(RELEASE, "SHA256SUMS"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print(f"release {RELEASE}  ({len(lines)} files)")
    return RELEASE


def zip_release() -> str:
    zip_path = os.path.join(DELIVERABLES, f"{NAME}-{VERSION}-release.zip")
    if os.path.exists(zip_path):
        os.unlink(zip_path)
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for dirpath, dirnames, filenames in os.walk(RELEASE):
            dirnames.sort()
            for filename in sorted(filenames):
                full = os.path.join(dirpath, filename)
                arc = os.path.relpath(full, DELIVERABLES)
                zf.write(full, arc)
    print(f"zip    {zip_path}  ({os.path.getsize(zip_path)} B)")
    return zip_path


if __name__ == "__main__":
    wheel = build_wheel()
    sdist = build_sdist()
    build_release(wheel, sdist)
    zip_release()
