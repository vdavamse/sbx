#!/usr/bin/env python3
"""Build the ``sbx-bin`` platform wheel around a prebuilt static binary.

Issue #16: the same pattern as the ``ripgrep`` wheel. The wheel holds the
``sbx_bin`` package (``binary_path()`` only) and the static musl binary next
to it. No build backend: a wheel is a zip with three metadata files, and
writing it directly keeps the release job free of third-party build tooling.

Stdlib only. Deterministic: every entry gets the same timestamp
(``SOURCE_DATE_EPOCH``, default 1980-01-01), sorted order and fixed modes,
so rebuilding from the same inputs with the same Python (zlib) yields a
byte-identical wheel.

Usage:
  build_wheel.py --binary target/x86_64-unknown-linux-musl/release/sbx \\
      --target x86_64-unknown-linux-musl --version 0.1.0 --out dist/
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import os
import re
import sys
import time
import zipfile
from pathlib import Path

DIST_NAME = "sbx-bin"
IMPORT_NAME = "sbx_bin"
HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent.parent

# The binary is fully static (no libc dependency), so it runs on every
# glibc and musl distribution of the architecture. manylinux2014 is the
# oldest tag pip still prefers; musllinux_1_1 covers Alpine.
PLATFORM_TAGS = {
    "x86_64-unknown-linux-musl": [
        "manylinux_2_17_x86_64",
        "manylinux2014_x86_64",
        "musllinux_1_1_x86_64",
    ],
    "aarch64-unknown-linux-musl": [
        "manylinux_2_17_aarch64",
        "manylinux2014_aarch64",
        "musllinux_1_1_aarch64",
    ],
}

# Cargo SemVer pre-release -> PEP 440 (the only shapes this project tags).
_PRE = {"alpha": "a", "beta": "b", "rc": "rc"}
_SEMVER = re.compile(r"^(\d+)\.(\d+)\.(\d+)(?:-(alpha|beta|rc)\.(\d+))?$")


def pep440_version(cargo_version: str) -> str:
    """Map a Cargo version to PEP 440; reject shapes with no clean mapping."""
    m = _SEMVER.match(cargo_version)
    if not m:
        raise ValueError(
            f"unsupported version {cargo_version!r}: expected X.Y.Z or "
            "X.Y.Z-(alpha|beta|rc).N"
        )
    major, minor, patch, pre, num = m.groups()
    base = f"{major}.{minor}.{patch}"
    return base + (f"{_PRE[pre]}{num}" if pre else "")


def _record_hash(data: bytes) -> str:
    digest = hashlib.sha256(data).digest()
    return "sha256=" + base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def _metadata(version: str) -> str:
    readme = (HERE / "README.md").read_text(encoding="utf-8")
    headers = [
        "Metadata-Version: 2.4",
        f"Name: {DIST_NAME}",
        f"Version: {version}",
        "Summary: The static sbx sandbox binary for Linux; exposes its path and nothing else",
        "License-Expression: Apache-2.0",
        "License-File: LICENSE",
        "Requires-Python: >=3.8",
        "Project-URL: Source, https://github.com/vdavamse/sbx",
        "Classifier: Operating System :: POSIX :: Linux",
        "Classifier: Topic :: Security",
        "Description-Content-Type: text/markdown",
    ]
    return "\n".join(headers) + "\n\n" + readme


def _wheel_file(tags: list[str]) -> str:
    lines = [
        "Wheel-Version: 1.0",
        "Generator: sbx packaging/pypi/build_wheel.py",
        "Root-Is-Purelib: false",
    ]
    lines += [f"Tag: py3-none-{tag}" for tag in tags]
    return "\n".join(lines) + "\n"


def wheel_name(version: str, target: str) -> str:
    tags = ".".join(PLATFORM_TAGS[target])
    return f"{IMPORT_NAME}-{version}-py3-none-{tags}.whl"


def build(binary: Path, target: str, cargo_version: str, out: Path, epoch: int) -> Path:
    """Write the wheel into ``out`` and return its path."""
    if target not in PLATFORM_TAGS:
        raise ValueError(f"unsupported target {target!r}")
    version = pep440_version(cargo_version)
    dist_info = f"{IMPORT_NAME}-{version}.dist-info"
    # (archive path, bytes, unix mode) — RECORD is appended last.
    files = [
        (f"{IMPORT_NAME}/__init__.py", (HERE / IMPORT_NAME / "__init__.py").read_bytes(), 0o644),
        (f"{IMPORT_NAME}/sbx", binary.read_bytes(), 0o755),
        (f"{dist_info}/METADATA", _metadata(version).encode(), 0o644),
        (f"{dist_info}/WHEEL", _wheel_file(PLATFORM_TAGS[target]).encode(), 0o644),
        (f"{dist_info}/licenses/LICENSE", (REPO_ROOT / "LICENSE").read_bytes(), 0o644),
    ]
    # Package files first, then .dist-info (the wheel spec recommends the
    # metadata last); sorted within each group.
    files.sort(key=lambda f: (f[0].startswith(dist_info), f[0]))
    record = "".join(f"{name},{_record_hash(data)},{len(data)}\n" for name, data, _ in files)
    record += f"{dist_info}/RECORD,,\n"
    files.append((f"{dist_info}/RECORD", record.encode(), 0o644))

    # zip timestamps cannot predate 1980.
    stamp = time.gmtime(max(epoch, 315532800))[:6]
    out.mkdir(parents=True, exist_ok=True)
    path = out / wheel_name(version, target)
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, data, mode in files:
            info = zipfile.ZipInfo(name, date_time=stamp)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3  # Unix: honour external_attr modes
            info.external_attr = (0o100000 | mode) << 16
            zf.writestr(info, data)
    return path


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--binary", type=Path, required=True)
    p.add_argument("--target", required=True, choices=sorted(PLATFORM_TAGS))
    p.add_argument("--version", required=True, help="Cargo package version")
    p.add_argument("--out", type=Path, required=True)
    args = p.parse_args(argv)
    epoch = int(os.environ.get("SOURCE_DATE_EPOCH", "315532800"))
    path = build(args.binary, args.target, args.version, args.out, epoch)
    print(path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
