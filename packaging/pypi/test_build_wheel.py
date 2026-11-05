#!/usr/bin/env python3
"""Unit tests for build_wheel.py (stdlib unittest; run directly).

  python3 packaging/pypi/test_build_wheel.py
"""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import stat
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import build_wheel as bw  # noqa: E402

TARGET = "x86_64-unknown-linux-musl"


class VersionTests(unittest.TestCase):
    def test_release_and_prerelease_map_to_pep440(self):
        self.assertEqual(bw.pep440_version("0.1.0"), "0.1.0")
        self.assertEqual(bw.pep440_version("1.2.3-alpha.1"), "1.2.3a1")
        self.assertEqual(bw.pep440_version("1.2.3-beta.2"), "1.2.3b2")
        self.assertEqual(bw.pep440_version("1.2.3-rc.10"), "1.2.3rc10")

    def test_unmappable_versions_rejected(self):
        for bad in ["1.2", "1.2.3-rc", "1.2.3-dev.1", "1.2.3+build", "v1.2.3", ""]:
            with self.assertRaises(ValueError, msg=bad):
                bw.pep440_version(bad)


class WheelTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        # A stand-in "binary": a shell script, so the install smoke can exec it.
        self.binary = self.dir / "sbx"
        self.binary.write_text("#!/bin/sh\necho sbx-fake \"$@\"\n")

    def tearDown(self):
        self.tmp.cleanup()

    def build(self, out="out", epoch=1700000000, target=TARGET):
        return bw.build(self.binary, target, "0.1.0", self.dir / out, epoch)

    def test_name_and_tags(self):
        path = self.build()
        self.assertEqual(
            path.name,
            "sbx_bin-0.1.0-py3-none-manylinux_2_17_x86_64.manylinux2014_x86_64"
            ".musllinux_1_1_x86_64.whl",
        )
        with zipfile.ZipFile(path) as zf:
            wheel = zf.read("sbx_bin-0.1.0.dist-info/WHEEL").decode()
        self.assertIn("Root-Is-Purelib: false", wheel)
        for tag in bw.PLATFORM_TAGS[TARGET]:
            self.assertIn(f"Tag: py3-none-{tag}\n", wheel)

    def test_contents_modes_and_record(self):
        path = self.build()
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()
            self.assertEqual(
                names[:2], ["sbx_bin/__init__.py", "sbx_bin/sbx"], "package files first"
            )
            self.assertTrue(
                all(n.startswith("sbx_bin-0.1.0.dist-info/") for n in names[2:]),
                ".dist-info last",
            )
            self.assertEqual(sorted(names[2:-1]), names[2:-1], "sorted within groups")
            self.assertEqual(names[-1], "sbx_bin-0.1.0.dist-info/RECORD")
            self.assertEqual(
                set(names),
                {
                    "sbx_bin/__init__.py",
                    "sbx_bin/sbx",
                    "sbx_bin-0.1.0.dist-info/METADATA",
                    "sbx_bin-0.1.0.dist-info/WHEEL",
                    "sbx_bin-0.1.0.dist-info/licenses/LICENSE",
                    "sbx_bin-0.1.0.dist-info/RECORD",
                },
            )
            mode = zf.getinfo("sbx_bin/sbx").external_attr >> 16
            self.assertTrue(stat.S_ISREG(mode))
            self.assertEqual(stat.S_IMODE(mode), 0o755)
            # Every RECORD hash and size matches the stored bytes.
            rows = zf.read(names[-1]).decode().splitlines()
            self.assertEqual(rows[-1], "sbx_bin-0.1.0.dist-info/RECORD,,")
            for row in rows[:-1]:
                name, digest, size = row.split(",")
                data = zf.read(name)
                want = base64.urlsafe_b64encode(hashlib.sha256(data).digest())
                self.assertEqual(digest, "sha256=" + want.rstrip(b"=").decode(), name)
                self.assertEqual(int(size), len(data), name)
            self.assertEqual(zf.read("sbx_bin/sbx"), self.binary.read_bytes())

    def test_metadata(self):
        with zipfile.ZipFile(self.build()) as zf:
            meta = zf.read("sbx_bin-0.1.0.dist-info/METADATA").decode()
        self.assertTrue(meta.startswith("Metadata-Version: 2.4\nName: sbx-bin\nVersion: 0.1.0\n"))
        self.assertIn("License-Expression: Apache-2.0\n", meta)
        self.assertIn("License-File: LICENSE\n", meta)

    def test_deterministic(self):
        a = self.build("a").read_bytes()
        b = self.build("b").read_bytes()
        self.assertEqual(a, b)
        self.assertNotEqual(a, self.build("c", epoch=1800000000).read_bytes())

    def test_unknown_target_rejected(self):
        with self.assertRaises(ValueError):
            self.build(target="x86_64-unknown-linux-gnu")

    def test_installed_package_exposes_only_binary_path(self):
        # Unpack the wheel like an installer would and import the package.
        path = self.build()
        site = self.dir / "site"
        with zipfile.ZipFile(path) as zf:
            zf.extractall(site)
            (site / "sbx_bin" / "sbx").chmod(zf.getinfo("sbx_bin/sbx").external_attr >> 16 & 0o777)
        spec = importlib.util.spec_from_file_location("sbx_bin", site / "sbx_bin" / "__init__.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        self.assertEqual(mod.__all__, ["binary_path"])
        exe = mod.binary_path()
        self.assertEqual(Path(exe), (site / "sbx_bin" / "sbx").resolve())
        out = subprocess.run([exe, "--version"], capture_output=True, text=True, check=True)
        self.assertEqual(out.stdout.strip(), "sbx-fake --version")


if __name__ == "__main__":
    unittest.main()
