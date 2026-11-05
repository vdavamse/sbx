"""The static ``sbx`` binary, bundled (issue #16).

This package exposes the binary's path and nothing else; run it with any
process API, for example ``subprocess.run([sbx_bin.binary_path(), "--version"])``.
"""

from pathlib import Path

__all__ = ["binary_path"]


def binary_path() -> str:
    """Absolute path of the bundled static ``sbx`` executable."""
    return str(Path(__file__).resolve().parent / "sbx")
