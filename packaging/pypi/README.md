# sbx-bin

The static [`sbx`](https://github.com/vdavamse/sbx) binary for Linux
(x86_64 and aarch64), packaged as a Python wheel, the same pattern as the
`ripgrep` wheel. `sbx` runs untrusted commands inside a locked-down Linux
sandbox; it needs `bwrap` (bubblewrap) on the host.

The package exposes the binary's path and nothing else:

```python
import subprocess
import sbx_bin

subprocess.run([sbx_bin.binary_path(), "check"], check=True)
```

The binary is the same fully static musl build attached to the matching
GitHub Release, which carries SHA256 checksums and build provenance
attestations (`gh attestation verify`).
