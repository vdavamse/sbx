# TLS termination (opt-in build feature)

The default binary never terminates TLS. A policy can opt specific hosts in,
so that sbx can enforce URL-path rules for them. The feature is compiled in
only when you ask for it:

```sh
cargo build --release --features tls-termination
```

A policy with `network.mitm_hosts` or `network.paths` is refused by the
default binary: `sbx check --policy` exits 1 and `sbx run` exits 125, with the
message `network.mitm_hosts requires an sbx built with the tls-termination
feature`. The opt-in policy looks like this:

```json
"network": {
  "mode": "transparent",
  "allow": ["=api.example.com"],
  "ports": [443],
  "mitm_hosts": ["api.example.com"],
  "paths": ["https://api.example.com/v1/"]
}
```

- **Scope.** Only the `mitm_hosts` names are terminated, and each must be an
  exact name that is reachable on port 443 and that `allow` covers with exact
  rules only (`=api.example.com`). A subdomain rule such as `example.com` is
  refused, because it would also allow passthrough names (`www.example.com`)
  that a shared CDN or load balancer can route to the terminated host by
  `Host`, past the path rules. Every other host stays a byte-for-byte TLS
  passthrough. Path rules hold only for connections whose SNI is the
  terminated name: another allowed name served by the same edge can still
  carry its `Host` (threat model R1). A `paths` rule applies to
  one host and matches the request path at a segment boundary: a rule ending
  in `/` covers everything below it.
- **Per-run CA, key custody.** `sbx run` creates a CA in memory for each run.
  Its certificate is written into the session directory and bound read-only at
  `/etc/sbx/ca.pem` and `/etc/sbx/ca-bundle.pem`. The bundle also holds the
  host's trust roots. `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`,
  `GIT_SSL_CAINFO`, `CARGO_HTTP_CAINFO` and `NODE_EXTRA_CA_CERTS` point at
  them, and policy `env` cannot override these. The private key never touches
  disk, the sandbox, the bwrap argv or the environment, and `sbx run` marks
  itself non-dumpable (and sets `RLIMIT_CORE` to 0) before creating it, so no
  core file readable by the invoking user can hold it. The CA
  is valid for the run timeout plus one hour (for a `--keep-alive` session, its
  max lifetime plus one hour), capped at 24 hours. Its name constraints permit
  exactly the `mitm_hosts` names, not their subdomains. A run is refused when
  no host CA bundle is found (`/etc/ssl/certs/ca-certificates.crt`,
  `/etc/pki/tls/certs/ca-bundle.crt` or `/etc/ssl/cert.pem`), since the bundle
  would then break every passthrough HTTPS host.
- **Upstream.** The upstream certificate is verified against the Mozilla root
  set, with the policy host name. Verification is never disabled, and there is
  no plaintext fallback. A failed handshake returns `502` over TLS.
- **Per request.** The request `Host` must equal the SNI, and its path must
  match a rule. Paths are printable ASCII with no `%`, `;`, `\` or dot
  segments. URL-override headers (`X-Original-URL`, `X-Rewrite-URL` and kin)
  are refused. Anything else is answered `403` (path) or `400` (request shape)
  over TLS. The path rule also depends on the upstream honoring the request's
  framing (`Content-Length`, `Connection: close`).
- **Costs.** Certificate-pinned upstreams and upstreams that need a client
  certificate fail for terminated hosts. The client protocol is HTTP/1.1 only,
  so an HTTP/2-only client fails the handshake. Each connection carries one
  request, with no keep-alive, and chunked request bodies and protocol
  upgrades are denied. Plain HTTP on port 80 to a terminated host is denied.
  Programs that ignore the trust variables reject the CA, which fails closed.
  Residuals are in the [threat model](threat-model.md) (R37, S25, S26).
