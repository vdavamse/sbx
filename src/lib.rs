//! sbx — run untrusted commands inside a locked-down Linux sandbox.
//!
//! The crate is split into a library and a thin binary so every piece of
//! logic (starting with CLI parsing) is unit-testable without spawning a
//! process. Later issues add modules alongside [`cli`] (proxy, dns, ...);
//! the binary surface stays a one-liner.
//!
//! Current status: the CLI parses the full documented interface; `check`
//! validates policy files against [`policy`]'s versioned schema and prints
//! the JSON Schema (issue #3); [`egress`] holds the two pure predicates
//! every egress decision will call — the domain allow-list matcher and the
//! resolved-address guard (issue #4); [`init`] is the real `sbx __init`
//! namespace child (issue #5) that `run` (#10) will re-exec: user+network
//! namespace unshare with single-id maps, loopback up as `10.255.255.1`
//! with a default route into the sandbox, IPv6 off, the spike-proven
//! nftables batch loaded atomically with post-load dump verification, three
//! listener fds handed to the parent over SCM_RIGHTS, a go byte, then
//! `exec` of the payload — plus the parent-side control-protocol
//! primitives ([`init::fdpass`]) #10 drives. `__init` setup failures are
//! staged (`sbx __init: <stage>: <reason>`, exit 1, payload never started);
//! success is silent. [`bwrap`] is the real launcher-argv builder (issue
//! #6): a pure, deterministic `build()` from a validated policy + session
//! directory to the complete unmodified-bwrap argv (allow-list mounts with
//! ancestor/priority ordering, `--clearenv` + explicit `--setenv`
//! environment, user/pid/ipc/uts/cgroup isolation, `--disable-userns`
//! hardening, synthetic `/etc`, session work/home/tmp), plus bwrap
//! discovery/version parsing; #10 spawns it via `Launch::command()` (which
//! encodes the `env_clear` contract).
//! [`dns`] is the fake-IP resolver (issue #9): it serves `__init`'s handed-off
//! UDP :53 fd, answers A for allow-listed names from `198.18.0.0/15` (a stable
//! per-run [`dns::FakeIpMap`], also the proxy's [`proxy::DnsMap`]), NODATA for
//! other types, NXDOMAIN for every other name, and never forwards; one
//! [`dns::DnsDecision`] per datagram goes to the [`dns::DnsSink`] seam (#10).
//! [`proxy`] is the real transparent
//! egress proxy (issue #7) and its explicit counterpart (issue #8, served
//! by [`proxy::serve_explicit`]; `CONNECT` and absolute-form requests on
//! the explicit listener, same policy and inspectors): it serves #5's
//! handed-off transparent listener fd, recovers the dialed destination via
//! `SO_ORIGINAL_DST`, maps fake IPs back to names through the
//! [`proxy::DnsMap`] seam (#9), enforces the
//! policy's port + domain allow-lists, and inspects WITHOUT terminating the
//! protocol preamble — TLS `ClientHello` SNI on 443 (rustls's `Acceptor`
//! with NO crypto provider; ECH denied) and the HTTP request line + `Host`
//! on 80 — then resolves and dials BY NAME under [`egress::guard`] (every
//! resolved address, plus the connected `peer_addr()` re-check as the
//! DNS-rebinding backstop), replays the buffered bytes, and relays
//! bidirectionally — the validated name binding enforced for the whole
//! connection lifetime: on 80 the validated head is replayed with an
//! inserted `Connection: close` (a keep-alive foreign-`Host` follow-up
//! cannot ride the relay), and on 443 the client→upstream bytes stay
//! watched by the relay-phase scanner — a SECOND `ClientHello` (the
//! post-HRR retry shape) tears the connection down, within the recorded
//! residuals the library module docs list honestly (e.g. an ENCRYPTED
//! renegotiation hello — invisible to any non-terminating proxy). Every
//! connection ends in exactly one [`proxy::Decision`] recorded to the
//! [`proxy::DecisionSink`] seam (#10) with the pinned deny vocabulary —
//! whose `teardown` hook surfaces relay-phase teardowns so a blocked
//! attack is not audit-invisible; everything fails closed. [`policy`]
//! deserialization now validates on EVERY path — the old point-5 asymmetry
//! is resolved (TODO(#6)(a), landed with issue #6). `run` is real since
//! issue #10 (see [`run`]: the sandbox lifecycle, exit codes, audit log);
//! [`gc`] (issue #12) removes expired session directories under a lock, via a
//! tombstone rename and a fd-bounded walker that never follows symlinks or
//! crosses mounts. `check` (issue #11) reports the host:
//! [`host`] classifies what the sandbox needs (user namespaces, the
//! nftables redirect, bwrap, …) from a probe that runs the very same setup
//! stages, and `run` shares that classifier for its refusals (rc 125).
//! [`conformance`] (issue #13) is `sbx check --conformance`: every security
//! guarantee as an executable check (69 checks, eight groups). Its host and
//! init tiers are real in this build; the lab and network tiers land in a
//! follow-up PR and report `not implemented` until then.
//! Tracking issue #20 describes the architecture; the
//! issue #1 spike (`spikes/nft-load`) proved the unprivileged
//! nftables-loading approach `sbx __init` ships.

pub mod bwrap;
pub mod cli;
pub mod conformance;
pub mod dns;
pub mod egress;
pub mod gc;
pub mod host;
pub mod init;
pub mod policy;
pub mod proxy;
pub mod run;
