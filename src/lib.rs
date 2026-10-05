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
//! encodes the `env_clear` contract). [`proxy`] is the real transparent
//! egress proxy (issue #7): it serves #5's handed-off transparent listener
//! fd, recovers the dialed destination via `SO_ORIGINAL_DST`, maps fake IPs
//! back to names through the [`proxy::DnsMap`] seam (#9), enforces the
//! policy's port + domain allow-lists, and inspects WITHOUT terminating the
//! protocol preamble — TLS `ClientHello` SNI on 443 (rustls's `Acceptor`
//! with NO crypto provider; ECH denied) and the HTTP request line + `Host`
//! on 80 — then resolves and dials BY NAME under [`egress::guard`] (every
//! resolved address, plus the connected `peer_addr()` re-check as the
//! DNS-rebinding backstop), replays the buffered bytes, and relays
//! bidirectionally. Every connection ends in exactly one
//! [`proxy::Decision`] recorded to the [`proxy::DecisionSink`] seam (#10)
//! with the pinned deny vocabulary; everything fails closed. [`policy`]
//! deserialization now validates on EVERY path — the old point-5 asymmetry
//! is resolved (TODO(#6)(a), landed with issue #6). `run` and `gc` remain
//! stubs that exit 1. Tracking issue #20 describes the architecture; the
//! issue #1 spike (`spikes/nft-load`) proved the unprivileged
//! nftables-loading approach `sbx __init` ships.

pub mod bwrap;
pub mod cli;
pub mod egress;
pub mod init;
pub mod policy;
pub mod proxy;
