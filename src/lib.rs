//! sbx — run untrusted commands inside a locked-down Linux sandbox.
//!
//! The crate is split into a library and a thin binary so every piece of
//! logic (starting with CLI parsing) is unit-testable without spawning a
//! process. Later issues add modules alongside [`cli`] (proxy, dns, bwrap,
//! ...); the binary surface stays a one-liner.
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
//! success is silent. `run` and `gc` remain stubs that exit 1. Tracking
//! issue #20 describes the architecture; the issue #1 spike
//! (`spikes/nft-load`) proved the unprivileged nftables-loading approach
//! `sbx __init` ships.

pub mod cli;
pub mod egress;
pub mod init;
pub mod policy;
