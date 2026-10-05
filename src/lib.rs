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
//! resolved-address guard (issue #4); [`init`] is growing the `sbx __init`
//! namespace child (issue #5) — so far the staged error vocabulary and the
//! control-socket protocol ([`init::fdpass`]: SCM_RIGHTS fd hand-off + go
//! byte, parent and child sides) that `run` (#10) will drive. `run`, `gc`
//! and the internal `__init` helper remain stubs that exit 1. Tracking
//! issue #20 describes the architecture; the issue #1 spike
//! (`spikes/nft-load`) proved the unprivileged nftables-loading approach
//! that `sbx __init` will use.

pub mod cli;
pub mod egress;
pub mod init;
pub mod policy;
