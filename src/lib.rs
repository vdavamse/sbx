//! sbx — run untrusted commands inside a locked-down Linux sandbox.
//!
//! The crate is split into a library and a thin binary so every piece of
//! logic (starting with CLI parsing) is unit-testable without spawning a
//! process. Later issues add modules alongside [`cli`] (policy, init,
//! proxy, dns, bwrap, ...); the binary surface stays a one-liner.
//!
//! Current status: the CLI parses the full documented interface; `check`
//! validates policy files against [`policy`]'s versioned schema and prints
//! the JSON Schema (issue #3), while `run`, `gc` and the internal `__init`
//! helper remain stubs that exit 1. Tracking issue #20 describes the
//! architecture; the issue #1 spike (`spikes/nft-load`) proved the
//! unprivileged nftables-loading approach that `sbx __init` will use.

pub mod cli;
pub mod policy;
