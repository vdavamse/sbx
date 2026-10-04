//! sbx — run untrusted commands inside a locked-down Linux sandbox.
//!
//! The crate is split into a library and a thin binary so every piece of
//! logic (starting with CLI parsing) is unit-testable without spawning a
//! process. Later issues add modules alongside [`cli`] (policy, init,
//! proxy, dns, bwrap, ...); the binary surface stays a one-liner.
//!
//! Current status (issue #2): skeleton only — the CLI parses the full
//! documented interface, but every subcommand is a stub that exits 1.
//! Tracking issue #20 describes the architecture; the issue #1 spike
//! (`spikes/nft-load`) proved the unprivileged nftables-loading approach
//! that the hidden `sbx __init` helper will use.

pub mod cli;
pub mod policy;
