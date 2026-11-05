//! Persistent session namespaces (issue #18): the control-plane foundation.
//!
//! **Status.** This module is the first slice of #18. It is not reachable from
//! the CLI yet: `sbx run --keep-alive`, `sbx attach` and `sbx stop` are not
//! implemented, and no user-visible behaviour changed. The pieces are unit
//! tested here and the join is exercised by a namespace test (`join`). The
//! holder, the attach path and the conformance checks are the next slices.
//!
//! 1. **Lifetime** ([`limits`]). Idle timeout (default 15m), max lifetime
//!    (default 8h, hard cap 24h, rc 2 above it), and the pure clock that decides
//!    when a session ends.
//! 2. **Policy pin** ([`pin`]). A session admits only policy bytes identical to
//!    the bytes it started with. Pinned as bytes, not a hash (see `pin` rule 1).
//! 3. **Protocol** ([`proto`]). Length-prefixed frames with a 256 KiB cap checked
//!    before allocation, strict per-opcode decoding, and a fixed outcome
//!    vocabulary. Any parse error drops the connection.
//! 4. **Control socket** ([`ctl`]). `sbx.ctl` is bound and connected through an
//!    `O_NOFOLLOW` directory fd. Only a stale socket of this user is replaced,
//!    and every connection is checked with `SO_PEERCRED`.
//! 5. **Join** ([`join`]). Unprivileged `setns` into the session's user and
//!    network namespaces, user first, from a single-threaded child.
//!
//! Nothing here touches the holder's audit file, bwrap or `__init`; those
//! change only when the holder and attach land.

// The consumers (holder, attach, stop) land in the follow-up slices; until
// then the non-test build has no caller for these items.
#![allow(dead_code)]

pub(crate) mod ctl;
pub(crate) mod join;
pub(crate) mod limits;
pub(crate) mod pin;
pub(crate) mod proto;
