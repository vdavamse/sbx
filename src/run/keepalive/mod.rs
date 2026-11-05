//! Persistent session namespaces (issue #18).
//!
//! `sbx run --keep-alive` starts a session holder that keeps a resident command
//! and the session's namespaces, proxies, DNS map and audit writer alive.
//! `sbx attach` runs further commands inside those namespaces, and `sbx stop`
//! ends the session. Plain `sbx run` is unchanged and does not use this module.
//!
//! 1. **Lifetime** ([`limits`]). Idle timeout (default 15m), max lifetime
//!    (default 8h, hard cap 24h, rc 2 above it), and the pure clock that decides
//!    when a session ends.
//! 2. **Policy pin** ([`pin`]). A session admits only policy bytes identical to
//!    the bytes it started with. **Deviation:** pinned as the exact bytes, not a
//!    hash. The comparison is stricter, needs no digest crate, and costs one
//!    policy file of memory.
//! 3. **Protocol** ([`proto`]). Opcode-prefixed frames with a 256 KiB cap checked
//!    before allocation, strict per-opcode decoding, and a fixed outcome
//!    vocabulary. Descriptors travel with the frame header (SCM_RIGHTS, see
//!    [`ctl::send_frame`]). Any parse error drops the connection.
//! 4. **Control socket** ([`ctl`]). `sbx.ctl` is bound and connected through an
//!    `O_NOFOLLOW` directory fd. Only a stale socket of this user is replaced,
//!    and every connection is checked with `SO_PEERCRED`.
//! 5. **Join** ([`join`]). An unprivileged `setns` into the session's user
//!    namespace and then its network namespace, from a single-threaded child.
//!    **Deviation:** the descriptors are captured from `/proc/<init>/ns` while
//!    `__init` is parked before the go byte, not through a pidfd-anchored
//!    `setns`. The capture happens before bwrap execs (after exec the process's
//!    user namespace is bwrap's nested one). The result needs no Linux 5.8
//!    check, so the existing 5.3 floor is kept.
//! 6. **Holder** ([`holder`]). `run --keep-alive` forks, detaches with `setsid`,
//!    and reports readiness through a pipe. It serves the control socket from
//!    the supervisor loop, records each call's exit row (`call_id`), and on
//!    shutdown SIGTERMs the attached calls, then SIGKILLs stragglers after a
//!    grace period.
//! 7. **Attach and stop** ([`client`]). The attach handshake sends its pidfd and
//!    receives the holder's pidfd and the namespace descriptors. The attach then
//!    runs `__init --join-user --join-net`, which re-verifies the session's
//!    nftables ruleset in the joined namespace before the call's bwrap exec. An
//!    attach watches the holder's pidfd and tears its call down when the holder
//!    exits.
//!
//! **Kill paths.** A stop or an idle or max-lifetime end is a holder shutdown
//! (rule 6). A holder SIGKILL ends the resident through `__init`'s
//! `PR_SET_PDEATHSIG` and bwrap's `--die-with-parent`, and ends each attached
//! call through rule 7's pidfd watch. The stale `sbx.ctl` is replaced by the
//! next holder under the session lock.
//!
//! **Known limits of this slice.** Attach only works for transparent-mode
//! sessions: an explicit-mode session has no nftables rules for the join to
//! re-verify, so attach refuses it (rc 125, a fail-closed deviation). Join
//! failures use the existing `netns` and `nft-verify` stage names, because the
//! stage codes are pinned on the wire (deviation).

pub(crate) mod client;
pub(crate) mod ctl;
pub(crate) mod holder;
pub(crate) mod join;
pub(crate) mod limits;
pub(crate) mod pin;
pub(crate) mod proto;
