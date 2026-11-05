//! Session lifetime limits (issue #18, design point 3).
//!
//! 1. **Defaults and cap.** `--idle-timeout` defaults to 15 minutes and
//!    `--max-lifetime` to 8 hours. `--max-lifetime` is hard-capped at 24 hours:
//!    a larger value is a usage error (rc 2), refused by the clap value parser
//!    so no session is ever started with it. Both are CLI flags only.
//! 2. **Idle.** A session is idle while no attached call is running. The idle
//!    clock starts when the session starts and restarts each time the last
//!    running call ends. Reaching `idle` while idle ends the session.
//! 3. **Max lifetime.** `max` counts from the holder's start and ends the
//!    session whether or not calls are running. When both limits are reached
//!    at the same instant the reason is [`EndReason::MaxLifetime`].
//! 4. **Pure and clock-injected.** [`Clock`] takes every instant as an argument,
//!    so the state machine is unit-tested without sleeping. The holder polls
//!    on [`Clock::next_deadline`] and asks [`Clock::expired`] when it wakes.

use std::time::{Duration, Instant};

/// `--idle-timeout` when the flag is absent.
pub(crate) const DEFAULT_IDLE: Duration = Duration::from_secs(15 * 60);
/// `--max-lifetime` when the flag is absent.
pub(crate) const DEFAULT_MAX_LIFETIME: Duration = Duration::from_secs(8 * 60 * 60);
/// The hard cap on `--max-lifetime`. No flag, policy field or environment
/// variable raises it.
pub(crate) const MAX_LIFETIME_CAP: Duration = Duration::from_secs(24 * 60 * 60);

/// Why a session ends on its own (the holder's teardown reason).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EndReason {
    /// No attached call ran for the idle timeout.
    Idle,
    /// The max lifetime elapsed.
    MaxLifetime,
}

/// The clap value parser for `--max-lifetime`: a positive duration not above
/// [`MAX_LIFETIME_CAP`]. A refusal is a usage error (rc 2) by clap's convention,
/// and the message echoes the caller's text.
pub fn parse_max_lifetime(s: &str) -> Result<Duration, String> {
    let d = crate::cli::parse_duration(s)?;
    if d > MAX_LIFETIME_CAP {
        return Err(format!("--max-lifetime must not exceed 24h (got {s})"));
    }
    Ok(d)
}

/// The lifetime state of one session: when it started, how many calls run, and
/// since when the session has been idle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Clock {
    started: Instant,
    idle_since: Instant,
    active: usize,
    idle: Duration,
    max: Duration,
}

impl Clock {
    /// A session that starts at `now` with no calls running.
    pub(crate) fn new(now: Instant, idle: Duration, max: Duration) -> Self {
        Self {
            started: now,
            idle_since: now,
            active: 0,
            idle,
            max,
        }
    }

    /// The idle timeout this clock enforces.
    pub(crate) fn idle(&self) -> Duration {
        self.idle
    }

    /// The max lifetime this clock enforces.
    pub(crate) fn max(&self) -> Duration {
        self.max
    }

    /// Number of attached calls currently running.
    #[cfg(test)]
    pub(crate) fn active(&self) -> usize {
        self.active
    }

    /// An attached call was admitted.
    pub(crate) fn call_started(&mut self) {
        self.active = self.active.saturating_add(1);
    }

    /// An attached call ended at `now`. The idle clock restarts when the last
    /// one ends. An unmatched end is ignored (the count never goes below zero).
    pub(crate) fn call_ended(&mut self, now: Instant) {
        self.active = self.active.saturating_sub(1);
        if self.active == 0 {
            self.idle_since = now;
        }
    }

    /// The reason the session must end at `now`, if any.
    pub(crate) fn expired(&self, now: Instant) -> Option<EndReason> {
        if now.saturating_duration_since(self.started) >= self.max {
            return Some(EndReason::MaxLifetime);
        }
        if self.active == 0 && now.saturating_duration_since(self.idle_since) >= self.idle {
            return Some(EndReason::Idle);
        }
        None
    }

    /// The earliest instant at which [`Clock::expired`] can become `Some`.
    /// While calls run, only the max lifetime can end the session.
    pub(crate) fn next_deadline(&self) -> Instant {
        let max_at = self
            .started
            .checked_add(self.max)
            .unwrap_or_else(|| self.started + Duration::from_secs(60 * 60 * 24 * 365 * 100));
        if self.active > 0 {
            return max_at;
        }
        let idle_at = self.idle_since.checked_add(self.idle).unwrap_or(max_at);
        idle_at.min(max_at)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const IDLE: Duration = Duration::from_secs(60);
    const MAX: Duration = Duration::from_secs(600);

    #[test]
    fn defaults_are_the_documented_values() {
        assert_eq!(DEFAULT_IDLE, Duration::from_secs(900));
        assert_eq!(DEFAULT_MAX_LIFETIME, Duration::from_secs(28_800));
        assert_eq!(MAX_LIFETIME_CAP, Duration::from_secs(86_400));
    }

    #[test]
    fn max_lifetime_cap_is_inclusive_and_rejects_above() {
        assert_eq!(parse_max_lifetime("24h"), Ok(MAX_LIFETIME_CAP));
        assert_eq!(parse_max_lifetime("1h"), Ok(Duration::from_secs(3600)));
        let err = parse_max_lifetime("25h").unwrap_err();
        assert_eq!(err, "--max-lifetime must not exceed 24h (got 25h)");
        assert!(parse_max_lifetime("1441min").is_err());
        assert!(parse_max_lifetime("0s").is_err());
        assert!(parse_max_lifetime("nope").is_err());
    }

    #[test]
    fn idle_expires_after_the_timeout_with_no_calls() {
        let t0 = Instant::now();
        let clock = Clock::new(t0, IDLE, MAX);
        assert_eq!(clock.expired(t0 + IDLE - Duration::from_millis(1)), None);
        assert_eq!(clock.expired(t0 + IDLE), Some(EndReason::Idle));
    }

    #[test]
    fn a_running_call_suspends_the_idle_clock() {
        let t0 = Instant::now();
        let mut clock = Clock::new(t0, IDLE, MAX);
        clock.call_started();
        assert_eq!(clock.active(), 1);
        assert_eq!(clock.expired(t0 + IDLE * 2), None, "idle is suspended");
        assert_eq!(clock.next_deadline(), t0 + MAX);
    }

    #[test]
    fn idle_restarts_when_the_last_call_ends() {
        let t0 = Instant::now();
        let mut clock = Clock::new(t0, IDLE, MAX);
        clock.call_started();
        clock.call_started();
        let mid = t0 + Duration::from_secs(100);
        clock.call_ended(mid);
        assert_eq!(clock.expired(mid + IDLE), None, "one call still runs");
        let end = t0 + Duration::from_secs(200);
        clock.call_ended(end);
        assert_eq!(clock.expired(end + IDLE - Duration::from_millis(1)), None);
        assert_eq!(clock.expired(end + IDLE), Some(EndReason::Idle));
    }

    #[test]
    fn unmatched_call_end_is_ignored() {
        let t0 = Instant::now();
        let mut clock = Clock::new(t0, IDLE, MAX);
        clock.call_ended(t0 + Duration::from_secs(1));
        assert_eq!(clock.active(), 0);
    }

    #[test]
    fn max_lifetime_ends_the_session_even_with_calls_running() {
        let t0 = Instant::now();
        let mut clock = Clock::new(t0, IDLE, MAX);
        clock.call_started();
        assert_eq!(clock.expired(t0 + MAX - Duration::from_millis(1)), None);
        assert_eq!(clock.expired(t0 + MAX), Some(EndReason::MaxLifetime));
    }

    #[test]
    fn max_lifetime_wins_a_tie_with_idle() {
        let t0 = Instant::now();
        let clock = Clock::new(t0, MAX, MAX);
        assert_eq!(clock.expired(t0 + MAX), Some(EndReason::MaxLifetime));
    }

    #[test]
    fn next_deadline_is_the_earlier_limit_when_idle() {
        let t0 = Instant::now();
        let clock = Clock::new(t0, IDLE, MAX);
        assert_eq!(clock.next_deadline(), t0 + IDLE);
        let long_idle = Clock::new(t0, MAX * 2, MAX);
        assert_eq!(long_idle.next_deadline(), t0 + MAX);
    }

    #[test]
    fn huge_limits_do_not_overflow() {
        let t0 = Instant::now();
        let clock = Clock::new(t0, Duration::MAX, Duration::MAX);
        let _ = clock.next_deadline();
        assert_eq!(clock.expired(t0 + Duration::from_secs(1)), None);
    }
}
