//! The per-run fake-IP allocation map (issue #9, T2).
//!
//! One [`FakeIpMap`] lives for one sandbox run. The resolver ([`super::serve_dns`])
//! allocates into it when it answers an A query for an allow-listed name, and the
//! transparent proxy reads it back through [`crate::proxy::DnsMap`] (the SAME
//! `Arc`, so the two sides can never disagree).
//!
//! Module docs, numbered:
//!
//! 1. **Pool (Q5).** Addresses are handed out sequentially from
//!    [`FAKE_POOL_FIRST`] to [`FAKE_POOL_LAST`] (`198.18.0.1` … `198.19.255.254`,
//!    i.e. the whole `198.18.0.0/15` benchmarking block minus its network and
//!    broadcast addresses). Each name is stored ONCE (one heap allocation, two
//!    `Arc` handles: the ordered `names` vector and the lookup index).
//! 2. **Never expire, never reuse (Q6).** Within a run a name keeps its address
//!    and an address is never handed to a second name. Expiry would need a
//!    quarantine before reuse so a stale fake IP can never map to a different
//!    name; that is #18's problem, not this module's.
//! 3. **Exhaustion never wraps (Q4).** Once `capacity` names exist, a NEW name
//!    gets [`AllocError::Exhausted`]; existing mappings are untouched and keep
//!    resolving.
//! 4. **Fail closed (Q11).** A poisoned lock makes [`FakeIpMap::allocate`] return
//!    [`AllocError::Unavailable`] and [`DnsMap::name_for`] return `None`, which the
//!    proxy turns into `UnknownFakeIp` (deny).
//! 5. **Read path is cheap and non-panicking.** `name_for` is a bounds check, one
//!    lock and a vector index; nothing on either path can panic.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

use crate::policy::Domain;
use crate::proxy::DnsMap;

use super::DnsLimits;

/// First address handed out (`198.18.0.0` itself is never allocated).
pub const FAKE_POOL_FIRST: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 1);
/// Last address handed out (`198.19.255.255` is never allocated).
pub const FAKE_POOL_LAST: Ipv4Addr = Ipv4Addr::new(198, 19, 255, 254);
/// Number of allocatable addresses: `u32(LAST) - u32(FIRST) + 1`.
pub const FAKE_POOL_SIZE: u32 = 131_070;

/// Why [`FakeIpMap::allocate`] could not give out an address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllocError {
    /// The run already holds `capacity` names; a NEW name is refused (Q4).
    Exhausted,
    /// The map's lock is poisoned: fail closed (Q11).
    Unavailable,
}

struct MapState {
    /// Index `i` holds the name whose fake IP is `FAKE_POOL_FIRST + i`.
    names: Vec<Arc<Domain>>,
    /// Canonical name -> index. Same `Arc` as in `names`: one allocation.
    index: HashMap<Arc<Domain>, u32>,
}

/// The run's fake-IP map: canonical name <-> pool address, both directions.
pub struct FakeIpMap {
    state: Mutex<MapState>,
    capacity: u32,
}

impl FakeIpMap {
    /// An empty map holding at most `limits.max_names` names (clamped to the
    /// pool size, so an oversized limit cannot allocate past `198.19.255.254`).
    pub fn new(limits: &DnsLimits) -> Self {
        Self {
            state: Mutex::new(MapState {
                names: Vec::new(),
                index: HashMap::new(),
            }),
            capacity: limits.max_names.min(FAKE_POOL_SIZE),
        }
    }

    /// The fake IP for `name`, allocating the next free address on first sight.
    ///
    /// Idempotent: the same canonical name always gets the same address and
    /// consumes no new slot. Never panics.
    pub fn allocate(&self, name: &Domain) -> Result<Ipv4Addr, AllocError> {
        let mut state = self.state.lock().map_err(|_| AllocError::Unavailable)?;
        if let Some(&index) = state.index.get(name) {
            return Ok(ip_at(index));
        }
        let index = u32::try_from(state.names.len()).map_err(|_| AllocError::Exhausted)?;
        if index >= self.capacity {
            return Err(AllocError::Exhausted);
        }
        let key = Arc::new(name.clone());
        state.index.insert(Arc::clone(&key), index);
        state.names.push(key);
        Ok(ip_at(index))
    }

    /// Test hook: poison the lock (a panic while holding it on another thread),
    /// so callers can pin the fail-closed behaviour from outside this module.
    #[cfg(test)]
    pub(crate) fn poison_for_test(&self) {
        std::thread::scope(|scope| {
            let _ = scope
                .spawn(|| {
                    let _guard = self.state.lock().expect("not yet poisoned");
                    panic!("poisoning the fake-IP map on purpose");
                })
                .join();
        });
    }

    /// Read-only lookup: the fake IP already given to `name`, if any.
    pub fn ip_for(&self, name: &Domain) -> Option<Ipv4Addr> {
        let state = self.state.lock().ok()?;
        state.index.get(name).map(|&index| ip_at(index))
    }

    /// `true` when the lock is poisoned: every allocation returns
    /// `Unavailable` and every lookup returns `None` (fail closed, Q11).
    /// Callers that must tell "empty" from "poisoned" (the #10 audit) check
    /// this first; [`FakeIpMap::len`] cannot tell them apart.
    pub fn poisoned(&self) -> bool {
        self.state.is_poisoned()
    }

    /// Number of names allocated so far. Reports 0 when the lock is poisoned
    /// (see [`FakeIpMap::poisoned`]); the proxy never needs this count.
    pub fn len(&self) -> usize {
        self.state.lock().map(|s| s.names.len()).unwrap_or(0)
    }

    /// `true` when no name has been allocated. Also `true` when the lock is
    /// poisoned, so check [`FakeIpMap::poisoned`] to tell the two apart.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The maximum number of names this run may allocate.
    pub fn capacity(&self) -> u32 {
        self.capacity
    }
}

impl DnsMap for FakeIpMap {
    fn name_for(&self, ip: Ipv4Addr) -> Option<Domain> {
        let index = index_of(ip)?;
        let state = self.state.lock().ok()?;
        state
            .names
            .get(index as usize)
            .map(|name| name.as_ref().clone())
    }
}

/// The pool address at offset `index` (callers keep `index < FAKE_POOL_SIZE`).
fn ip_at(index: u32) -> Ipv4Addr {
    Ipv4Addr::from(u32::from(FAKE_POOL_FIRST) + index)
}

/// The offset of `ip` inside the pool, or `None` outside `FIRST..=LAST`.
fn index_of(ip: Ipv4Addr) -> Option<u32> {
    let value = u32::from(ip);
    let first = u32::from(FAKE_POOL_FIRST);
    let last = u32::from(FAKE_POOL_LAST);
    (first..=last).contains(&value).then(|| value - first)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dom(raw: &str) -> Domain {
        Domain::parse(raw).expect("test domain parses")
    }

    fn map_with(max_names: u32) -> FakeIpMap {
        FakeIpMap::new(&DnsLimits { max_names })
    }

    fn poison(map: &FakeIpMap) {
        map.poison_for_test();
    }

    #[test]
    fn pool_consts_pinned() {
        assert_eq!(FAKE_POOL_FIRST, Ipv4Addr::new(198, 18, 0, 1));
        assert_eq!(FAKE_POOL_LAST, Ipv4Addr::new(198, 19, 255, 254));
        assert_eq!(
            FAKE_POOL_SIZE,
            u32::from(FAKE_POOL_LAST) - u32::from(FAKE_POOL_FIRST) + 1
        );
        assert_eq!(FAKE_POOL_SIZE, 131_070);
        assert_eq!(super::super::FAKE_TTL, 60);
    }

    #[test]
    fn sequential_from_first() {
        let map = map_with(u32::MAX);
        assert_eq!(
            map.allocate(&dom("a.test")),
            Ok(Ipv4Addr::new(198, 18, 0, 1))
        );
        assert_eq!(
            map.allocate(&dom("b.test")),
            Ok(Ipv4Addr::new(198, 18, 0, 2))
        );
        assert_eq!(
            map.allocate(&dom("c.test")),
            Ok(Ipv4Addr::new(198, 18, 0, 3))
        );
        assert_eq!(map.len(), 3);
    }

    #[test]
    fn same_name_same_ip() {
        let map = map_with(u32::MAX);
        let first = map.allocate(&dom("allowed.test")).unwrap();
        assert_eq!(map.allocate(&dom("allowed.test")), Ok(first));
        assert_eq!(map.allocate(&dom("allowed.test")), Ok(first));
        assert_eq!(map.len(), 1, "a repeat allocation consumes no slot");
    }

    #[test]
    fn canonical_key() {
        // Domain::parse lowercases: both spellings are one map key.
        let map = map_with(u32::MAX);
        let upper = map.allocate(&dom("PyPI.org")).unwrap();
        assert_eq!(map.allocate(&dom("pypi.org")), Ok(upper));
        assert_eq!(map.ip_for(&dom("PYPI.ORG")), Some(upper));
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn name_for_roundtrip() {
        let map = map_with(u32::MAX);
        let ip = map.allocate(&dom("allowed.test")).unwrap();
        assert_eq!(map.name_for(ip), Some(dom("allowed.test")));
        assert!(map.ip_for(&dom("missing.test")).is_none());
        assert!(!map.is_empty());
    }

    #[test]
    fn name_for_outside_or_unallocated_none() {
        let map = map_with(u32::MAX);
        map.allocate(&dom("allowed.test")).unwrap();
        for ip in [
            Ipv4Addr::new(198, 18, 0, 0),
            Ipv4Addr::new(198, 19, 255, 255),
            Ipv4Addr::new(203, 0, 113, 7),
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(198, 18, 0, 5),
        ] {
            assert_eq!(map.name_for(ip), None, "{ip} must not resolve");
        }
    }

    #[test]
    fn exhaustion_no_wrap() {
        let map = map_with(2);
        let a = map.allocate(&dom("a.test")).unwrap();
        let b = map.allocate(&dom("b.test")).unwrap();
        assert_eq!(map.allocate(&dom("c.test")), Err(AllocError::Exhausted));
        assert_eq!(map.name_for(a), Some(dom("a.test")));
        assert_eq!(map.name_for(b), Some(dom("b.test")));
        assert_eq!(
            map.allocate(&dom("a.test")),
            Ok(a),
            "existing names keep answering"
        );
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn capacity_clamped() {
        assert_eq!(map_with(u32::MAX).capacity(), FAKE_POOL_SIZE);
        let none = map_with(0);
        assert_eq!(none.capacity(), 0);
        assert_eq!(none.allocate(&dom("a.test")), Err(AllocError::Exhausted));
    }

    #[test]
    fn full_pool_boundary() {
        let map = map_with(u32::MAX);
        let mut last = Ipv4Addr::UNSPECIFIED;
        for i in 0..FAKE_POOL_SIZE {
            last = map.allocate(&dom(&format!("n{i}.test"))).unwrap();
        }
        assert_eq!(last, FAKE_POOL_LAST);
        assert_eq!(
            map.allocate(&dom("overflow.test")),
            Err(AllocError::Exhausted)
        );
        assert_eq!(map.len(), FAKE_POOL_SIZE as usize);
    }

    #[test]
    fn poisoned_lock_fails_closed() {
        let map = map_with(u32::MAX);
        let ip = map.allocate(&dom("allowed.test")).unwrap();
        poison(&map);
        assert_eq!(map.name_for(ip), None);
        assert_eq!(
            map.allocate(&dom("other.test")),
            Err(AllocError::Unavailable)
        );
        assert_eq!(map.ip_for(&dom("allowed.test")), None);
        assert!(map.poisoned());
        assert_eq!(map.len(), 0);
        assert!(map.is_empty());
    }

    #[test]
    fn names_stored_once() {
        let map = map_with(u32::MAX);
        map.allocate(&dom("allowed.test")).unwrap();
        let state = map.state.lock().unwrap();
        assert_eq!(state.names.len(), 1);
        assert_eq!(
            Arc::strong_count(&state.names[0]),
            2,
            "one name, two handles"
        );
    }

    #[test]
    fn fake_ip_map_is_a_dns_map() {
        fn assert_dns_map<T: DnsMap>() {}
        assert_dns_map::<FakeIpMap>();
        let shared: Arc<dyn DnsMap> = Arc::new(map_with(u32::MAX));
        fn assert_send_sync<T: Send + Sync + 'static>(_: &T) {}
        assert_send_sync(&shared);
    }
}
