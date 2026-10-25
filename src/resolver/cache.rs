//! `DocumentCache`: resolution results kept for a while.

use core::fmt;
use std::collections::HashMap;
use std::sync::{PoisonError, RwLock};
use std::time::{Duration, Instant};

use crate::did::{Did, ResolutionResult};

/// A bounded cache of resolution results, keyed by DID, where every entry expires after the
/// same time to live.
///
/// A [`Resolver`](super::Resolver) built with [`cache`](super::ResolverBuilder::cache) serves
/// repeated resolutions of a DID from it, for resolutions without options only: options such
/// as `versionId` or `accept` change what is returned, so those always reach the method.
///
/// The cache is `Sync`: readers share a lock, and an insert takes it exclusively. When it is
/// full, expired entries go first and then the entry that expires soonest.
///
/// # Examples
///
/// ```
/// use std::time::Duration;
///
/// use identity_kit::did::{Did, DidDocument, ResolutionResult};
/// use identity_kit::resolver::DocumentCache;
///
/// let cache = DocumentCache::new(Duration::from_secs(300));
/// let did = Did::parse("did:example:123")?;
/// cache.insert(did.clone(), ResolutionResult::new(DidDocument::new(did.clone())));
/// assert!(cache.get(&did).is_some());
/// assert_eq!(cache.len(), 1);
///
/// cache.remove(&did);
/// assert!(cache.is_empty());
/// # Ok::<(), identity_kit::did::DidError>(())
/// ```
pub struct DocumentCache {
    ttl: Duration,
    capacity: usize,
    entries: RwLock<HashMap<Did, Entry>>,
}

struct Entry {
    result: ResolutionResult,
    /// `None` when `now + ttl` overflows: the entry never expires.
    expires_at: Option<Instant>,
}

impl Entry {
    fn is_live(&self, now: Instant) -> bool {
        self.expires_at.is_none_or(|expires_at| expires_at > now)
    }
}

impl DocumentCache {
    /// The number of entries [`new`](Self::new) allows.
    pub const DEFAULT_CAPACITY: usize = 1024;

    /// A cache whose entries live for `ttl`, holding up to
    /// [`DEFAULT_CAPACITY`](Self::DEFAULT_CAPACITY) entries.
    pub fn new(ttl: Duration) -> Self {
        Self::with_capacity(ttl, Self::DEFAULT_CAPACITY)
    }

    /// A cache whose entries live for `ttl`, holding up to `capacity` entries (at least one).
    pub fn with_capacity(ttl: Duration, capacity: usize) -> Self {
        Self {
            ttl,
            capacity: capacity.max(1),
            entries: RwLock::new(HashMap::new()),
        }
    }

    /// How long an entry lives.
    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// How many entries the cache holds at most.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// The cached result for `did`, if one is present and has not expired.
    pub fn get(&self, did: &Did) -> Option<ResolutionResult> {
        let now = Instant::now();
        let entries = self.entries.read().unwrap_or_else(PoisonError::into_inner);
        entries
            .get(did)
            .filter(|entry| entry.is_live(now))
            .map(|entry| entry.result.clone())
    }

    /// Caches `result` for `did`, replacing any earlier entry.
    pub fn insert(&self, did: Did, result: ResolutionResult) {
        let now = Instant::now();
        let mut entries = self.entries.write().unwrap_or_else(PoisonError::into_inner);
        if !entries.contains_key(&did) && entries.len() >= self.capacity {
            entries.retain(|_, entry| entry.is_live(now));
            if entries.len() >= self.capacity {
                // Every entry is live: evict the one that expires first.
                let soonest = entries
                    .iter()
                    .min_by_key(|(_, entry)| entry.expires_at)
                    .map(|(did, _)| did.clone());
                if let Some(soonest) = soonest {
                    entries.remove(&soonest);
                }
            }
        }
        entries.insert(
            did,
            Entry {
                result,
                expires_at: now.checked_add(self.ttl),
            },
        );
    }

    /// Removes the entry for `did`, returning it if it had not expired.
    pub fn remove(&self, did: &Did) -> Option<ResolutionResult> {
        let now = Instant::now();
        let mut entries = self.entries.write().unwrap_or_else(PoisonError::into_inner);
        entries
            .remove(did)
            .filter(|entry| entry.is_live(now))
            .map(|entry| entry.result)
    }

    /// Removes every entry.
    pub fn clear(&self) {
        self.entries
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
    }

    /// Removes the expired entries, returning how many there were.
    pub fn purge_expired(&self) -> usize {
        let now = Instant::now();
        let mut entries = self.entries.write().unwrap_or_else(PoisonError::into_inner);
        let before = entries.len();
        entries.retain(|_, entry| entry.is_live(now));
        before - entries.len()
    }

    /// The number of entries that have not expired.
    pub fn len(&self) -> usize {
        let now = Instant::now();
        self.entries
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
            .filter(|entry| entry.is_live(now))
            .count()
    }

    /// Whether no entry is live.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl fmt::Debug for DocumentCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DocumentCache")
            .field("ttl", &self.ttl)
            .field("capacity", &self.capacity)
            .field("len", &self.len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::did::DidDocument;

    #[test]
    fn an_entry_expires_at_its_instant() {
        let did: Did = "did:example:123".parse().unwrap();
        let now = Instant::now();
        let entry = Entry {
            result: ResolutionResult::new(DidDocument::new(did)),
            expires_at: Some(now),
        };
        assert!(entry.is_live(now.checked_sub(Duration::from_nanos(1)).unwrap()));
        assert!(!entry.is_live(now));
    }
}
