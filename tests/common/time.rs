//! Doubles that record the validation time a validator hands them. A validation without a
//! fixed time reads the clock once, so that a key, the claims it signed and their status are
//! all checked at the same instant.

use std::sync::Mutex;

use chrono::{DateTime, Utc};
use identity_kit::jose::Jwk;
use identity_kit::resolver::{KeyReference, KeyResolutionError, KeyResolver, KeyRole};
use identity_kit::vc::validation::{CredentialStatus, StatusCheck, StatusError, TimeOptions};

/// A status check that passes every entry and records the validation time it is handed.
#[derive(Default)]
pub(crate) struct RecordedTimes(Mutex<Vec<Option<DateTime<Utc>>>>);

#[async_trait::async_trait]
impl StatusCheck for RecordedTimes {
    async fn check(&self, _: CredentialStatus<'_>, time: TimeOptions) -> Result<(), StatusError> {
        self.0.lock().unwrap().push(time.now);
        Ok(())
    }
}

/// A resolver that records, for every issuer key it resolves, the validation time it is asked
/// at and the time on the clock when it is asked.
pub(crate) struct TimedResolver<R> {
    resolver: R,
    asked: Mutex<Vec<(i64, DateTime<Utc>)>>,
}

impl<R> TimedResolver<R> {
    pub(crate) fn new(resolver: R) -> Self {
        Self {
            resolver,
            asked: Mutex::new(Vec::new()),
        }
    }
}

#[async_trait::async_trait]
impl<R: KeyResolver> KeyResolver for TimedResolver<R> {
    async fn resolve_key(
        &self,
        key: &KeyReference,
        role: KeyRole,
    ) -> Result<Jwk, KeyResolutionError> {
        self.resolver.resolve_key(key, role).await
    }

    async fn resolve_key_at(
        &self,
        key: &KeyReference,
        role: KeyRole,
        now: i64,
    ) -> Result<Jwk, KeyResolutionError> {
        if role == KeyRole::Issuer {
            self.asked.lock().unwrap().push((now, Utc::now()));
        }
        self.resolver.resolve_key_at(key, role, now).await
    }
}

/// Asserts that `resolver` resolved one issuer key and `check` checked `entries` status
/// entries, all at one validation time read from the clock, between `started` and the moment
/// the key was asked for: a time read again for the status would be later than that.
pub(crate) fn assert_one_validation_time<R>(
    resolver: &TimedResolver<R>,
    check: &RecordedTimes,
    entries: usize,
    started: DateTime<Utc>,
) {
    let asked = resolver.asked.lock().unwrap();
    let [(key_time, asked_at)] = asked[..] else {
        panic!("one issuer key is resolved: {asked:?}");
    };
    let times = check.0.lock().unwrap();
    assert_eq!(times.len(), entries, "{times:?}");
    for time in times.iter() {
        let time = time.expect("the status is checked at a fixed time");
        assert_eq!(time.timestamp(), key_time);
        assert!(
            started <= time && time <= asked_at,
            "{time} is not the time of the key"
        );
    }
}
