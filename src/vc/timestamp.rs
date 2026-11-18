//! `Timestamp`, an instant in UTC: the type of every time in the upper layer.

use core::fmt;
use core::str::FromStr;
use core::time::Duration;
use std::borrow::Cow;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use time::format_description::well_known::Rfc3339;
use time::{OffsetDateTime, UtcOffset};

/// An instant in UTC, to the nanosecond, between `0000-01-01T00:00:00Z` and
/// `9999-12-31T23:59:59.999999999Z`: the instants RFC 3339 can write.
///
/// It serializes as an RFC 3339 string in UTC (`2010-01-01T19:23:24Z`), the `dateTimeStamp`
/// form the VC data models require, with as many fractional digits as the instant needs
/// (`2010-01-01T19:23:24.5Z`), and parses an RFC 3339 string with any offset. A JWT
/// `NumericDate` converts with [`from_unix_seconds`](Self::from_unix_seconds) and
/// [`unix_seconds`](Self::unix_seconds).
///
/// The type keeps the public API off any date and time crate; it is built on `time`, and
/// converts to and from [`SystemTime`](std::time::SystemTime).
///
/// # Examples
///
/// ```
/// use identity_kit::vc::Timestamp;
///
/// let time: Timestamp = "2010-01-01T21:23:24+02:00".parse()?;
/// assert_eq!(time.to_string(), "2010-01-01T19:23:24Z");
/// assert_eq!(time.unix_seconds(), 1_262_373_804);
/// assert_eq!(Timestamp::from_unix_seconds(1_262_373_804), Some(time));
/// assert_eq!(serde_json::to_string(&time)?, r#""2010-01-01T19:23:24Z""#);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(OffsetDateTime);

/// `0000-01-01T00:00:00Z` in seconds since the Unix epoch.
const MIN_SECONDS: i64 = -62_167_219_200;
/// `9999-12-31T23:59:59Z` in seconds since the Unix epoch.
const MAX_SECONDS: i64 = 253_402_300_799;

impl Timestamp {
    /// `0000-01-01T00:00:00Z`, the earliest instant.
    pub const MIN: Self = Self::from_seconds_in_range(MIN_SECONDS, 0);
    /// `9999-12-31T23:59:59.999999999Z`, the latest instant.
    pub const MAX: Self = Self::from_seconds_in_range(MAX_SECONDS, 999_999_999);
    /// `1970-01-01T00:00:00Z`.
    pub const UNIX_EPOCH: Self = Self(OffsetDateTime::UNIX_EPOCH);

    const fn from_seconds_in_range(seconds: i64, nanosecond: u32) -> Self {
        let Ok(time) = OffsetDateTime::from_unix_timestamp(seconds) else {
            panic!("in the range of `time`");
        };
        let Ok(time) = time.replace_nanosecond(nanosecond) else {
            panic!("a nanosecond");
        };
        Self(time)
    }

    /// The current time, from the system clock.
    ///
    /// # Panics
    ///
    /// When the system clock is set after year 9999.
    pub fn now() -> Self {
        Self::try_from(OffsetDateTime::now_utc()).expect("the system clock is before year 10000")
    }

    /// The instant `seconds` after the Unix epoch, a JWT `NumericDate` (RFC 7519 §2), when it is
    /// in range.
    pub fn from_unix_seconds(seconds: i64) -> Option<Self> {
        (MIN_SECONDS..=MAX_SECONDS)
            .contains(&seconds)
            .then(|| Self::from_seconds_in_range(seconds, 0))
    }

    /// Whole seconds since the Unix epoch, a JWT `NumericDate`; fractions are dropped, toward
    /// the past.
    pub fn unix_seconds(self) -> i64 {
        self.0.unix_timestamp()
    }

    /// The fraction of the second, in nanoseconds.
    pub fn nanosecond(self) -> u32 {
        self.0.nanosecond()
    }

    /// The instant `duration` later, when it is in range.
    #[must_use]
    pub fn checked_add(self, duration: Duration) -> Option<Self> {
        let duration = time::Duration::try_from(duration).ok()?;
        Self::try_from(self.0.checked_add(duration)?).ok()
    }

    /// The instant `duration` earlier, when it is in range.
    #[must_use]
    pub fn checked_sub(self, duration: Duration) -> Option<Self> {
        let duration = time::Duration::try_from(duration).ok()?;
        Self::try_from(self.0.checked_sub(duration)?).ok()
    }

    /// The instant `duration` later, or [`MAX`](Self::MAX).
    #[must_use]
    pub fn saturating_add(self, duration: Duration) -> Self {
        self.checked_add(duration).unwrap_or(Self::MAX)
    }

    /// The instant `duration` earlier, or [`MIN`](Self::MIN).
    #[must_use]
    pub fn saturating_sub(self, duration: Duration) -> Self {
        self.checked_sub(duration).unwrap_or(Self::MIN)
    }
}

impl core::ops::Add<Duration> for Timestamp {
    type Output = Self;

    /// # Panics
    ///
    /// When the result is after `9999-12-31T23:59:59.999999999Z`, as `SystemTime` panics on
    /// overflow; [`checked_add`](Self::checked_add) and
    /// [`saturating_add`](Self::saturating_add) do not.
    fn add(self, duration: Duration) -> Self {
        self.checked_add(duration)
            .expect("a timestamp before year 10000")
    }
}

impl core::ops::Sub<Duration> for Timestamp {
    type Output = Self;

    /// # Panics
    ///
    /// When the result is before `0000-01-01T00:00:00Z`; [`checked_sub`](Self::checked_sub)
    /// and [`saturating_sub`](Self::saturating_sub) do not.
    fn sub(self, duration: Duration) -> Self {
        self.checked_sub(duration)
            .expect("a timestamp after year 0")
    }
}

impl TryFrom<OffsetDateTime> for Timestamp {
    type Error = TimestampError;

    fn try_from(time: OffsetDateTime) -> Result<Self, Self::Error> {
        let time = time
            .checked_to_offset(UtcOffset::UTC)
            .ok_or(TimestampError::OutOfRange)?;
        if (0..=9999).contains(&time.year()) {
            Ok(Self(time))
        } else {
            Err(TimestampError::OutOfRange)
        }
    }
}

impl TryFrom<std::time::SystemTime> for Timestamp {
    type Error = TimestampError;

    fn try_from(time: std::time::SystemTime) -> Result<Self, Self::Error> {
        Self::try_from(OffsetDateTime::from(time))
    }
}

impl From<Timestamp> for std::time::SystemTime {
    fn from(time: Timestamp) -> Self {
        time.0.into()
    }
}

impl FromStr for Timestamp {
    type Err = TimestampError;

    /// Parses an RFC 3339 date-time (§5.6) with any offset, as the instant it names.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let time = OffsetDateTime::parse(s, &Rfc3339).map_err(|_| TimestampError::Invalid)?;
        Self::try_from(time)
    }
}

impl fmt::Display for Timestamp {
    /// RFC 3339 in UTC, with `Z` and as many fractional digits as needed.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Every instant in range has a four-digit year, which is all RFC 3339 formatting needs.
        let text = self.0.format(&Rfc3339).map_err(|_| fmt::Error)?;
        f.write_str(&text)
    }
}

impl fmt::Debug for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl Serialize for Timestamp {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Timestamp {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = Cow::<'de, str>::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

/// Why a [`Timestamp`] could not be made.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TimestampError {
    /// The text is not an RFC 3339 date-time.
    #[error("not an RFC 3339 date-time")]
    Invalid,
    /// The instant is before year 0 or after year 9999 in UTC.
    #[error("outside the years 0000 to 9999 in UTC")]
    OutOfRange,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounds_write_as_rfc_3339() {
        assert_eq!(Timestamp::MIN.to_string(), "0000-01-01T00:00:00Z");
        assert_eq!(Timestamp::MAX.to_string(), "9999-12-31T23:59:59.999999999Z");
        assert_eq!(Timestamp::UNIX_EPOCH.unix_seconds(), 0);
        assert_eq!(
            Timestamp::from_unix_seconds(MIN_SECONDS),
            Some(Timestamp::MIN)
        );
        assert_eq!(Timestamp::from_unix_seconds(MIN_SECONDS - 1), None);
        assert_eq!(
            Timestamp::from_unix_seconds(MAX_SECONDS)
                .map(|time| time.to_string())
                .as_deref(),
            Some("9999-12-31T23:59:59Z")
        );
        assert_eq!(Timestamp::from_unix_seconds(MAX_SECONDS + 1), None);
    }

    #[test]
    fn arithmetic_stays_in_range() {
        let second = Duration::from_secs(1);
        assert_eq!(Timestamp::MAX.checked_add(Duration::from_nanos(1)), None);
        assert_eq!(Timestamp::MIN.checked_sub(Duration::from_nanos(1)), None);
        assert_eq!(Timestamp::MAX.saturating_add(Duration::MAX), Timestamp::MAX);
        assert_eq!(Timestamp::MIN.saturating_sub(Duration::MAX), Timestamp::MIN);
        assert_eq!(
            Timestamp::UNIX_EPOCH
                .checked_add(second)
                .map(Timestamp::unix_seconds),
            Some(1)
        );
        assert_eq!(
            Timestamp::UNIX_EPOCH
                .checked_sub(second)
                .map(Timestamp::unix_seconds),
            Some(-1)
        );
    }

    #[test]
    fn an_offset_that_leaves_the_range_is_refused() {
        assert_eq!(
            "0000-01-01T00:30:00+01:00".parse::<Timestamp>(),
            Err(TimestampError::OutOfRange)
        );
        assert_eq!(
            "9999-12-31T23:30:00-01:00".parse::<Timestamp>(),
            Err(TimestampError::OutOfRange)
        );
    }
}
