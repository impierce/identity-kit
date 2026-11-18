//! `vc::Timestamp` against the examples of RFC 3339 §5.8 and the `NumericDate` of RFC 7519 §2.
#![cfg(feature = "vc")]

use std::time::{Duration, SystemTime};

use identity_kit::vc::{Timestamp, TimestampError};

/// RFC 3339 §5.8: each example, the instant it names in UTC as `Timestamp` writes it, and that
/// instant in whole seconds since the Unix epoch.
const RFC3339_EXAMPLES: [(&str, &str, i64); 5] = [
    (
        "1985-04-12T23:20:50.52Z",
        "1985-04-12T23:20:50.52Z",
        482_196_050,
    ),
    (
        "1996-12-19T16:39:57-08:00",
        "1996-12-20T00:39:57Z",
        851_042_397,
    ),
    // A leap second is the last instant of the second before it.
    (
        "1990-12-31T23:59:60Z",
        "1990-12-31T23:59:59.999999999Z",
        662_687_999,
    ),
    (
        "1990-12-31T15:59:60-08:00",
        "1990-12-31T23:59:59.999999999Z",
        662_687_999,
    ),
    // A fraction before the epoch rounds toward the past.
    (
        "1937-01-01T12:00:27.87+00:20",
        "1937-01-01T11:40:27.87Z",
        -1_041_337_173,
    ),
];

#[test]
fn reads_the_rfc_3339_examples() {
    for (text, utc, seconds) in RFC3339_EXAMPLES {
        let time: Timestamp = text.parse().unwrap();
        assert_eq!(time.to_string(), utc, "{text}");
        assert_eq!(time.unix_seconds(), seconds, "{text}");
        let nanosecond = match utc.split_once('.') {
            Some((_, fraction)) => format!("{:0<9}", fraction.trim_end_matches('Z'))
                .parse()
                .unwrap(),
            None => 0,
        };
        assert_eq!(time.nanosecond(), nanosecond, "{text}");
        // Serialized, it is the UTC text, which reads back as the same instant.
        let json = serde_json::to_string(&time).unwrap();
        assert_eq!(json, format!("\"{utc}\""));
        assert_eq!(serde_json::from_str::<Timestamp>(&json).unwrap(), time);
    }
}

#[test]
fn refuses_what_rfc_3339_does_not_write() {
    for text in [
        "2010-01-01T19:23:24",       // no offset
        "2010-01-01T19:23Z",         // no seconds
        "2010-01-01T19:23:24,5Z",    // a comma fraction
        "2010-01-01T19:23:24+0200",  // an offset without a colon
        "2010-01-01T19:23:24 UTC",   // a zone name
        "2010-01-01T19:23:24+24:00", // an offset of a whole day
        "2010-13-01T19:23:24Z",      // no 13th month
        "",
    ] {
        assert_eq!(
            text.parse::<Timestamp>(),
            Err(TimestampError::Invalid),
            "{text}"
        );
        assert!(serde_json::from_value::<Timestamp>(serde_json::json!(text)).is_err());
    }
    assert!(serde_json::from_value::<Timestamp>(serde_json::json!(1_262_373_804)).is_err());
}

#[test]
fn converts_numeric_dates_in_range() {
    // RFC 7519 §2: seconds since 1970-01-01T00:00:00Z UTC, leap seconds ignored.
    let time = Timestamp::from_unix_seconds(1_300_819_380).unwrap();
    assert_eq!(time.to_string(), "2011-03-22T18:43:00Z");
    assert_eq!(time.unix_seconds(), 1_300_819_380);
    // The "no well-defined expiration date" of RFC 5280 §4.1.2.5 is in range.
    let never = "9999-12-31T23:59:59Z".parse::<Timestamp>().unwrap();
    assert_eq!(never.unix_seconds(), 253_402_300_799);
    assert_eq!(Timestamp::from_unix_seconds(253_402_300_799), Some(never));
    assert_eq!(Timestamp::from_unix_seconds(253_402_300_800), None);
    assert_eq!(
        "10000-01-01T00:00:00Z".parse::<Timestamp>(),
        Err(TimestampError::Invalid)
    );
}

#[test]
fn orders_adds_and_converts() {
    let earlier: Timestamp = "2010-01-01T19:23:24Z".parse().unwrap();
    let later: Timestamp = "2010-01-01T21:23:24+01:00".parse().unwrap();
    assert!(earlier < later);
    assert_eq!(earlier + Duration::from_secs(3_600), later);
    assert_eq!(later - Duration::from_secs(3_600), earlier);
    assert_eq!(
        earlier
            .checked_add(Duration::from_millis(500))
            .unwrap()
            .to_string(),
        "2010-01-01T19:23:24.5Z"
    );
    let system = SystemTime::try_from(earlier).unwrap();
    assert_eq!(Timestamp::try_from(system), Ok(earlier));
    // Before the epoch, in whole seconds and with a fraction.
    let second_before = Timestamp::from_unix_seconds(-1).unwrap();
    let system = SystemTime::try_from(second_before).unwrap();
    assert_eq!(Timestamp::try_from(system), Ok(second_before));
    let before: Timestamp = "1937-01-01T11:40:27.87Z".parse().unwrap();
    let system = SystemTime::try_from(before).unwrap();
    assert_eq!(Timestamp::try_from(system), Ok(before));
    assert_eq!(
        SystemTime::UNIX_EPOCH.duration_since(system).unwrap(),
        Duration::new(1_041_337_172, 130_000_000)
    );
    let year_11476 = SystemTime::UNIX_EPOCH + Duration::from_hours(83_333_334);
    assert_eq!(
        Timestamp::try_from(year_11476),
        Err(TimestampError::OutOfRange)
    );
    assert!(Timestamp::now() > earlier);
}
