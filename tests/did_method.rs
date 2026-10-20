//! Specification vectors for `DidMethod` (W3C DID Core 1.0 §3.1 `method-name`, one `idchar`
//! segment as namespace).

use std::collections::{BTreeSet, HashSet};

use identity_kit::did::{DEFAULT_MAX_LEN, Did, DidError, DidMethod};
use proptest::prelude::*;
use serde::Deserialize;
use serde::de::IntoDeserializer;
use serde::de::value::{Error as ValueError, StrDeserializer};

fn method(s: &str) -> DidMethod {
    DidMethod::parse(s).unwrap_or_else(|e| panic!("{s}: {e}"))
}

fn did(s: &str) -> Did {
    Did::parse(s).unwrap_or_else(|e| panic!("{s}: {e}"))
}

// ---------------------------------------------------------------------------------------------
// method-name = 1*method-char ; method-char = %x61-7A / DIGIT
// ---------------------------------------------------------------------------------------------

/// Every boundary of `method-char`: `a`, `z`, `0`, `9`, and the names of the methods in use.
const VALID_NAMES: &[&str] = &[
    "a", "z", "0", "9", "az09", "key", "jwk", "web", "iota", "ebsi",
];

#[test]
fn method_name_boundaries_parse() {
    for name in VALID_NAMES {
        let input = format!("did:{name}");
        let parsed = method(&input);
        assert_eq!(parsed.name(), *name);
        assert_eq!(parsed.namespace(), None);
        assert_eq!(parsed.to_string(), input);
        assert_eq!(DidMethod::new(*name), Ok(parsed));
    }
}

#[test]
fn method_name_rejects_what_the_abnf_excludes() {
    // (input, byte offset of the offending character)
    let invalid: &[(&str, usize)] = &[
        ("did:Example", 4),
        ("did:EXAMPLE", 4),
        ("did:exAmple", 6),
        ("did:ex_ample", 6),
        ("did:ex-ample", 6),
        ("did:ex.ample", 6),
        ("did:ex ample", 6),
        ("did:ex/ample", 6),
        ("did:ex#ample", 6),
        ("did:ex%61mple", 6),
        ("did:exämple", 6),
        ("did:", 4),
        ("did::smr", 4),
    ];
    for (input, position) in invalid {
        assert_eq!(
            DidMethod::parse(input),
            Err(DidError::InvalidMethodName {
                position: *position
            }),
            "{input}"
        );
    }
    for name in ["Example", "ex_ample", ""] {
        assert!(
            matches!(
                DidMethod::new(name),
                Err(DidError::InvalidMethodName { .. })
            ),
            "{name}"
        );
    }
    assert_eq!(
        DidMethod::new("ex_ample"),
        Err(DidError::InvalidMethodName { position: 2 })
    );
    assert_eq!(
        DidMethod::new(""),
        Err(DidError::InvalidMethodName { position: 0 })
    );
}

#[test]
fn scheme_is_lowercase_and_required() {
    for input in [
        "iota", "DID:iota", "Did:iota", "did", "", ":iota", "did iota",
    ] {
        assert_eq!(
            DidMethod::parse(input),
            Err(DidError::MissingScheme),
            "{input}"
        );
    }
}

#[test]
fn input_longer_than_the_limit_is_rejected() {
    let longest = format!("did:{}", "a".repeat(DEFAULT_MAX_LEN - 4));
    assert_eq!(longest.len(), DEFAULT_MAX_LEN);
    assert_eq!(method(&longest).name().len(), DEFAULT_MAX_LEN - 4);
    let too_long = format!("{longest}a");
    assert_eq!(
        DidMethod::parse(&too_long),
        Err(DidError::TooLong {
            max: DEFAULT_MAX_LEN
        })
    );
    // The constructors take a name of any length; only parsing has the limit.
    assert!(DidMethod::new("a".repeat(DEFAULT_MAX_LEN)).is_ok());
}

// ---------------------------------------------------------------------------------------------
// Namespace: one non-empty idchar segment
// ---------------------------------------------------------------------------------------------

#[test]
fn namespace_forms_parse() {
    let valid: &[(&str, &str, &str)] = &[
        ("did:iota:smr", "iota", "smr"),
        ("did:iota:rms", "iota", "rms"),
        ("did:ebsi:zXYZ", "ebsi", "zXYZ"),
        ("did:web:example.com", "web", "example.com"),
        ("did:example:a.b-c_d", "example", "a.b-c_d"),
        ("did:example:ab%2Fcd", "example", "ab%2Fcd"),
        ("did:example:0", "example", "0"),
        ("did:a:b", "a", "b"),
    ];
    for (input, name, namespace) in valid {
        let parsed = method(input);
        assert_eq!(parsed.name(), *name, "{input}");
        assert_eq!(parsed.namespace(), Some(*namespace), "{input}");
        assert_eq!(parsed.to_string(), *input);
        assert_eq!(
            DidMethod::new(*name).and_then(|m| m.with_namespace(*namespace)),
            Ok(parsed),
            "{input}"
        );
    }
}

#[test]
fn namespace_rejects_empty_second_segment_and_non_idchar() {
    let invalid: &[(&str, DidError)] = &[
        ("did:iota:", DidError::InvalidNamespace { position: 9 }),
        (
            "did:iota:smr:x",
            DidError::InvalidNamespace { position: 12 },
        ),
        ("did:iota:smr:", DidError::InvalidNamespace { position: 12 }),
        ("did:iota::smr", DidError::InvalidNamespace { position: 9 }),
        ("did:iota:sm r", DidError::InvalidNamespace { position: 11 }),
        ("did:iota:smr/", DidError::InvalidNamespace { position: 12 }),
        (
            "did:iota:smr?v=1",
            DidError::InvalidNamespace { position: 12 },
        ),
        (
            "did:iota:smr#key-1",
            DidError::InvalidNamespace { position: 12 },
        ),
        ("did:iota:smr~", DidError::InvalidNamespace { position: 12 }),
        ("did:iota:smrä", DidError::InvalidNamespace { position: 12 }),
        (
            "did:iota:a%2",
            DidError::InvalidPercentEncoding { position: 10 },
        ),
        (
            "did:iota:a%G1",
            DidError::InvalidPercentEncoding { position: 10 },
        ),
        (
            "did:iota:%",
            DidError::InvalidPercentEncoding { position: 9 },
        ),
    ];
    for (input, error) in invalid {
        assert_eq!(DidMethod::parse(input).as_ref(), Err(error), "{input}");
    }

    let iota = method("did:iota");
    assert_eq!(
        iota.clone().with_namespace(""),
        Err(DidError::InvalidNamespace { position: 0 })
    );
    assert_eq!(
        iota.clone().with_namespace("smr:x"),
        Err(DidError::InvalidNamespace { position: 3 })
    );
    assert_eq!(
        iota.clone().with_namespace("a%2"),
        Err(DidError::InvalidPercentEncoding { position: 1 })
    );
    // A namespace is not case-folded: the method name is lowercase, the namespace is any idchar.
    assert_eq!(
        iota.with_namespace("SMR").map(|m| m.to_string()),
        Ok("did:iota:SMR".into())
    );
}

#[test]
fn with_namespace_replaces_an_existing_namespace() {
    let shimmer = method("did:iota:smr");
    let mainnet = shimmer.clone().with_namespace("iota").unwrap();
    assert_eq!(mainnet.to_string(), "did:iota:iota");
    assert_eq!(shimmer.namespace(), Some("smr"));
}

// ---------------------------------------------------------------------------------------------
// Conversions and traits
// ---------------------------------------------------------------------------------------------

#[test]
fn parsing_forms_agree() {
    for input in ["did:iota", "did:iota:smr", "did:web:example.com"] {
        let parsed = method(input);
        assert_eq!(input.parse::<DidMethod>().as_ref(), Ok(&parsed));
        assert_eq!(DidMethod::try_from(input).as_ref(), Ok(&parsed));
        assert_eq!(DidMethod::try_from(input.to_owned()).as_ref(), Ok(&parsed));
    }
    for input in ["iota", "did:Iota", "did:iota:"] {
        assert!(input.parse::<DidMethod>().is_err(), "{input}");
        assert!(DidMethod::try_from(input).is_err(), "{input}");
        assert!(DidMethod::try_from(input.to_owned()).is_err(), "{input}");
    }
}

#[test]
fn serde_round_trips_as_a_string() {
    for input in ["did:iota", "did:iota:smr", "did:ebsi:zXYZ"] {
        let parsed = method(input);
        let json = serde_json::to_string(&parsed).unwrap();
        assert_eq!(json, format!("\"{input}\""));
        assert_eq!(serde_json::from_str::<DidMethod>(&json).unwrap(), parsed);
    }

    let list: Vec<DidMethod> = serde_json::from_str(r#"["did:key", "did:iota:smr"]"#).unwrap();
    assert_eq!(list, [method("did:key"), method("did:iota:smr")]);

    for input in [
        r#""iota""#,
        r#""did:Iota""#,
        r#""did:iota:""#,
        r#""did:iota:smr:x""#,
        "5",
    ] {
        assert!(serde_json::from_str::<DidMethod>(input).is_err(), "{input}");
    }

    let input: StrDeserializer<'_, ValueError> = "did:iota:smr".into_deserializer();
    assert_eq!(DidMethod::deserialize(input), Ok(method("did:iota:smr")));
    let input: StrDeserializer<'_, ValueError> = "did:iota:smr:x".into_deserializer();
    assert!(DidMethod::deserialize(input).is_err());
}

#[test]
fn equality_ordering_and_hashing_follow_the_fields() {
    let bare = method("did:iota");
    let smr = method("did:iota:smr");
    let rms = method("did:iota:rms");
    let web = method("did:web");

    assert_eq!(bare, DidMethod::new("iota").unwrap());
    assert_ne!(bare, smr);
    assert_ne!(smr, rms);
    assert_ne!(method("did:iota:SMR"), smr);

    let ordered: BTreeSet<DidMethod> = [web.clone(), smr.clone(), rms.clone(), bare.clone()]
        .into_iter()
        .collect();
    assert_eq!(
        ordered.into_iter().collect::<Vec<_>>(),
        [bare.clone(), rms.clone(), smr.clone(), web.clone()]
    );

    let set: HashSet<DidMethod> = [bare.clone(), bare.clone(), smr.clone(), smr.clone()]
        .into_iter()
        .collect();
    assert_eq!(set.len(), 2);

    assert_eq!(
        format!("{smr:?}"),
        r#"DidMethod { name: "iota", namespace: Some("smr") }"#
    );
    assert_eq!(
        format!("{bare:?}"),
        r#"DidMethod { name: "iota", namespace: None }"#
    );
}

// ---------------------------------------------------------------------------------------------
// Relation to `Did`
// ---------------------------------------------------------------------------------------------

#[test]
fn matches_compares_the_name_and_the_first_segment() {
    let shimmer = did("did:iota:smr:0xabc");
    assert!(method("did:iota").matches(&shimmer));
    assert!(method("did:iota:smr").matches(&shimmer));
    assert!(!method("did:iota:rms").matches(&shimmer));
    assert!(!method("did:iota:0xabc").matches(&shimmer));
    assert!(!method("did:web").matches(&shimmer));
    assert!(!method("did:web:smr").matches(&shimmer));

    // The namespace is the whole first segment, compared byte for byte.
    assert!(!method("did:iota:sm").matches(&shimmer));
    assert!(!method("did:iota:SMR").matches(&shimmer));
    assert!(!method("did:iota:smr").matches(&did("did:iota:smr0:abc")));

    // A DID whose method-specific id is a single segment: that segment is the namespace.
    assert!(method("did:iota:smr").matches(&did("did:iota:smr")));
    assert!(method("did:key").matches(&did(
        "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
    )));
    assert!(method("did:web:example.com").matches(&did("did:web:example.com")));
    assert!(method("did:web:example.com").matches(&did("did:web:example.com:user:alice")));
    assert!(!method("did:web:example.com").matches(&did("did:web:example.com%3A8443")));

    // An empty inner segment is not a namespace.
    assert!(!method("did:iota:smr").matches(&did("did:iota::smr")));
}

#[test]
fn from_did_takes_the_name_only() {
    let shimmer = did("did:iota:smr:0xabc");
    let from_did = DidMethod::from(&shimmer);
    assert_eq!(from_did, method("did:iota"));
    assert_eq!(from_did.namespace(), None);
    assert!(from_did.matches(&shimmer));
    assert_eq!(from_did.to_string(), "did:iota");

    assert_eq!(
        DidMethod::from(&did("did:web:example.com")),
        method("did:web")
    );
    assert_eq!(DidMethod::from(&did("did:0:0")), method("did:0"));
}

// ---------------------------------------------------------------------------------------------
// Properties
// ---------------------------------------------------------------------------------------------

proptest! {
    #[test]
    fn any_method_name_and_namespace_round_trip(
        name in "[a-z0-9]{1,32}",
        namespace in proptest::option::of("([A-Za-z0-9._-]|%[0-9A-Fa-f]{2}){1,32}"),
    ) {
        let built = match &namespace {
            Some(namespace) => DidMethod::new(name.as_str())?.with_namespace(namespace.as_str())?,
            None => DidMethod::new(name.as_str())?,
        };
        let printed = built.to_string();
        let reparsed = DidMethod::parse(&printed);
        prop_assert_eq!(reparsed.as_ref(), Ok(&built));
        prop_assert_eq!(built.name(), name.as_str());
        prop_assert_eq!(built.namespace(), namespace.as_deref());

        let json = serde_json::to_string(&built).unwrap();
        prop_assert_eq!(serde_json::from_str::<DidMethod>(&json).unwrap(), built.clone());

        let did = Did::parse(&format!("did:{name}:{}:rest", namespace.as_deref().unwrap_or("x")))?;
        prop_assert!(built.matches(&did));
        prop_assert_eq!(DidMethod::from(&did), DidMethod::new(name.as_str())?);
    }

    #[test]
    fn a_name_with_a_non_method_char_is_rejected_at_its_position(
        prefix in "[a-z0-9]{0,8}",
        bad in "[A-Z_./: #%-]",
        suffix in "[a-z0-9]{0,8}",
    ) {
        let input = format!("did:{prefix}{bad}{suffix}");
        let expected = if bad == ":" && !prefix.is_empty() {
            // A colon after a non-empty name starts the namespace instead.
            if suffix.is_empty() {
                DidError::InvalidNamespace { position: 4 + prefix.len() + 1 }
            } else {
                return Ok(());
            }
        } else {
            DidError::InvalidMethodName { position: 4 + prefix.len() }
        };
        prop_assert_eq!(DidMethod::parse(&input), Err(expected));
    }
}
