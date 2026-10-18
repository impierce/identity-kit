//! Specification vectors for `Did` and `DidUrl` (W3C DID Core 1.0 §3.1 and §3.2, RFC 3986).

use std::collections::{BTreeSet, HashSet};

use identity_kit::did::{DEFAULT_MAX_LEN, Did, DidError, DidUrl, DidUrlReference};
use proptest::prelude::*;
use serde::de::IntoDeserializer;
use serde::de::value::{Error as ValueError, StrDeserializer};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------------------------
// Valid DIDs
// ---------------------------------------------------------------------------------------------

const VALID_DIDS: &[(&str, &str, &str)] = &[
    (
        "did:example:123456789abcdefghi",
        "example",
        "123456789abcdefghi",
    ),
    ("did:example:123:456", "example", "123:456"),
    ("did:example:a::b", "example", "a::b"),
    ("did:web:example.com", "web", "example.com"),
    (
        "did:web:example.com%3A8443:user:alice",
        "web",
        "example.com%3A8443:user:alice",
    ),
    (
        "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
        "key",
        "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
    ),
    (
        "did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9",
        "jwk",
        "eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9",
    ),
    ("did:a:b", "a", "b"),
    ("did:0:0", "0", "0"),
    ("did:example:ab%2Fcd", "example", "ab%2Fcd"),
    ("did:example:a.b-c_d", "example", "a.b-c_d"),
];

#[test]
fn valid_dids_parse_and_expose_components() {
    for (input, method, id) in VALID_DIDS {
        let did = Did::parse(input).unwrap_or_else(|e| panic!("{input}: {e}"));
        assert_eq!(did.as_str(), *input);
        assert_eq!(did.as_ref(), *input);
        assert_eq!(did.to_string(), *input);
        assert_eq!(did.method(), *method, "{input}");
        assert_eq!(did.method_specific_id(), *id, "{input}");
    }
}

#[test]
fn valid_dids_parse_as_did_urls_without_components() {
    for (input, ..) in VALID_DIDS {
        let did = Did::parse(input).unwrap();
        let url = DidUrl::parse(input).unwrap_or_else(|e| panic!("{input}: {e}"));
        assert_eq!(url, did.to_url());
        assert_eq!(url.did(), &did);
        assert_eq!(url.path(), None);
        assert_eq!(url.query(), None);
        assert_eq!(url.fragment(), None);
        assert_eq!(url.as_str(), *input);
        assert_eq!(url.to_string(), *input);
    }
}

#[test]
fn constructors_agree() {
    for (input, ..) in VALID_DIDS {
        let did = Did::parse(input).unwrap();
        assert_eq!(input.parse::<Did>().unwrap(), did);
        assert_eq!(Did::try_from(*input).unwrap(), did);
        assert_eq!(Did::try_from((*input).to_owned()).unwrap(), did);

        let url = DidUrl::parse(input).unwrap();
        assert_eq!(input.parse::<DidUrl>().unwrap(), url);
        assert_eq!(DidUrl::try_from(*input).unwrap(), url);
        assert_eq!(DidUrl::try_from((*input).to_owned()).unwrap(), url);
    }
}

// ---------------------------------------------------------------------------------------------
// Invalid DIDs
// ---------------------------------------------------------------------------------------------

const INVALID_DIDS: &[(&str, DidError)] = &[
    ("DID:example:123", DidError::MissingScheme),
    (
        "did:Example:123",
        DidError::InvalidMethodName { position: 4 },
    ),
    (
        "did:ex-ample:123",
        DidError::InvalidMethodName { position: 6 },
    ),
    ("did::123", DidError::InvalidMethodName { position: 4 }),
    ("did:example", DidError::EmptyMethodSpecificId),
    ("did:example:", DidError::EmptyMethodSpecificId),
    ("did:example:a:", DidError::EmptyMethodSpecificId),
    (
        "did:example:a b",
        DidError::InvalidChar {
            position: 13,
            ch: ' ',
        },
    ),
    (
        "did:example:ab%2",
        DidError::InvalidPercentEncoding { position: 14 },
    ),
    (
        "did:example:ab%G1",
        DidError::InvalidPercentEncoding { position: 14 },
    ),
    (
        "did:example:ab/c",
        DidError::InvalidChar {
            position: 14,
            ch: '/',
        },
    ),
    (
        "did:example:ab#c",
        DidError::InvalidChar {
            position: 14,
            ch: '#',
        },
    ),
    (
        "did:example:ü",
        DidError::InvalidChar {
            position: 12,
            ch: 'ü',
        },
    ),
    ("example:123", DidError::MissingScheme),
    ("", DidError::MissingScheme),
];

#[test]
fn invalid_dids_are_rejected_with_the_expected_error() {
    for (input, expected) in INVALID_DIDS {
        assert_eq!(Did::parse(input).as_ref(), Err(expected), "{input:?}");
        assert_eq!(input.parse::<Did>().as_ref(), Err(expected), "{input:?}");
        assert_eq!(
            Did::try_from((*input).to_owned()).as_ref(),
            Err(expected),
            "{input:?}"
        );
    }
}

#[test]
fn did_with_fragment_is_a_valid_did_url_but_not_a_did() {
    assert!(Did::parse("did:example:ab#c").is_err());
    let url = DidUrl::parse("did:example:ab#c").unwrap();
    assert_eq!(url.did().as_str(), "did:example:ab");
    assert_eq!(url.fragment(), Some("c"));

    assert!(Did::parse("did:example:ab/c").is_err());
    let url = DidUrl::parse("did:example:ab/c").unwrap();
    assert_eq!(url.path(), Some("/c"));
}

#[test]
fn invalid_dids_are_also_invalid_did_urls_unless_a_url_delimiter_follows() {
    for (input, expected) in INVALID_DIDS {
        if matches!(*input, "did:example:ab/c" | "did:example:ab#c") {
            continue;
        }
        assert_eq!(DidUrl::parse(input).as_ref(), Err(expected), "{input:?}");
    }
}

#[test]
fn percent_encoding_is_kept_verbatim_and_case_sensitive() {
    let lower = Did::parse("did:example:ab%2fcd").unwrap();
    let upper = Did::parse("did:example:ab%2Fcd").unwrap();
    assert_ne!(lower, upper);
    assert_eq!(lower.method_specific_id(), "ab%2fcd");
    assert_eq!(upper.method_specific_id(), "ab%2Fcd");
}

#[test]
fn errors_display_a_message() {
    for (_, error) in INVALID_DIDS {
        assert!(!error.to_string().is_empty());
    }
    assert_eq!(
        DidError::InvalidChar {
            position: 13,
            ch: ' '
        }
        .to_string(),
        "invalid character ' ' at byte 13"
    );
}

// ---------------------------------------------------------------------------------------------
// Length limit
// ---------------------------------------------------------------------------------------------

#[test]
fn overlong_input_is_rejected() {
    let prefix = "did:example:";
    let at_limit = format!("{prefix}{}", "a".repeat(DEFAULT_MAX_LEN - prefix.len()));
    assert_eq!(at_limit.len(), DEFAULT_MAX_LEN);
    assert!(Did::parse(&at_limit).is_ok());
    assert!(DidUrl::parse(&at_limit).is_ok());

    let over_limit = format!("{at_limit}a");
    let too_long = DidError::TooLong {
        max: DEFAULT_MAX_LEN,
    };
    assert_eq!(Did::parse(&over_limit), Err(too_long.clone()));
    assert_eq!(DidUrl::parse(&over_limit), Err(too_long.clone()));
    assert_eq!(over_limit.parse::<Did>(), Err(too_long.clone()));
    assert_eq!(Did::try_from(over_limit.clone()), Err(too_long.clone()));
    assert_eq!(DidUrl::try_from(over_limit), Err(too_long));
}

#[test]
fn join_keeps_to_the_limit() {
    let did = Did::parse("did:example:123").unwrap();
    let too_long = DidError::TooLong {
        max: DEFAULT_MAX_LEN,
    };
    // A reference that fits the limit on its own, but not together with the DID.
    let query = format!("?{}", "a".repeat(DEFAULT_MAX_LEN - 1));
    let reference = DidUrlReference::parse(&query).unwrap();
    assert_eq!(did.join(&query), Err(too_long.clone()));
    assert_eq!(reference.resolve(&did), Err(too_long));
    assert!(!reference.refers_to(&did.to_url(), &did));
    // At the limit, the URL parses back.
    let fits = format!("?{}", "a".repeat(DEFAULT_MAX_LEN - did.as_str().len() - 1));
    let url = did.join(&fits).unwrap();
    assert_eq!(url.as_str().len(), DEFAULT_MAX_LEN);
    assert_eq!(DidUrl::parse(url.as_str()).as_ref(), Ok(&url));
    assert_eq!(
        DidUrlReference::parse(&fits).unwrap().resolve(&did),
        Ok(url)
    );
}

#[test]
fn maximum_length_is_configurable() {
    let input = "did:example:123";
    assert!(Did::parse_with_max_len(input, input.len()).is_ok());
    assert_eq!(
        Did::parse_with_max_len(input, input.len() - 1),
        Err(DidError::TooLong {
            max: input.len() - 1
        })
    );
    assert!(DidUrl::parse_with_max_len(input, input.len()).is_ok());
    assert_eq!(
        DidUrl::parse_with_max_len(input, 10),
        Err(DidError::TooLong { max: 10 })
    );
}

// ---------------------------------------------------------------------------------------------
// DID URLs
// ---------------------------------------------------------------------------------------------

#[test]
fn did_url_vectors() {
    let url = DidUrl::parse("did:example:123#key-1").unwrap();
    assert_eq!(url.did().as_str(), "did:example:123");
    assert_eq!(url.path(), None);
    assert_eq!(url.query(), None);
    assert_eq!(url.fragment(), Some("key-1"));
    assert_eq!(url.to_string(), "did:example:123#key-1");

    let url = DidUrl::parse("did:example:123/path/to?versionId=1#frag").unwrap();
    assert_eq!(url.did().as_str(), "did:example:123");
    assert_eq!(url.path(), Some("/path/to"));
    assert_eq!(url.query(), Some("versionId=1"));
    assert_eq!(url.fragment(), Some("frag"));
    assert_eq!(url.as_str(), "did:example:123/path/to?versionId=1#frag");

    let url = DidUrl::parse("did:example:123?service=agent&relativeRef=%2Fsome%2Fpath").unwrap();
    assert_eq!(url.did().as_str(), "did:example:123");
    assert_eq!(url.path(), None);
    assert_eq!(
        url.query(),
        Some("service=agent&relativeRef=%2Fsome%2Fpath")
    );
    assert_eq!(url.fragment(), None);

    let url = DidUrl::parse("did:web:example.com%3A8443#0").unwrap();
    assert_eq!(url.did().as_str(), "did:web:example.com%3A8443");
    assert_eq!(url.did().method_specific_id(), "example.com%3A8443");
    assert_eq!(url.fragment(), Some("0"));

    let url = DidUrl::parse("did:example:123#").unwrap();
    assert_eq!(url.fragment(), Some(""));
    assert_eq!(url.query(), None);
    assert_eq!(url.to_string(), "did:example:123#");

    let url = DidUrl::parse("did:example:123?").unwrap();
    assert_eq!(url.query(), Some(""));
    assert_eq!(url.fragment(), None);
    assert_eq!(url.to_string(), "did:example:123?");

    let url = DidUrl::parse("did:example:123/").unwrap();
    assert_eq!(url.path(), Some("/"));

    // A fragment may contain `/` and `?`; a query may contain `/` and `?`.
    let url = DidUrl::parse("did:example:123?a=/b?c#d/e?f").unwrap();
    assert_eq!(url.query(), Some("a=/b?c"));
    assert_eq!(url.fragment(), Some("d/e?f"));

    // `pchar` sub-delims and `:`/`@` are allowed in path segments.
    let url = DidUrl::parse("did:example:123/a:b@c!$&'()*+,;=~").unwrap();
    assert_eq!(url.path(), Some("/a:b@c!$&'()*+,;=~"));
}

#[test]
fn invalid_did_urls_are_rejected() {
    let cases: &[(&str, DidError)] = &[
        ("did:example:123#a#b", DidError::InvalidFragment),
        ("did:example:123#a b", DidError::InvalidFragment),
        ("did:example:123#ü", DidError::InvalidFragment),
        ("did:example:123?q=a b", DidError::InvalidQuery),
        ("did:example:123?q=[1]", DidError::InvalidQuery),
        ("did:example:123/a b", DidError::InvalidPath),
        ("did:example:123/ü", DidError::InvalidPath),
        ("did:example:123/a[1]", DidError::InvalidPath),
        (
            "did:example:123/p%2",
            DidError::InvalidPercentEncoding { position: 17 },
        ),
        (
            "did:example:123?q=%zz",
            DidError::InvalidPercentEncoding { position: 18 },
        ),
        (
            "did:example:123#%",
            DidError::InvalidPercentEncoding { position: 16 },
        ),
        ("did:example:a:/path", DidError::EmptyMethodSpecificId),
        ("did:example:/path", DidError::EmptyMethodSpecificId),
        ("did:example/path", DidError::EmptyMethodSpecificId),
        ("did:example#frag", DidError::EmptyMethodSpecificId),
        (
            "did:example:123 ",
            DidError::InvalidChar {
                position: 15,
                ch: ' ',
            },
        ),
        (
            "did:example:123ü",
            DidError::InvalidChar {
                position: 15,
                ch: 'ü',
            },
        ),
        ("did:example:123/x#y?z#w", DidError::InvalidFragment),
    ];
    for (input, expected) in cases {
        assert_eq!(DidUrl::parse(input).as_ref(), Err(expected), "{input:?}");
    }
}

#[test]
fn join_builds_did_urls() {
    let did = Did::parse("did:example:123").unwrap();

    let url = did.join("#key-1").unwrap();
    assert_eq!(url.fragment(), Some("key-1"));
    assert_eq!(url.as_str(), "did:example:123#key-1");
    assert_eq!(url, DidUrl::parse("did:example:123#key-1").unwrap());

    let url = did.join("/path").unwrap();
    assert_eq!(url.path(), Some("/path"));
    assert_eq!(url.as_str(), "did:example:123/path");

    let url = did.join("?versionId=1").unwrap();
    assert_eq!(url.query(), Some("versionId=1"));
    assert_eq!(url.as_str(), "did:example:123?versionId=1");

    let url = did.join("/path?versionId=1#key-1").unwrap();
    assert_eq!(url.path(), Some("/path"));
    assert_eq!(url.query(), Some("versionId=1"));
    assert_eq!(url.fragment(), Some("key-1"));

    assert_eq!(did.join("").unwrap(), did.to_url());
    assert_eq!(did.join("#").unwrap().fragment(), Some(""));

    assert_eq!(did.join("key-1"), Err(DidError::InvalidPath));
    assert_eq!(did.join("did:example:456"), Err(DidError::InvalidPath));
    assert_eq!(did.join("/a b"), Err(DidError::InvalidPath));
    assert_eq!(did.join("?a b"), Err(DidError::InvalidQuery));
    assert_eq!(did.join("#a#b"), Err(DidError::InvalidFragment));
    assert_eq!(
        did.join("#%4"),
        Err(DidError::InvalidPercentEncoding { position: 16 })
    );
}

#[test]
fn with_fragment_and_without_fragment() {
    let url = DidUrl::parse("did:example:123/path?versionId=1#key-1").unwrap();

    let replaced = url.with_fragment("key-2");
    assert_eq!(replaced.as_str(), "did:example:123/path?versionId=1#key-2");
    assert_eq!(replaced.path(), Some("/path"));
    assert_eq!(replaced.query(), Some("versionId=1"));
    assert_eq!(replaced.fragment(), Some("key-2"));

    let stripped = url.without_fragment();
    assert_eq!(stripped.as_str(), "did:example:123/path?versionId=1");
    assert_eq!(stripped.fragment(), None);
    assert_eq!(stripped.query(), Some("versionId=1"));
    assert_eq!(stripped.without_fragment(), stripped);

    let bare = DidUrl::parse("did:example:123").unwrap();
    assert_eq!(bare.with_fragment("0").as_str(), "did:example:123#0");
    assert_eq!(bare.with_fragment("").as_str(), "did:example:123#");
    assert_eq!(bare.with_fragment("").fragment(), Some(""));
    assert_eq!(bare.without_fragment(), bare);
}

#[test]
fn with_fragment_percent_encodes_what_rfc_3986_does_not_allow() {
    let bare = DidUrl::parse("did:example:123").unwrap();
    let cases: &[(&str, &str)] = &[
        ("key-1", "key-1"),
        ("a b", "a%20b"),
        ("a#b", "a%23b"),
        ("%2F", "%2F"),
        ("%2f", "%2f"),
        ("%2", "%252"),
        ("%", "%25"),
        ("100%", "100%25"),
        ("ü", "%C3%BC"),
        ("a/b?c:d@e", "a/b?c:d@e"),
        ("[x]", "%5Bx%5D"),
    ];
    for (input, expected) in cases {
        let url = bare.with_fragment(input);
        assert_eq!(url.fragment(), Some(*expected), "{input:?}");
        // The result is always a valid DID URL that round-trips.
        assert_eq!(DidUrl::parse(url.as_str()).unwrap(), url, "{input:?}");
    }
}

// ---------------------------------------------------------------------------------------------
// Equality, ordering and hashing
// ---------------------------------------------------------------------------------------------

#[test]
fn equality_is_string_equality() {
    let a = Did::parse("did:example:123").unwrap();
    let b = Did::parse("did:example:123").unwrap();
    let c = Did::parse("did:example:124").unwrap();
    assert_eq!(a, b);
    assert_ne!(a, c);
    assert!(a < c);

    let url_a = DidUrl::parse("did:example:123#a").unwrap();
    let url_b = DidUrl::parse("did:example:123#a").unwrap();
    let url_c = DidUrl::parse("did:example:123#b").unwrap();
    assert_eq!(url_a, url_b);
    assert_ne!(url_a, url_c);
    assert!(url_a < url_c);
    assert_eq!(url_a.cmp(&url_c), url_a.as_str().cmp(url_c.as_str()));
    assert_ne!(a.to_url(), url_a);
}

#[test]
fn hash_and_ord_are_usable_in_collections() {
    let dids: HashSet<Did> = ["did:example:1", "did:example:2", "did:example:1"]
        .iter()
        .map(|s| Did::parse(s).unwrap())
        .collect();
    assert_eq!(dids.len(), 2);

    let urls: BTreeSet<DidUrl> = ["did:example:1#b", "did:example:1#a", "did:example:1#b"]
        .iter()
        .map(|s| DidUrl::parse(s).unwrap())
        .collect();
    let ordered: Vec<&str> = urls.iter().map(DidUrl::as_str).collect();
    assert_eq!(ordered, ["did:example:1#a", "did:example:1#b"]);

    let urls: HashSet<DidUrl> = ["did:example:1#a", "did:example:1#a"]
        .iter()
        .map(|s| DidUrl::parse(s).unwrap())
        .collect();
    assert_eq!(urls.len(), 1);
}

#[test]
fn debug_output_shows_the_string() {
    let did = Did::parse("did:example:123").unwrap();
    assert_eq!(format!("{did:?}"), "Did(\"did:example:123\")");
    let url = DidUrl::parse("did:example:123#a").unwrap();
    assert_eq!(format!("{url:?}"), "DidUrl(\"did:example:123#a\")");
}

// ---------------------------------------------------------------------------------------------
// serde
// ---------------------------------------------------------------------------------------------

/// A serializer that accepts exactly one string, so the tests need no serialization format.
struct StringOnly;

macro_rules! reject {
    ($($name:ident($($arg:ty),*);)*) => {
        $(
            fn $name(self, $(_: $arg),*) -> Result<String, ValueError> {
                Err(serde::ser::Error::custom(concat!("expected a string, got ", stringify!($name))))
            }
        )*
    };
}

impl serde::Serializer for StringOnly {
    type Ok = String;
    type Error = ValueError;
    type SerializeSeq = serde::ser::Impossible<String, ValueError>;
    type SerializeTuple = serde::ser::Impossible<String, ValueError>;
    type SerializeTupleStruct = serde::ser::Impossible<String, ValueError>;
    type SerializeTupleVariant = serde::ser::Impossible<String, ValueError>;
    type SerializeMap = serde::ser::Impossible<String, ValueError>;
    type SerializeStruct = serde::ser::Impossible<String, ValueError>;
    type SerializeStructVariant = serde::ser::Impossible<String, ValueError>;

    fn serialize_str(self, v: &str) -> Result<String, ValueError> {
        Ok(v.to_owned())
    }

    reject! {
        serialize_bool(bool);
        serialize_i8(i8);
        serialize_i16(i16);
        serialize_i32(i32);
        serialize_i64(i64);
        serialize_u8(u8);
        serialize_u16(u16);
        serialize_u32(u32);
        serialize_u64(u64);
        serialize_f32(f32);
        serialize_f64(f64);
        serialize_char(char);
        serialize_bytes(&[u8]);
        serialize_none();
        serialize_unit();
        serialize_unit_struct(&'static str);
        serialize_unit_variant(&'static str, u32, &'static str);
    }

    fn serialize_some<T: Serialize + ?Sized>(self, _: &T) -> Result<String, ValueError> {
        Err(serde::ser::Error::custom("expected a string, got some"))
    }

    fn serialize_newtype_struct<T: Serialize + ?Sized>(
        self,
        _: &'static str,
        _: &T,
    ) -> Result<String, ValueError> {
        Err(serde::ser::Error::custom(
            "expected a string, got newtype struct",
        ))
    }

    fn serialize_newtype_variant<T: Serialize + ?Sized>(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        _: &T,
    ) -> Result<String, ValueError> {
        Err(serde::ser::Error::custom(
            "expected a string, got newtype variant",
        ))
    }

    fn serialize_seq(self, _: Option<usize>) -> Result<Self::SerializeSeq, ValueError> {
        Err(serde::ser::Error::custom("expected a string, got seq"))
    }

    fn serialize_tuple(self, _: usize) -> Result<Self::SerializeTuple, ValueError> {
        Err(serde::ser::Error::custom("expected a string, got tuple"))
    }

    fn serialize_tuple_struct(
        self,
        _: &'static str,
        _: usize,
    ) -> Result<Self::SerializeTupleStruct, ValueError> {
        Err(serde::ser::Error::custom(
            "expected a string, got tuple struct",
        ))
    }

    fn serialize_tuple_variant(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        _: usize,
    ) -> Result<Self::SerializeTupleVariant, ValueError> {
        Err(serde::ser::Error::custom(
            "expected a string, got tuple variant",
        ))
    }

    fn serialize_map(self, _: Option<usize>) -> Result<Self::SerializeMap, ValueError> {
        Err(serde::ser::Error::custom("expected a string, got map"))
    }

    fn serialize_struct(
        self,
        _: &'static str,
        _: usize,
    ) -> Result<Self::SerializeStruct, ValueError> {
        Err(serde::ser::Error::custom("expected a string, got struct"))
    }

    fn serialize_struct_variant(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        _: usize,
    ) -> Result<Self::SerializeStructVariant, ValueError> {
        Err(serde::ser::Error::custom(
            "expected a string, got struct variant",
        ))
    }
}

fn deserialize_str<'de, T: Deserialize<'de>>(s: &'de str) -> Result<T, ValueError> {
    let deserializer: StrDeserializer<'de, ValueError> = s.into_deserializer();
    T::deserialize(deserializer)
}

#[test]
fn serde_round_trips_as_a_string() {
    for (input, ..) in VALID_DIDS {
        let did: Did = deserialize_str(input).unwrap();
        assert_eq!(did.as_str(), *input);
        assert_eq!(did.serialize(StringOnly).unwrap(), *input);
    }

    let urls = [
        "did:example:123#key-1",
        "did:example:123/path/to?versionId=1#frag",
        "did:example:123?service=agent&relativeRef=%2Fsome%2Fpath",
        "did:web:example.com%3A8443#0",
        "did:example:123#",
        "did:example:123",
    ];
    for input in urls {
        let url: DidUrl = deserialize_str(input).unwrap();
        assert_eq!(url.as_str(), input);
        assert_eq!(url.serialize(StringOnly).unwrap(), input);
    }
}

#[test]
fn deserialize_validates() {
    for (input, expected) in INVALID_DIDS {
        let error = deserialize_str::<Did>(input).unwrap_err();
        assert_eq!(error.to_string(), expected.to_string(), "{input:?}");
    }
    assert!(deserialize_str::<DidUrl>("did:example:123#a#b").is_err());
    assert!(deserialize_str::<DidUrl>("DID:example:123").is_err());
    assert!(deserialize_str::<DidUrl>("did:example:123 ").is_err());
}

// ---------------------------------------------------------------------------------------------
// Property tests
// ---------------------------------------------------------------------------------------------

/// Every match is a valid DID per the ABNF: `did:` method-name `:` method-specific-id.
const DID_RE: &str = r"did:[a-z0-9]{1,10}:(?:[A-Za-z0-9._\-]|%[0-9A-Fa-f]{2}|:){0,30}(?:[A-Za-z0-9._\-]|%[0-9A-Fa-f]{2}){1,8}";

/// Every match is a valid RFC 3986 fragment: `*( pchar / "/" / "?" )`.
const FRAGMENT_RE: &str = r"(?:[A-Za-z0-9._~!$&'()*+,;=:@/?\-]|%[0-9A-Fa-f]{2}){0,20}";

/// Every match is a valid RFC 3986 `path-abempty`.
const PATH_RE: &str = r"(?:/(?:[A-Za-z0-9._~!$&'()*+,;=:@\-]|%[0-9A-Fa-f]{2}){0,8}){0,4}";

proptest! {
    #[test]
    fn generated_dids_parse_and_round_trip(s in DID_RE) {
        let did = Did::parse(&s).unwrap();
        prop_assert_eq!(did.to_string(), s.clone());
        prop_assert_eq!(Did::parse(did.as_str()).unwrap(), did);
    }

    #[test]
    fn any_accepted_string_round_trips_through_display(s in any::<String>()) {
        if let Ok(did) = Did::parse(&s) {
            prop_assert_eq!(did.to_string(), s);
        }
    }

    #[test]
    fn any_accepted_did_url_round_trips_through_display(s in any::<String>()) {
        if let Ok(url) = DidUrl::parse(&s) {
            prop_assert_eq!(url.to_string(), s);
        }
    }

    #[test]
    fn parsing_a_did_as_a_did_url_equals_to_url(s in DID_RE) {
        let did = Did::parse(&s).unwrap();
        prop_assert_eq!(DidUrl::parse(did.as_str()).unwrap(), did.to_url());
    }

    #[test]
    fn join_sets_the_fragment(s in DID_RE, x in FRAGMENT_RE) {
        let did = Did::parse(&s).unwrap();
        let url = did.join(&format!("#{x}")).unwrap();
        prop_assert_eq!(url.fragment(), Some(x.as_str()));
        prop_assert_eq!(url.did(), &did);
        prop_assert_eq!(url.path(), None);
        prop_assert_eq!(url.query(), None);
    }

    #[test]
    fn generated_did_urls_round_trip(
        s in DID_RE,
        path in PATH_RE,
        query in proptest::option::of(FRAGMENT_RE),
        fragment in proptest::option::of(FRAGMENT_RE),
    ) {
        let mut input = format!("{s}{path}");
        if let Some(query) = &query {
            input.push('?');
            input.push_str(query);
        }
        if let Some(fragment) = &fragment {
            input.push('#');
            input.push_str(fragment);
        }
        let url = DidUrl::parse(&input).unwrap();
        prop_assert_eq!(url.to_string(), input.clone());
        prop_assert_eq!(url.did().as_str(), s.as_str());
        prop_assert_eq!(url.path(), (!path.is_empty()).then_some(path.as_str()));
        prop_assert_eq!(url.query(), query.as_deref());
        prop_assert_eq!(url.fragment(), fragment.as_deref());
        prop_assert_eq!(Did::parse(&s).unwrap().join(&input[s.len()..]).unwrap(), url);
    }

    #[test]
    fn with_fragment_always_yields_a_valid_url(s in DID_RE, x in any::<String>()) {
        let url = Did::parse(&s).unwrap().to_url().with_fragment(&x);
        prop_assert_eq!(DidUrl::parse(url.as_str()).unwrap(), url);
    }
}
