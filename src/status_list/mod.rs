//! The IETF Token Status List (draft-ietf-oauth-status-list): the `status` claim of a
//! referenced token, the status list and the status list token.
//!
//! The draft defines the `status` claim for any JWT (§6.1), so the module serves every
//! credential format of the crate: SD-JWT VCs and VCDM 2.0 credentials secured with SD-JWT
//! ([`sd_jwt_vc`](crate::sd_jwt_vc), feature `sd-jwt`) as much as JWT credentials of either
//! profile ([`vc`](crate::vc)). The validators of both hand the claim to a
//! [`StatusCheck`](crate::vc::validation::StatusCheck) as
//! [`CredentialStatus::StatusClaim`](crate::vc::validation::CredentialStatus::StatusClaim).
//!
//! - [`Status`] is the claim, [`StatusListRef`] its `status_list` mechanism and
//!   [`StatusMechanism`] one mechanism of it.
//! - [`StatusList`] is the list (§4): one [`StatusType`] of 1, 2, 4 or 8 bits per referenced
//!   token, ZLIB-compressed in its `lst` member.
//! - [`StatusListToken`] is the signed list (§5.1), issued with
//!   [`sign`](StatusListToken::sign) and read with [`status_of`](StatusListToken::status_of).
//! - `StatusListCheck` (feature `did-web` as well) is the [`StatusCheck`] that fetches the
//!   token a reference names over an `HttpClient` and verifies it (§8).
//!
//! [`StatusCheck`]: crate::vc::validation::StatusCheck

use core::fmt;
use core::str::FromStr;

use chrono::{DateTime, Utc};
use indexmap::IndexMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

use crate::cause::cause;
use crate::jose::{JwsError, JwsHeader, Signer, base64url};
use crate::vc::{Jwt, JwtClaims};

#[cfg(feature = "did-web")]
mod check;

#[cfg(feature = "did-web")]
#[cfg_attr(docsrs, doc(cfg(feature = "did-web")))]
pub use check::StatusListCheck;

/// The `status` claim of a referenced token: at least one status mechanism, `status_list`
/// being the one this crate implements.
///
/// # Examples
///
/// ```
/// use identity_kit::status_list::{Status, StatusListRef};
/// use serde_json::json;
///
/// // Token Status List §6.2.
/// let status: Status = serde_json::from_value(json!({
///   "status_list": { "idx": 0, "uri": "https://example.com/statuslists/1" }
/// }))?;
/// let reference = status.status_list.as_ref().unwrap();
/// assert_eq!(reference.idx, 0);
/// assert_eq!(reference.uri, "https://example.com/statuslists/1");
/// assert_eq!(status, Status::status_list(StatusListRef::new("https://example.com/statuslists/1", 0)));
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Status {
    /// The `status_list` mechanism.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_list: Option<StatusListRef>,
    /// Every other mechanism, by name.
    #[serde(flatten)]
    pub additional: IndexMap<String, Value>,
}

impl Status {
    /// A `status` claim with no mechanism yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// A `status` claim referencing a status list.
    pub fn status_list(reference: StatusListRef) -> Self {
        Self {
            status_list: Some(reference),
            additional: IndexMap::new(),
        }
    }

    /// This claim with the mechanism `name` set to `value`.
    #[must_use]
    pub fn with_mechanism(mut self, name: impl Into<String>, value: impl Into<Value>) -> Self {
        self.additional.insert(name.into(), value.into());
        self
    }

    /// Whether no mechanism is given.
    pub fn is_empty(&self) -> bool {
        self.status_list.is_none() && self.additional.is_empty()
    }

    /// The mechanisms, the status list first.
    pub fn mechanisms(&self) -> impl Iterator<Item = StatusMechanism<'_>> {
        self.status_list
            .iter()
            .map(StatusMechanism::StatusList)
            .chain(
                self.additional
                    .iter()
                    .map(|(name, value)| StatusMechanism::Other { name, value }),
            )
    }
}

/// One mechanism of a [`Status`] claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum StatusMechanism<'a> {
    /// A Token Status List reference.
    StatusList(&'a StatusListRef),
    /// A mechanism this crate does not implement.
    Other {
        /// Its name, the member of `status` it is given under.
        name: &'a str,
        /// Its value.
        value: &'a Value,
    },
}

/// A reference to a status list token (`status.status_list`): the token's URI and the index
/// of the referenced token in its list.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub struct StatusListRef {
    /// `idx`: the index in the status list.
    pub idx: u64,
    /// `uri`: where the status list token is.
    pub uri: String,
}

impl StatusListRef {
    /// A reference to index `idx` of the status list token at `uri`.
    pub fn new(uri: impl Into<String>, idx: u64) -> Self {
        Self {
            idx,
            uri: uri.into(),
        }
    }
}

/// A status type value (Token Status List §7): a number in `0..=255`, with the registered
/// meanings as constants.
///
/// It serializes as its registered name when it has one of its own (`"VALID"`, `"INVALID"`,
/// `"SUSPENDED"`) and as a number otherwise. `APPLICATION_SPECIFIC` names `0x03` and
/// `0x0C`-`0x0F` alike, so those serialize as numbers too. It deserializes from a registered
/// name, a number in `0..=255`, or that number as a decimal string; [`parse`](Self::parse) and
/// [`FromStr`] accept the same strings. Names are case-sensitive. Since the form depends on the
/// value, deserializing needs a self-describing format such as JSON or CBOR.
///
/// # Examples
///
/// ```
/// use identity_kit::status_list::StatusType;
/// use serde_json::json;
///
/// assert_eq!(serde_json::to_value(StatusType::SUSPENDED)?, json!("SUSPENDED"));
/// assert_eq!(serde_json::to_value(StatusType(3))?, json!(3));
/// assert_eq!(serde_json::from_value::<StatusType>(json!("INVALID"))?, StatusType::INVALID);
/// assert_eq!(serde_json::from_value::<StatusType>(json!(12))?, StatusType(0x0C));
/// assert_eq!("VALID".parse::<StatusType>()?, StatusType::VALID);
/// assert!("APPLICATION_SPECIFIC".parse::<StatusType>().is_err());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StatusType(pub u8);

impl StatusType {
    /// `0x00`: the referenced token is valid.
    pub const VALID: Self = Self(0);
    /// `0x01`: the referenced token is revoked.
    pub const INVALID: Self = Self(1);
    /// `0x02`: the referenced token is suspended.
    pub const SUSPENDED: Self = Self(2);

    /// The value.
    pub const fn value(self) -> u8 {
        self.0
    }

    /// Whether this is [`VALID`](Self::VALID).
    pub const fn is_valid(self) -> bool {
        self.0 == 0
    }

    /// The registered name of the value, if it has one.
    pub const fn name(self) -> Option<&'static str> {
        match self.0 {
            0 => Some("VALID"),
            1 => Some("INVALID"),
            2 => Some("SUSPENDED"),
            _ => None,
        }
    }

    /// The value named `s`: `VALID`, `INVALID`, `SUSPENDED`, or a decimal number in
    /// `0..=255`.
    ///
    /// # Errors
    ///
    /// [`StatusListError::UnknownStatusType`] for anything else, `APPLICATION_SPECIFIC`
    /// included: it names several values.
    pub fn parse(s: &str) -> Result<Self, StatusListError> {
        match s {
            "VALID" => Ok(Self::VALID),
            "INVALID" => Ok(Self::INVALID),
            "SUSPENDED" => Ok(Self::SUSPENDED),
            digits if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) => digits
                .parse()
                .map(Self)
                .map_err(|_| StatusListError::UnknownStatusType(s.to_owned())),
            _ => Err(StatusListError::UnknownStatusType(s.to_owned())),
        }
    }
}

impl fmt::Display for StatusType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.name() {
            Some(name) => write!(f, "{name} ({:#04x})", self.0),
            None => write!(f, "{:#04x}", self.0),
        }
    }
}

impl From<u8> for StatusType {
    fn from(value: u8) -> Self {
        Self(value)
    }
}

impl FromStr for StatusType {
    type Err = StatusListError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl Serialize for StatusType {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.name() {
            Some(name) => serializer.serialize_str(name),
            None => serializer.serialize_u8(self.0),
        }
    }
}

impl<'de> Deserialize<'de> for StatusType {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct StatusTypeVisitor;

        impl serde::de::Visitor<'_> for StatusTypeVisitor {
            type Value = StatusType;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("VALID, INVALID, SUSPENDED or a number in 0..=255")
            }

            fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<StatusType, E> {
                StatusType::parse(s).map_err(E::custom)
            }

            fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<StatusType, E> {
                u8::try_from(value)
                    .map(StatusType)
                    .map_err(|_| E::invalid_value(serde::de::Unexpected::Unsigned(value), &self))
            }

            fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<StatusType, E> {
                u8::try_from(value)
                    .map(StatusType)
                    .map_err(|_| E::invalid_value(serde::de::Unexpected::Signed(value), &self))
            }
        }

        deserializer.deserialize_any(StatusTypeVisitor)
    }
}

/// Why a status list or status list token could not be used.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StatusListError {
    /// `bits` is not 1, 2, 4 or 8.
    #[error("`bits` is {0}, not 1, 2, 4 or 8")]
    InvalidBits(u8),
    /// A status value does not fit in `bits`.
    #[error("status value {value} does not fit in {bits} bits")]
    InvalidStatusValue {
        /// The value.
        value: u8,
        /// The bits per status.
        bits: u8,
    },
    /// The index is beyond the end of the list.
    #[error("index {idx} is out of range of a status list of {len} entries")]
    IndexOutOfRange {
        /// The index.
        idx: u64,
        /// The number of entries in the list.
        len: usize,
    },
    /// `lst` is not base64url, or not a ZLIB-compressed byte array. The source is the base64url
    /// error, when that is the cause.
    #[error("invalid status list: {reason}{}", cause(.source.as_ref()))]
    Compression {
        /// What is wrong with `lst`.
        reason: String,
        /// The underlying error.
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },
    /// The decompressed list is larger than the limit.
    #[error("the status list decompresses to more than {limit} bytes")]
    TooLarge {
        /// The limit.
        limit: usize,
    },
    /// The status list token is not a compact JWS this crate decodes.
    #[error("invalid JWS: {0}")]
    Jws(#[from] JwsError),
    /// A string that is neither a registered status type name of its own nor a number in
    /// `0..=255`.
    #[error("{0:?} is not VALID, INVALID, SUSPENDED or a number in 0..=255")]
    UnknownStatusType(String),
    /// The status list token's `typ` is not `statuslist+jwt`.
    #[error("header `typ` is {0:?}, not `statuslist+jwt`")]
    UnexpectedTyp(Option<String>),
    /// The status list token's payload is not a status list token claims set; the source is
    /// the JSON error.
    #[error("the payload is not a status list token: {0}")]
    Payload(#[source] serde_json::Error),
    /// The token's `sub` is not the `uri` of the reference.
    #[error("status list token `sub` {sub:?} is not the referenced {uri:?}")]
    SubjectMismatch {
        /// The token's `sub`.
        sub: String,
        /// The reference's `uri`.
        uri: String,
    },
    /// The status list token has expired.
    #[error("status list token expired at {} (now is {})", expired_at.to_rfc3339(), now.to_rfc3339())]
    Expired {
        /// Its `exp`.
        expired_at: DateTime<Utc>,
        /// The validation time.
        now: DateTime<Utc>,
    },
}

/// A status list (Token Status List §4): one status of `bits` bits per referenced token,
/// packed into a byte array from the least significant bit up, ZLIB-compressed and
/// base64url-encoded as `lst` in JSON.
///
/// # Examples
///
/// ```
/// use identity_kit::status_list::{StatusList, StatusType};
/// use serde_json::json;
///
/// // Token Status List §4.1: 16 statuses of 1 bit.
/// let list: StatusList = serde_json::from_value(json!({ "bits": 1, "lst": "eNrbuRgAAhcBXQ" }))?;
/// assert_eq!(list.as_bytes(), &[0xb9, 0xa3]);
/// assert_eq!(list.get(0), Some(StatusType::INVALID));
/// assert_eq!(list.get(1), Some(StatusType::VALID));
/// assert_eq!(list.get(15), Some(StatusType::INVALID));
/// assert_eq!(list.get(16), None);
///
/// let mut rebuilt = StatusList::new(1, 16)?;
/// for index in [0, 3, 4, 5, 7, 8, 9, 13, 15] {
///     rebuilt.set(index, StatusType::INVALID)?;
/// }
/// assert_eq!(rebuilt.as_bytes(), list.as_bytes());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusList {
    bits: u8,
    bytes: Vec<u8>,
    aggregation_uri: Option<String>,
}

impl StatusList {
    /// The largest decompressed list [`Deserialize`] accepts: 16 MiB, room for 16 million
    /// 8-bit statuses.
    pub const MAX_BYTES: usize = 1 << 24;

    /// An all-`VALID` list of `size` statuses of `bits` bits each.
    ///
    /// # Errors
    ///
    /// [`StatusListError::InvalidBits`] unless `bits` is 1, 2, 4 or 8.
    pub fn new(bits: u8, size: usize) -> Result<Self, StatusListError> {
        check_bits(bits)?;
        let bytes = vec![0; (size * usize::from(bits)).div_ceil(8)];
        Ok(Self {
            bits,
            bytes,
            aggregation_uri: None,
        })
    }

    /// A list over the uncompressed byte array `bytes`.
    ///
    /// # Errors
    ///
    /// [`StatusListError::InvalidBits`] unless `bits` is 1, 2, 4 or 8.
    pub fn from_bytes(bits: u8, bytes: Vec<u8>) -> Result<Self, StatusListError> {
        check_bits(bits)?;
        Ok(Self {
            bits,
            bytes,
            aggregation_uri: None,
        })
    }

    /// This list with `aggregation_uri`.
    #[must_use]
    pub fn with_aggregation_uri(mut self, uri: impl Into<String>) -> Self {
        self.aggregation_uri = Some(uri.into());
        self
    }

    /// The bits per status: 1, 2, 4 or 8.
    pub const fn bits(&self) -> u8 {
        self.bits
    }

    /// The uncompressed byte array.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The `aggregation_uri`, if any.
    pub fn aggregation_uri(&self) -> Option<&str> {
        self.aggregation_uri.as_deref()
    }

    /// The number of statuses the list holds.
    pub fn len(&self) -> usize {
        self.bytes.len() * 8 / usize::from(self.bits)
    }

    /// Whether the list holds no status.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// The status at `index`, or `None` beyond the end of the list.
    pub fn get(&self, index: u64) -> Option<StatusType> {
        let (byte, shift) = self.position(index)?;
        let mask = self.mask();
        Some(StatusType((self.bytes.get(byte)? >> shift) & mask))
    }

    /// Sets the status at `index`.
    ///
    /// # Errors
    ///
    /// [`StatusListError::IndexOutOfRange`] or [`StatusListError::InvalidStatusValue`] when
    /// the value does not fit in `bits`.
    pub fn set(&mut self, index: u64, status: StatusType) -> Result<(), StatusListError> {
        let mask = self.mask();
        if status.0 & !mask != 0 {
            return Err(StatusListError::InvalidStatusValue {
                value: status.0,
                bits: self.bits,
            });
        }
        let len = self.len();
        let out_of_range = || StatusListError::IndexOutOfRange { idx: index, len };
        let (byte, shift) = self.position(index).ok_or_else(out_of_range)?;
        let slot = self.bytes.get_mut(byte).ok_or_else(out_of_range)?;
        *slot = (*slot & !(mask << shift)) | (status.0 << shift);
        Ok(())
    }

    /// The byte and the bit offset of `index`.
    fn position(&self, index: u64) -> Option<(usize, u8)> {
        let bits = u64::from(self.bits);
        let bit = index.checked_mul(bits)?;
        let byte = usize::try_from(bit / 8).ok()?;
        let shift = u8::try_from(bit % 8).ok()?;
        (byte < self.bytes.len()).then_some((byte, shift))
    }

    /// The mask of one status.
    const fn mask(&self) -> u8 {
        if self.bits == 8 {
            0xff
        } else {
            (1 << self.bits) - 1
        }
    }

    /// The ZLIB-compressed byte array, base64url-encoded: the `lst` member.
    pub fn to_lst(&self) -> String {
        let compressed = miniz_oxide::deflate::compress_to_vec_zlib(&self.bytes, 10);
        base64url::encode(&compressed)
    }

    /// Decodes `lst`, refusing a list that decompresses to more than `max_bytes`.
    ///
    /// # Errors
    ///
    /// [`StatusListError::InvalidBits`], [`StatusListError::Compression`] or
    /// [`StatusListError::TooLarge`].
    pub fn from_lst(bits: u8, lst: &str, max_bytes: usize) -> Result<Self, StatusListError> {
        check_bits(bits)?;
        let compressed = base64url::decode(lst).map_err(|e| StatusListError::Compression {
            reason: "`lst` is not base64url".to_owned(),
            source: Some(Box::new(e)),
        })?;
        let bytes = miniz_oxide::inflate::decompress_to_vec_zlib_with_limit(&compressed, max_bytes)
            .map_err(|e| match e.status {
                miniz_oxide::inflate::TINFLStatus::HasMoreOutput => {
                    StatusListError::TooLarge { limit: max_bytes }
                }
                status => StatusListError::Compression {
                    reason: format!("`lst` is not ZLIB data: {status:?}"),
                    source: None,
                },
            })?;
        Ok(Self {
            bits,
            bytes,
            aggregation_uri: None,
        })
    }
}

/// Checks `bits` is 1, 2, 4 or 8.
fn check_bits(bits: u8) -> Result<(), StatusListError> {
    match bits {
        1 | 2 | 4 | 8 => Ok(()),
        _ => Err(StatusListError::InvalidBits(bits)),
    }
}

/// The JSON form of a [`StatusList`].
#[derive(Serialize, Deserialize)]
struct StatusListJson {
    bits: u8,
    lst: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    aggregation_uri: Option<String>,
}

impl Serialize for StatusList {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        StatusListJson {
            bits: self.bits,
            lst: self.to_lst(),
            aggregation_uri: self.aggregation_uri.clone(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for StatusList {
    /// Decodes `lst` with [`StatusList::MAX_BYTES`] as the limit.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let json = StatusListJson::deserialize(deserializer)?;
        let mut list = Self::from_lst(json.bits, &json.lst, Self::MAX_BYTES)
            .map_err(serde::de::Error::custom)?;
        list.aggregation_uri = json.aggregation_uri;
        Ok(list)
    }
}

/// The claims of a status list token in JWT format (Token Status List §5.1).
///
/// # Examples
///
/// ```
/// use chrono::{TimeZone as _, Utc};
/// use identity_kit::status_list::{StatusListRef, StatusListToken, StatusType};
/// use identity_kit::vc::Jwt;
///
/// // Token Status List §8.2.
/// let jwt: Jwt = "eyJhbGciOiJFUzI1NiIsImtpZCI6IjEyIiwidHlwIjoic3RhdHVzbGlzdCtqd3QifQ.e\
///     yJleHAiOjIyOTE3MjAxNzAsImlhdCI6MTY4NjkyMDE3MCwiaXNzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbSIsInN0YXR1\
///     c19saXN0Ijp7ImJpdHMiOjEsImxzdCI6ImVOcmJ1UmdBQWhjQlhRIn0sInN1YiI6Imh0dHBzOi8vZXhhbXBsZS5jb20\
///     vc3RhdHVzbGlzdHMvMSIsInR0bCI6NDMyMDB9.2lKUUNG503R9htu4aHAYi7vjmr3sgApbfoDvPrl65N3URUO1EYqq\
///     Ql45Jfzd-Av4QzlKa3oVALpLwOEUOq-U_g".parse()?;
/// let (header, token) = StatusListToken::decode(&jwt)?;
/// assert_eq!(header.kid.as_deref(), Some("12"));
/// assert_eq!(token.sub, "https://example.com/statuslists/1");
/// assert_eq!(token.ttl, Some(43200));
///
/// let now = Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap();
/// let reference = StatusListRef::new("https://example.com/statuslists/1", 0);
/// assert_eq!(token.status_of(&reference, now)?, StatusType::INVALID);
/// assert_eq!(token.status_of(&StatusListRef::new(&reference.uri, 1), now)?, StatusType::VALID);
/// assert!(token.status_of(&StatusListRef::new(&reference.uri, 16), now).is_err());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct StatusListToken {
    /// `sub`: the URI of the token, the `uri` referenced tokens use.
    pub sub: String,
    /// `iat`: when the token was issued. A `NumericDate` with a fraction is floored.
    #[serde(deserialize_with = "crate::vc::required_numeric_date")]
    pub iat: i64,
    /// `exp`: when the token expires. A `NumericDate` with a fraction is floored.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::vc::numeric_date"
    )]
    pub exp: Option<i64>,
    /// `ttl`: how many seconds the token may be cached.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u64>,
    /// `status_list`: the list.
    pub status_list: StatusList,
    /// Every other claim, in insertion order.
    #[serde(flatten)]
    pub additional: IndexMap<String, Value>,
}

impl StatusListToken {
    /// The `typ` of a status list token, `statuslist+jwt`.
    pub const TYP: &'static str = "statuslist+jwt";

    /// The media type of a status list token, `application/statuslist+jwt`.
    pub const MEDIA_TYPE: &'static str = "application/statuslist+jwt";

    /// A token for the list at `sub`, issued at `iat`.
    pub fn new(sub: impl Into<String>, iat: DateTime<Utc>, status_list: StatusList) -> Self {
        Self {
            sub: sub.into(),
            iat: JwtClaims::numeric_date(iat),
            exp: None,
            ttl: None,
            status_list,
            additional: IndexMap::new(),
        }
    }

    /// This token with `exp`.
    #[must_use]
    pub fn with_expires_at(mut self, time: DateTime<Utc>) -> Self {
        self.exp = Some(JwtClaims::numeric_date(time));
        self
    }

    /// This token with `ttl`.
    #[must_use]
    pub fn with_ttl(mut self, seconds: u64) -> Self {
        self.ttl = Some(seconds);
        self
    }

    /// This token with the claim `name` set to `value`.
    #[must_use]
    pub fn with_claim(mut self, name: impl Into<String>, value: impl Into<Value>) -> Self {
        self.additional.insert(name.into(), value.into());
        self
    }

    /// Decodes `jwt` without verifying it: the header, whose `typ` must be
    /// `statuslist+jwt`, and the claims.
    ///
    /// # Errors
    ///
    /// [`StatusListError::Jws`], [`StatusListError::UnexpectedTyp`] or
    /// [`StatusListError::Payload`].
    pub fn decode(jwt: &Jwt) -> Result<(JwsHeader, Self), StatusListError> {
        let jws = jwt.decode()?;
        if jws.header().typ.as_deref() != Some(Self::TYP) {
            return Err(StatusListError::UnexpectedTyp(jws.header().typ.clone()));
        }
        let token = serde_json::from_slice(jws.payload()).map_err(StatusListError::Payload)?;
        Ok((jws.header().clone(), token))
    }

    /// Signs this token with `signer`, `typ: statuslist+jwt` and the signer's `kid`.
    ///
    /// # Errors
    ///
    /// [`StatusListError::Jws`] when signing fails.
    ///
    /// # Panics
    ///
    /// Never: the token always serializes to JSON, and the JWS is one this function has just
    /// encoded.
    pub async fn sign(&self, signer: &dyn Signer) -> Result<Jwt, StatusListError> {
        let mut header = JwsHeader::new(signer.alg()).with_typ(Self::TYP);
        header.kid = signer.kid().map(str::to_owned);
        let payload = serde_json::to_vec(self).expect("a token serializes");
        let jwt = crate::jose::encode_compact(&header, &payload, signer).await?;
        Ok(Jwt::new(jwt).expect("a freshly encoded JWS decodes"))
    }

    /// The status of the token `reference` points at (Token Status List §8.3, steps 4 to 6):
    /// `sub` must be the referenced URI, the token must not have expired at `now`, the index
    /// must be in range.
    ///
    /// # Errors
    ///
    /// [`StatusListError::SubjectMismatch`], [`StatusListError::Expired`] or
    /// [`StatusListError::IndexOutOfRange`].
    pub fn status_of(
        &self,
        reference: &StatusListRef,
        now: DateTime<Utc>,
    ) -> Result<StatusType, StatusListError> {
        if self.sub != reference.uri {
            return Err(StatusListError::SubjectMismatch {
                sub: self.sub.clone(),
                uri: reference.uri.clone(),
            });
        }
        if let Some(exp) = self.exp {
            let expired_at = JwtClaims::timestamp(exp).unwrap_or(DateTime::<Utc>::MIN_UTC);
            if expired_at <= now {
                return Err(StatusListError::Expired { expired_at, now });
            }
        }
        self.status_list
            .get(reference.idx)
            .ok_or(StatusListError::IndexOutOfRange {
                idx: reference.idx,
                len: self.status_list.len(),
            })
    }
}
