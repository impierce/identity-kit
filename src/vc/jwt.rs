//! `Jwt`, a compact JWS carrying a JSON claims set, and `JwtClaims`, the registered claims of
//! RFC 7519.

use core::fmt;
use core::str::FromStr;

use chrono::{DateTime, Utc};
use indexmap::IndexMap;
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

use crate::did::OneOrMany;
use crate::jose::{CompactJws, JwsError, JwsHeader, Signer, encode_compact};

/// A JSON Web Token (RFC 7519) in compact serialization, kept as the string it is.
///
/// Construction checks that the string is a well-formed compact JWS with a supported `alg`;
/// nothing is verified. The type serializes as a plain string, which is how a presentation
/// carries its credentials.
///
/// # Examples
///
/// ```
/// use identity_kit::vc::Jwt;
///
/// // RFC 8037 Appendix A.4.
/// let jwt: Jwt = "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc.\
///     hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg"
///     .parse()?;
/// assert_eq!(jwt.decode()?.payload(), b"Example of Ed25519 signing");
/// assert!("not.a.jwt".parse::<Jwt>().is_err());
/// # Ok::<(), identity_kit::jose::JwsError>(())
/// ```
#[derive(Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct Jwt(String);

impl Jwt {
    /// Wraps `token` after checking it is a compact JWS this crate can decode.
    ///
    /// # Errors
    ///
    /// The [`JwsError`] of [`CompactJws::decode`].
    pub fn new(token: impl Into<String>) -> Result<Self, JwsError> {
        let token = token.into();
        CompactJws::decode(&token)?;
        Ok(Self(token))
    }

    /// Signs `claims` under `header` with `signer`.
    ///
    /// The claims are serialized as compact JSON in their field order, `additional` last.
    ///
    /// # Errors
    ///
    /// [`JwsError::InvalidPayload`] when `additional` holds a registered claim, which would put
    /// the member in the payload twice; otherwise as [`encode_compact`].
    pub async fn sign(
        header: &JwsHeader,
        claims: &JwtClaims,
        signer: &dyn Signer,
    ) -> Result<Self, JwsError> {
        if let Some(name) = claims.registered_in_additional() {
            return Err(JwsError::InvalidPayload(format!(
                "registered claim `{name}` is set under `additional`; set its field instead"
            )));
        }
        let payload = serde_json::to_vec(claims).expect("a claims set serializes");
        encode_compact(header, &payload, signer).await.map(Self)
    }

    /// The compact serialization.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The compact serialization.
    pub fn into_string(self) -> String {
        self.0
    }

    /// The decoded parts, unverified.
    ///
    /// # Errors
    ///
    /// Never, in practice: construction decoded the same string.
    pub fn decode(&self) -> Result<CompactJws, JwsError> {
        CompactJws::decode(&self.0)
    }
}

impl fmt::Debug for Jwt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Jwt").field(&self.0).finish()
    }
}

impl fmt::Display for Jwt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for Jwt {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl FromStr for Jwt {
    type Err = JwsError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl TryFrom<String> for Jwt {
    type Error = JwsError;

    fn try_from(token: String) -> Result<Self, Self::Error> {
        Self::new(token)
    }
}

impl<'de> Deserialize<'de> for Jwt {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(String::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

/// A JWT claims set: the registered claims of RFC 7519 §4.1 as fields, every other claim
/// (`vc`, `vp`, `nonce`, `cnf`, …) in `additional`.
///
/// Times are `NumericDate` values, seconds since the Unix epoch; [`JwtClaims::numeric_date`]
/// and [`JwtClaims::timestamp`] convert.
///
/// # Examples
///
/// ```
/// use identity_kit::vc::JwtClaims;
///
/// let claims: JwtClaims = serde_json::from_str(
///     r#"{"iss":"did:example:123","exp":1573029723,"nonce":"660!6345FSer"}"#,
/// )?;
/// assert_eq!(claims.iss.as_deref(), Some("did:example:123"));
/// assert_eq!(
///     claims.exp.and_then(JwtClaims::timestamp).map(|t| t.to_rfc3339()),
///     Some("2019-11-06T08:42:03+00:00".to_owned())
/// );
/// assert_eq!(claims.additional["nonce"], "660!6345FSer");
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct JwtClaims {
    /// `iss`: the issuer of the token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    /// `sub`: the subject of the token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    /// `aud`: the intended recipients.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aud: Option<OneOrMany<String>>,
    /// `exp`: when the token expires.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "numeric_date"
    )]
    pub exp: Option<i64>,
    /// `nbf`: when the token becomes valid.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "numeric_date"
    )]
    pub nbf: Option<i64>,
    /// `iat`: when the token was issued.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "numeric_date"
    )]
    pub iat: Option<i64>,
    /// `jti`: the identifier of the token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    /// Every other claim, in insertion order.
    #[serde(flatten)]
    pub additional: IndexMap<String, Value>,
}

/// Deserializes a `NumericDate` (RFC 7519 §2): a JSON number, possibly with a fraction, floored
/// to whole seconds.
pub(crate) fn numeric_date<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<i64>, D::Error> {
    let Some(number) = Option::<serde_json::Number>::deserialize(deserializer)? else {
        return Ok(None);
    };
    number
        .as_i64()
        .or_else(|| {
            number
                .as_f64()
                .filter(|seconds| (i64::MIN as f64..i64::MAX as f64).contains(seconds))
                .map(|seconds| seconds.floor() as i64)
        })
        .map(Some)
        .ok_or_else(|| D::Error::custom(format!("NumericDate {number} is out of range")))
}

/// As [`numeric_date`], for a claim that must be present.
#[cfg(feature = "sd-jwt")]
pub(crate) fn required_numeric_date<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<i64, D::Error> {
    numeric_date(deserializer)?.ok_or_else(|| serde::de::Error::custom("a NumericDate is required"))
}

impl JwtClaims {
    /// The registered claim names of RFC 7519 §4.1, which have fields of their own.
    pub const REGISTERED: [&'static str; 7] = ["iss", "sub", "aud", "exp", "nbf", "iat", "jti"];

    /// An empty claims set.
    pub fn new() -> Self {
        Self::default()
    }

    /// The first registered claim name found under `additional`, if any.
    fn registered_in_additional(&self) -> Option<&str> {
        Self::REGISTERED
            .into_iter()
            .find(|name| self.additional.contains_key(*name))
    }

    /// This claims set with `iss` set to `issuer`.
    #[must_use]
    pub fn with_iss(mut self, issuer: impl Into<String>) -> Self {
        self.iss = Some(issuer.into());
        self
    }

    /// This claims set with `sub` set to `subject`.
    #[must_use]
    pub fn with_sub(mut self, subject: impl Into<String>) -> Self {
        self.sub = Some(subject.into());
        self
    }

    /// This claims set with `jti` set to `id`.
    #[must_use]
    pub fn with_jti(mut self, id: impl Into<String>) -> Self {
        self.jti = Some(id.into());
        self
    }

    /// `time` as a `NumericDate`: whole seconds since the Unix epoch, fractions dropped.
    pub fn numeric_date(time: DateTime<Utc>) -> i64 {
        time.timestamp()
    }

    /// The time a `NumericDate` names, if it is in the range `chrono` represents.
    pub fn timestamp(numeric_date: i64) -> Option<DateTime<Utc>> {
        DateTime::from_timestamp(numeric_date, 0)
    }

    /// The audiences, in order; empty when `aud` is absent.
    pub fn audiences(&self) -> impl Iterator<Item = &str> {
        self.aud
            .iter()
            .flat_map(OneOrMany::iter)
            .map(String::as_str)
    }

    /// This claims set with `exp` set to `time`.
    #[must_use]
    pub fn with_exp(mut self, time: DateTime<Utc>) -> Self {
        self.exp = Some(Self::numeric_date(time));
        self
    }

    /// This claims set with `nbf` set to `time`.
    #[must_use]
    pub fn with_nbf(mut self, time: DateTime<Utc>) -> Self {
        self.nbf = Some(Self::numeric_date(time));
        self
    }

    /// This claims set with `iat` set to `time`.
    #[must_use]
    pub fn with_iat(mut self, time: DateTime<Utc>) -> Self {
        self.iat = Some(Self::numeric_date(time));
        self
    }

    /// This claims set with `aud` set to the one audience `audience`.
    #[must_use]
    pub fn with_aud(mut self, audience: impl Into<String>) -> Self {
        self.aud = Some(OneOrMany::One(audience.into()));
        self
    }

    /// This claims set with the claim `name` set to `value`.
    ///
    /// `name` should not be one of [`REGISTERED`](Self::REGISTERED), which have setters of their
    /// own: [`Jwt::sign`] refuses a claims set holding a registered claim under `additional`.
    #[must_use]
    pub fn with_claim(mut self, name: impl Into<String>, value: impl Into<Value>) -> Self {
        self.additional.insert(name.into(), value.into());
        self
    }
}
