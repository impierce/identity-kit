//! `JwtClaims`, the registered claims of RFC 7519 and every other claim of a JWT.

use indexmap::IndexMap;
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

use super::OneOrMany;

/// A JWT claims set: the registered claims of RFC 7519 §4.1 as fields, every other claim
/// (`vc`, `vp`, `nonce`, `cnf`, …) in `additional`.
///
/// Times are `NumericDate` values (RFC 7519 §2), whole seconds since the Unix epoch; a fraction
/// is dropped on deserialization. With the `vc` feature, `JwtClaims::numeric_date`,
/// `JwtClaims::timestamp` and the `with_exp`, `with_nbf` and `with_iat` setters convert from
/// and to `chrono` times.
///
/// Decoding a token's payload with [`CompactJws::claims`](super::CompactJws::claims) checks
/// nothing; validating the registered claims is the validators' job.
///
/// # Examples
///
/// ```
/// use identity_kit::jose::JwtClaims;
///
/// let claims: JwtClaims = serde_json::from_str(
///     r#"{"iss":"did:example:123","aud":["a","b"],"exp":1573029723,"nonce":"660!6345FSer"}"#,
/// )?;
/// assert_eq!(claims.iss.as_deref(), Some("did:example:123"));
/// assert_eq!(claims.audiences().collect::<Vec<_>>(), ["a", "b"]);
/// assert_eq!(claims.exp, Some(1573029723));
/// assert_eq!(claims.additional["nonce"], "660!6345FSer");
///
/// let built = JwtClaims::new()
///     .with_iss("did:example:123")
///     .with_aud("did:example:verifier")
///     .with_claim("nonce", "n-0S6_WzA2Mj");
/// assert_eq!(
///     serde_json::to_string(&built)?,
///     r#"{"iss":"did:example:123","aud":"did:example:verifier","nonce":"n-0S6_WzA2Mj"}"#
/// );
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

impl JwtClaims {
    /// The registered claim names of RFC 7519 §4.1, which have fields of their own.
    pub const REGISTERED: [&'static str; 7] = ["iss", "sub", "aud", "exp", "nbf", "iat", "jti"];

    /// An empty claims set.
    pub fn new() -> Self {
        Self::default()
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

    /// The audiences, in order; empty when `aud` is absent.
    pub fn audiences(&self) -> impl Iterator<Item = &str> {
        self.aud
            .iter()
            .flat_map(OneOrMany::iter)
            .map(String::as_str)
    }

    /// This claims set with `aud` set to the one audience `audience`.
    #[must_use]
    pub fn with_aud(mut self, audience: impl Into<String>) -> Self {
        self.aud = Some(OneOrMany::One(audience.into()));
        self
    }

    /// This claims set with the claim `name` set to `value`.
    ///
    /// `name` should not be one of [`REGISTERED`](Self::REGISTERED), which have fields of their
    /// own: the member would be serialized twice, and `vc::Jwt::sign` refuses such a claims set.
    #[must_use]
    pub fn with_claim(mut self, name: impl Into<String>, value: impl Into<Value>) -> Self {
        self.additional.insert(name.into(), value.into());
        self
    }
}
