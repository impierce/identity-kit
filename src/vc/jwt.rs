//! `Jwt`, a compact JWS carrying a JSON claims set, and the `chrono` conversions of
//! [`JwtClaims`].

use core::fmt;
use core::str::FromStr;

use chrono::{DateTime, Utc};
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};

#[cfg(feature = "sd-jwt")]
use crate::jose::numeric_date;
use crate::jose::{CompactJws, JwsError, JwsHeader, JwtClaims, Signer, encode_compact};

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
        if let Some(name) = registered_in_additional(claims) {
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

/// The first registered claim name found under `additional` of `claims`, if any.
fn registered_in_additional(claims: &JwtClaims) -> Option<&'static str> {
    JwtClaims::REGISTERED
        .into_iter()
        .find(|name| claims.additional.contains_key(*name))
}

/// As [`numeric_date`], for a claim that must be present.
#[cfg(feature = "sd-jwt")]
pub(crate) fn required_numeric_date<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<i64, D::Error> {
    numeric_date(deserializer)?.ok_or_else(|| serde::de::Error::custom("a NumericDate is required"))
}

/// The conversions between `NumericDate` values and `chrono` times, which come with the `vc`
/// feature.
#[cfg_attr(docsrs, doc(cfg(feature = "vc")))]
impl JwtClaims {
    /// `time` as a `NumericDate`: whole seconds since the Unix epoch, fractions dropped.
    pub fn numeric_date(time: DateTime<Utc>) -> i64 {
        time.timestamp()
    }

    /// The time a `NumericDate` names, if it is in the range `chrono` represents.
    pub fn timestamp(numeric_date: i64) -> Option<DateTime<Utc>> {
        DateTime::from_timestamp(numeric_date, 0)
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
}
