//! Disclosures (RFC 9901 §4.2).

use core::fmt;
use core::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

use super::{HashAlgorithm, SdJwtError};
use crate::jose::base64url;

/// A disclosure: the salt, the claim name (for an object property; an array element has
/// none) and the claim value, base64url-encoded as a JSON array.
///
/// A disclosure keeps the encoded string it was parsed from, since the digest is taken over
/// that string and any JSON serialization of the array is as valid as another.
///
/// # Examples
///
/// ```
/// use identity_kit::sd_jwt_vc::{Disclosure, HashAlgorithm};
/// use serde_json::json;
///
/// // RFC 9901 §4.2.1.
/// let disclosure: Disclosure =
///     "WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0".parse()?;
/// assert_eq!(disclosure.salt(), "_26bc4LT-ac6q2KI6cBW5es");
/// assert_eq!(disclosure.name(), Some("family_name"));
/// assert_eq!(disclosure.value(), &json!("Möbius"));
/// assert_eq!(
///     disclosure.digest(HashAlgorithm::Sha256),
///     "X9yH0Ajrdm1Oij4tWso9UzzKJvPoDxwmuEcO3XAdRC0"
/// );
///
/// // RFC 9901 §4.2.2: an array element.
/// let element: Disclosure = "WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIkZSIl0".parse()?;
/// assert_eq!(element.name(), None);
/// assert_eq!(element.value(), &json!("FR"));
/// # Ok::<(), identity_kit::sd_jwt_vc::SdJwtError>(())
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct Disclosure {
    encoded: String,
    salt: String,
    name: Option<String>,
    value: Value,
}

impl Disclosure {
    /// A disclosure for the object property `name` with `value`, encoded as compact JSON.
    pub fn property(salt: impl Into<String>, name: impl Into<String>, value: Value) -> Self {
        let salt = salt.into();
        let name = name.into();
        let array = Value::Array(vec![
            Value::String(salt.clone()),
            Value::String(name.clone()),
            value.clone(),
        ]);
        Self {
            encoded: encode(&array),
            salt,
            name: Some(name),
            value,
        }
    }

    /// A disclosure for the array element `value`, encoded as compact JSON.
    pub fn element(salt: impl Into<String>, value: Value) -> Self {
        let salt = salt.into();
        let array = Value::Array(vec![Value::String(salt.clone()), value.clone()]);
        Self {
            encoded: encode(&array),
            salt,
            name: None,
            value,
        }
    }

    /// Decodes the base64url string `encoded`.
    ///
    /// # Errors
    ///
    /// [`SdJwtError::InvalidDisclosure`] when the string is not base64url of a JSON array of
    /// two elements (a string salt and a value) or three (a string salt, a string name and a
    /// value).
    pub fn parse(encoded: &str) -> Result<Self, SdJwtError> {
        let invalid = |reason: &str| SdJwtError::InvalidDisclosure {
            disclosure: encoded.to_owned(),
            reason: reason.to_owned(),
        };
        let bytes = base64url::decode(encoded).map_err(|_| invalid("not base64url"))?;
        let array: Vec<Value> =
            serde_json::from_slice(&bytes).map_err(|_| invalid("not a JSON array"))?;
        let mut array = array.into_iter();
        let Some(Value::String(salt)) = array.next() else {
            return Err(invalid("the salt is not a string"));
        };
        let (name, value) = match (array.next(), array.next(), array.next()) {
            (Some(value), None, None) => (None, value),
            (Some(Value::String(name)), Some(value), None) => (Some(name), value),
            (Some(_), Some(_), None) => return Err(invalid("the claim name is not a string")),
            _ => return Err(invalid("not an array of two or three elements")),
        };
        Ok(Self {
            encoded: encoded.to_owned(),
            salt,
            name,
            value,
        })
    }

    /// The encoded disclosure, as it travels in an SD-JWT.
    pub fn as_str(&self) -> &str {
        &self.encoded
    }

    /// The salt.
    pub fn salt(&self) -> &str {
        &self.salt
    }

    /// The claim name; `None` for an array element.
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// The claim value.
    pub fn value(&self) -> &Value {
        &self.value
    }

    /// Whether this discloses an array element rather than an object property.
    pub fn is_element(&self) -> bool {
        self.name.is_none()
    }

    /// The digest of the encoded disclosure under `alg` (RFC 9901 §4.2.3).
    pub fn digest(&self, alg: HashAlgorithm) -> String {
        alg.digest(self.encoded.as_bytes())
    }
}

/// `array` as compact JSON, base64url-encoded.
fn encode(array: &Value) -> String {
    let json = serde_json::to_vec(array).expect("a JSON value serializes");
    base64url::encode(&json)
}

impl fmt::Debug for Disclosure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Disclosure")
            .field("salt", &self.salt)
            .field("name", &self.name)
            .field("value", &self.value)
            .finish_non_exhaustive()
    }
}

impl fmt::Display for Disclosure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.encoded)
    }
}

impl AsRef<str> for Disclosure {
    fn as_ref(&self) -> &str {
        &self.encoded
    }
}

impl FromStr for Disclosure {
    type Err = SdJwtError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl Serialize for Disclosure {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.encoded)
    }
}

impl<'de> Deserialize<'de> for Disclosure {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let encoded = String::deserialize(deserializer)?;
        Self::parse(&encoded).map_err(serde::de::Error::custom)
    }
}
