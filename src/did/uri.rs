//! `Uri`: an RFC 3986 URI kept exactly as written.

use core::fmt;
use core::str::FromStr;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::{Did, DidError, DidUrl};

/// A URI (RFC 3986) stored exactly as written: no normalization, no percent-decoding, no case
/// folding.
///
/// DID documents carry URIs in `alsoKnownAs` and `serviceEndpoint`, and DID Core requires a
/// consumer to hand them on unchanged, so this type checks the generic syntax and nothing more:
/// a scheme, then characters from the RFC 3986 sets (`unreserved`, `reserved`, `pct-encoded`),
/// with at most one `#`. Two URIs are equal exactly when their strings are equal.
///
/// Every [`Did`] and [`DidUrl`] is a `Uri`; use `From` to convert.
///
/// # Examples
///
/// ```
/// use identity_kit::did::Uri;
///
/// let uri = Uri::parse("https://bar.example.com")?;
/// assert_eq!(uri.as_str(), "https://bar.example.com"); // no trailing slash added
/// assert_eq!(uri.scheme(), "https");
///
/// assert!(Uri::parse("not a uri").is_err());
/// assert!(Uri::parse("/relative/path").is_err());
/// # Ok::<(), identity_kit::did::DidError>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Uri(String);

impl Uri {
    /// Parses a URI, checking the RFC 3986 generic syntax.
    ///
    /// # Errors
    ///
    /// [`DidError::InvalidChar`] names the first byte that is not allowed in a URI, including a
    /// missing or malformed scheme; [`DidError::InvalidPercentEncoding`] an incomplete `%xx`.
    pub fn parse(s: &str) -> Result<Self, DidError> {
        validate_uri(s)?;
        Ok(Self(s.to_owned()))
    }

    /// The URI as written.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The scheme, without the `:`.
    pub fn scheme(&self) -> &str {
        // Construction guarantees a `:` after the scheme.
        self.0.split(':').next().unwrap_or_default()
    }

    /// Whether this URI is a DID or a DID URL.
    pub fn is_did_url(&self) -> bool {
        self.scheme() == "did"
    }
}

/// Checks the RFC 3986 generic syntax: `scheme ":" *( unreserved / reserved / pct-encoded )`
/// with at most one `#`.
fn validate_uri(s: &str) -> Result<(), DidError> {
    let bytes = s.as_bytes();
    let colon = bytes
        .iter()
        .position(|&b| b == b':')
        .ok_or(DidError::InvalidChar {
            position: bytes.len(),
            ch: ':',
        })?;
    if colon == 0 || !bytes[0].is_ascii_alphabetic() {
        return Err(DidError::InvalidChar {
            position: 0,
            ch: s.chars().next().unwrap_or(':'),
        });
    }
    if let Some(i) = bytes[..colon]
        .iter()
        .position(|&b| !(b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.')))
    {
        return Err(DidError::InvalidChar {
            position: i,
            ch: char::from(bytes[i]),
        });
    }
    let mut hashes = 0;
    let mut i = colon + 1;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let ok = bytes.len() >= i + 3
                    && bytes[i + 1].is_ascii_hexdigit()
                    && bytes[i + 2].is_ascii_hexdigit();
                if !ok {
                    return Err(DidError::InvalidPercentEncoding { position: i });
                }
                i += 3;
                continue;
            }
            b'#' => {
                hashes += 1;
                if hashes > 1 {
                    return Err(DidError::InvalidChar {
                        position: i,
                        ch: '#',
                    });
                }
            }
            b if is_uri_char(b) => {}
            _ => {
                // Report the whole character, not its first UTF-8 byte.
                let ch = s[i..].chars().next().unwrap_or('\0');
                return Err(DidError::InvalidChar { position: i, ch });
            }
        }
        i += 1;
    }
    Ok(())
}

/// `unreserved / gen-delims / sub-delims` of RFC 3986 §2, less `%` and `#` (handled apart).
fn is_uri_char(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'-' | b'.'
                | b'_'
                | b'~'
                | b':'
                | b'/'
                | b'?'
                | b'['
                | b']'
                | b'@'
                | b'!'
                | b'$'
                | b'&'
                | b'\''
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b','
                | b';'
                | b'='
        )
}

impl fmt::Display for Uri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for Uri {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl FromStr for Uri {
    type Err = DidError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl TryFrom<&str> for Uri {
    type Error = DidError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::parse(s)
    }
}

impl TryFrom<String> for Uri {
    type Error = DidError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        validate_uri(&s)?;
        Ok(Self(s))
    }
}

impl From<Did> for Uri {
    fn from(did: Did) -> Self {
        Self(did.as_str().to_owned())
    }
}

impl From<DidUrl> for Uri {
    fn from(url: DidUrl) -> Self {
        Self(url.as_str().to_owned())
    }
}

impl From<&Did> for Uri {
    fn from(did: &Did) -> Self {
        Self(did.as_str().to_owned())
    }
}

impl From<&DidUrl> for Uri {
    fn from(url: &DidUrl) -> Self {
        Self(url.as_str().to_owned())
    }
}

impl PartialEq<str> for Uri {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for Uri {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

impl Serialize for Uri {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Uri {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::try_from(s).map_err(D::Error::custom)
    }
}
