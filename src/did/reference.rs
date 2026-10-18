//! `DidUrlReference`: an absolute DID URL or a relative reference to one.

use core::fmt;
use core::str::FromStr;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::syntax::{check_len, scan_url_suffix};
use super::{DEFAULT_MAX_LEN, Did, DidError, DidUrl};

/// A reference to a resource of a DID document: either an absolute [`DidUrl`] or a relative DID
/// URL (DID Core §3.2.2) such as `#key-1`, which is resolved against the document's `id`.
///
/// Verification relationships reference verification methods this way, and a document may use
/// either form, so the reference keeps whichever it was given and [`resolve`](Self::resolve)
/// turns it into an absolute DID URL when a base DID is known.
///
/// A relative reference is a path, query and fragment (any of them, in that order), so it starts
/// with `/`, `?` or `#`.
///
/// # Examples
///
/// ```
/// use identity_kit::did::{Did, DidUrlReference};
///
/// let base: Did = "did:example:123".parse()?;
///
/// let relative = DidUrlReference::parse("#key-1")?;
/// assert!(relative.is_relative());
/// assert_eq!(relative.resolve(&base)?.as_str(), "did:example:123#key-1");
///
/// let absolute = DidUrlReference::parse("did:example:456#key-1")?;
/// assert!(!absolute.is_relative());
/// assert_eq!(absolute.resolve(&base)?.as_str(), "did:example:456#key-1");
/// # Ok::<(), identity_kit::did::DidError>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DidUrlReference {
    /// A DID URL.
    Absolute(DidUrl),
    /// A relative DID URL: `/path`, `?query` or `#fragment`, possibly combined, as written.
    Relative(String),
}

impl DidUrlReference {
    /// Parses a DID URL or a relative DID URL, rejecting input longer than [`DEFAULT_MAX_LEN`]
    /// bytes.
    ///
    /// # Errors
    ///
    /// A [`DidError`] when the input is neither a valid DID URL nor a relative reference starting
    /// with `/`, `?` or `#` whose components are valid per RFC 3986. Positions in the error are
    /// byte offsets into the input.
    pub fn parse(s: &str) -> Result<Self, DidError> {
        if s.starts_with(['/', '?', '#']) {
            check_len(s, DEFAULT_MAX_LEN)?;
            scan_url_suffix(s, 0)?;
            Ok(Self::Relative(s.to_owned()))
        } else {
            DidUrl::parse(s).map(Self::Absolute)
        }
    }

    /// Whether this is a relative reference.
    pub fn is_relative(&self) -> bool {
        matches!(self, Self::Relative(_))
    }

    /// The reference as written.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Absolute(url) => url.as_str(),
            Self::Relative(s) => s,
        }
    }

    /// The absolute DID URL, resolving a relative reference against `base` as RFC 3986 §5
    /// prescribes for a DID document (DID Core §3.2.2).
    ///
    /// # Errors
    ///
    /// Only a [`DidError`] that cannot happen for a reference this type accepted; the signature
    /// stays fallible so a future base other than a bare DID can report one.
    pub fn resolve(&self, base: &Did) -> Result<DidUrl, DidError> {
        match self {
            Self::Absolute(url) => Ok(url.clone()),
            Self::Relative(s) => base.join(s),
        }
    }

    /// Whether this reference denotes `url` in a document whose `id` is `base`.
    pub fn refers_to(&self, url: &DidUrl, base: &Did) -> bool {
        match self {
            Self::Absolute(this) => this == url,
            Self::Relative(_) => self.resolve(base).is_ok_and(|resolved| &resolved == url),
        }
    }
}

impl fmt::Display for DidUrlReference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl AsRef<str> for DidUrlReference {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl FromStr for DidUrlReference {
    type Err = DidError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl TryFrom<&str> for DidUrlReference {
    type Error = DidError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::parse(s)
    }
}

impl TryFrom<String> for DidUrlReference {
    type Error = DidError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::parse(&s)
    }
}

impl From<DidUrl> for DidUrlReference {
    fn from(url: DidUrl) -> Self {
        Self::Absolute(url)
    }
}

impl From<&DidUrl> for DidUrlReference {
    fn from(url: &DidUrl) -> Self {
        Self::Absolute(url.clone())
    }
}

impl Serialize for DidUrlReference {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for DidUrlReference {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::parse(&s).map_err(D::Error::custom)
    }
}
